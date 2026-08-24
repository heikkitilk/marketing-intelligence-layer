"""Bounded, deterministic normalization of Codex and Claude evidence packets.

The module never writes raw transcript records. It reads source files through
the U1 no-follow boundary, removes injected context before role filtering,
redacts textual evidence twice, and writes only private redacted packets.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
from typing import Any, Iterable, Mapping, Sequence

from .census import (
    CensusConfig,
    _artifact_id,
    _discover_jsonl_files,
    _open_safe_regular,
    _validate_root,
    canonical_json,
    parse_timestamp,
)
from .estimate import FULL_POC_LIMITS, ResourceBudgetExceeded, estimate_probe_resources, enforce_r25
from .redact import (
    RedactionStatus,
    fingerprint_policy_version,
    inspect_injected_context,
    redact_text,
    redaction_policy_version,
    scan_for_unsafe_content,
    secure_write_text,
)


_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_CONFIG_ROOT = _REPOSITORY_ROOT / "config"
_DEFAULT_RULES_PATH = _CONFIG_ROOT / "redaction-rules.json"
_DEFAULT_FINGERPRINTS_PATH = _CONFIG_ROOT / "injected-context-fingerprints.json"
MAX_RECORD_BYTES = 2 * 1024 * 1024
MAX_NORMALIZED_EVENT_BYTES = 256 * 1024
MAX_PACKET_BYTES = 100 * 1024
MAX_PACKET_TOKENS = 32_000
BYTES_PER_TOKEN = 3
UNKNOWN = "?"


@dataclass(frozen=True)
class ArtifactNormalization:
    """One artifact's source-free normalized events, packets, and coverage."""

    artifact_id: str
    harness: str
    terminal_status: str
    reason: str
    events: tuple[dict[str, Any], ...]
    packets: tuple[dict[str, Any], ...]
    coverage: dict[str, Any]
    redaction_count: int
    excluded_injected_blocks: int
    excluded_fingerprints: tuple[str, ...]
    injected_provenance: Mapping[str, int]


@dataclass(frozen=True)
class NormalizationRun:
    """The complete source-free result over a U1 manifest and fixed window."""

    packet_manifest_document: dict[str, Any]
    coverage_document: dict[str, Any]
    receipt_document: dict[str, Any]
    artifacts: tuple[ArtifactNormalization, ...]
    packets: tuple[dict[str, Any], ...]
    source_byte_sha256: Mapping[str, str]
    source_integrity: Mapping[str, Any]
    coverage_complete: bool


@dataclass(frozen=True)
class NormalizationOutput:
    root: Path
    run_directory: Path
    files: tuple[Path, ...]
    receipt_path: Path
    receipt_sha256: str


@dataclass(frozen=True)
class _Candidate:
    role: str
    evidence_strength: str
    text: str
    part: int
    stable_item_id: str | None = None


@dataclass(frozen=True)
class _SourceRead:
    records: tuple[dict[str, Any], ...]
    source_event_count: int
    content_sha256: str
    source_byte_sha256: str
    reason: str | None
    source_changed_during_read: bool


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _stable_source_event_id(artifact_id: str, source_version: str, ordinal: int) -> str:
    raw = f"{artifact_id}\0{source_version}\0source\0{ordinal}".encode("utf-8")
    return "source-event-" + _sha256_bytes(raw)[:24]


def _stable_event_id(artifact_id: str, source_version: str, ordinal: int, part: int, role: str) -> str:
    raw = f"{artifact_id}\0{source_version}\0{ordinal}\0{part}\0{role}".encode("utf-8")
    return "event-" + _sha256_bytes(raw)[:24]


def _stable_packet_id(artifact_id: str, source_version: str, event_ids: Sequence[str]) -> str:
    identity = {
        "artifact_id": artifact_id,
        "source_version": source_version,
        "event_ids": list(event_ids),
    }
    return "packet-" + _sha256_bytes(canonical_json(identity).encode("utf-8"))[:24]


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _artifact_fields(artifact: Mapping[str, Any]) -> tuple[str, str, str, int]:
    artifact_id = artifact.get("artifact_id")
    harness = artifact.get("harness")
    content_sha256 = artifact.get("content_sha256")
    event_count = artifact.get("in_window_event_count")
    if not isinstance(artifact_id, str) or not artifact_id.startswith("artifact-"):
        raise ValueError("normalization_invalid_artifact")
    if harness not in {"codex", "claude"}:
        raise ValueError("normalization_invalid_harness")
    if not isinstance(content_sha256, str) or not content_sha256:
        raise ValueError("normalization_invalid_source_version")
    if not isinstance(event_count, int) or event_count < 0:
        raise ValueError("normalization_invalid_event_count")
    return artifact_id, harness, content_sha256, event_count


def _text_from_value(value: Any) -> str:
    """Extract a bounded textual representation from a known text-bearing field."""

    if isinstance(value, str):
        return value
    if isinstance(value, Mapping):
        if isinstance(value.get("text"), str):
            return str(value["text"])
        if "content" in value:
            return _text_from_value(value.get("content"))
        return canonical_json(dict(value))
    if isinstance(value, (list, tuple)):
        parts = [_text_from_value(item) for item in value]
        return "\n".join(part for part in parts if part)
    if value is None:
        return ""
    return str(value)


def _claude_candidates(record: Mapping[str, Any]) -> tuple[_Candidate, ...]:
    record_type = record.get("type")
    if record_type == "system":
        text = _text_from_value(record.get("content"))
        return (_Candidate("system", "reasoned", text, 1),) if text else ()
    if record_type not in {"user", "assistant"}:
        return ()
    message = record.get("message")
    if not isinstance(message, Mapping):
        return ()
    declared_role = message.get("role")
    if declared_role not in {"user", "assistant", "system", "developer"}:
        return ()
    content = message.get("content")
    candidates: list[_Candidate] = []
    default_strength = "asserted" if declared_role == "user" else "reasoned"
    if isinstance(content, str):
        candidates.append(_Candidate(str(declared_role), default_strength, content, 1))
    elif isinstance(content, (list, tuple)):
        for index, block in enumerate(content, start=1):
            if not isinstance(block, Mapping):
                continue
            block_type = block.get("type")
            if block_type == "text":
                text = _text_from_value(block.get("text"))
                if text:
                    candidates.append(_Candidate(str(declared_role), default_strength, text, index))
            elif block_type == "tool_use":
                text = _text_from_value(block.get("input"))
                if text:
                    candidates.append(_Candidate("tool", "reasoned", text, index, str(block.get("id", "")) or None))
            elif block_type == "tool_result":
                text = _text_from_value(block.get("content"))
                if text:
                    candidates.append(_Candidate("tool_result", "observed", text, index, str(block.get("tool_use_id", "")) or None))
    return tuple(candidates)


def _codex_candidates(record: Mapping[str, Any], seen_item_ids: set[str]) -> tuple[_Candidate, ...]:
    if record.get("type") != "response_item":
        return ()
    payload = record.get("payload")
    if not isinstance(payload, Mapping):
        return ()
    item_type = payload.get("type")
    if not isinstance(item_type, str):
        return ()
    item_identifier = payload.get("id")
    stable_item_id = str(item_identifier) if isinstance(item_identifier, (str, int)) else None

    def one(role: str, strength: str, value: Any, part: int = 1, identifier: str | None = stable_item_id) -> tuple[_Candidate, ...]:
        text = _text_from_value(value)
        if not text:
            return ()
        if identifier:
            seen_item_ids.add(identifier)
        return (_Candidate(role, strength, text, part, identifier),)

    if item_type == "message":
        role = payload.get("role")
        if role in {"user", "assistant", "system", "developer"}:
            return one(str(role), "asserted" if role == "user" else "reasoned", payload.get("content"))
    if item_type == "user_message":
        return one("user", "asserted", payload.get("message", payload.get("text_elements")))
    if item_type == "agent_message":
        return one("assistant", "reasoned", payload.get("content"))
    if item_type in {"function_call", "custom_tool_call"}:
        return one("tool", "reasoned", payload.get("arguments", payload.get("input")))
    if item_type in {"function_call_output", "custom_tool_call_output"}:
        return one("tool_result", "observed", payload.get("output"))
    if item_type != "item_completed":
        return ()
    wrapped = payload.get("item")
    if not isinstance(wrapped, Mapping):
        return ()
    wrapped_id_value = wrapped.get("id")
    wrapped_id = str(wrapped_id_value) if isinstance(wrapped_id_value, (str, int)) else None
    if wrapped_id and wrapped_id in seen_item_ids:
        return ()
    wrapped_type = wrapped.get("type")
    if wrapped_type == "UserMessage":
        return one("user", "asserted", wrapped.get("content"), identifier=wrapped_id)
    if wrapped_type == "AgentMessage":
        return one("assistant", "reasoned", wrapped.get("content"), identifier=wrapped_id)
    if wrapped_type in {"CommandExecution", "McpToolCall"}:
        value = wrapped.get("aggregated_output", wrapped.get("result", wrapped.get("stdout")))
        return one("tool_result", "observed", value, identifier=wrapped_id)
    return ()


def _text_leaves(value: Any) -> Iterable[str]:
    """Yield every serialized text leaf so R24 runs before role filtering."""

    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for item in value.values():
            yield from _text_leaves(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _text_leaves(item)


def _empty_coverage(
    artifact_id: str,
    harness: str,
    terminal_status: str,
    reason: str,
    source_event_count: int,
    *,
    event_coverage: Sequence[Mapping[str, Any]] = (),
    redaction_count: int = 0,
    excluded_injected_blocks: int = 0,
    excluded_fingerprints: Sequence[str] = (),
    injected_provenance: Mapping[str, int] | None = None,
) -> dict[str, Any]:
    return {
        "artifact_id": artifact_id,
        "harness": harness,
        "terminal_status": terminal_status,
        "reason": reason,
        "source_event_count": source_event_count,
        "normalized_event_count": 0,
        "packet_count": 0,
        "packet_event_count": 0,
        "event_coverage": list(event_coverage),
        "redaction_count": redaction_count,
        "injected_context": {
            "excluded_blocks": excluded_injected_blocks,
            "fingerprints": list(sorted(set(excluded_fingerprints))),
            "provenance": dict(sorted((injected_provenance or {}).items())),
        },
    }


def _quarantined_result(
    artifact_id: str,
    harness: str,
    reason: str,
    source_event_count: int,
    *,
    event_coverage: Sequence[Mapping[str, Any]] = (),
    redaction_count: int = 0,
    excluded_injected_blocks: int = 0,
    excluded_fingerprints: Sequence[str] = (),
    injected_provenance: Mapping[str, int] | None = None,
) -> ArtifactNormalization:
    coverage = _empty_coverage(
        artifact_id,
        harness,
        "quarantined",
        reason,
        source_event_count,
        event_coverage=event_coverage,
        redaction_count=redaction_count,
        excluded_injected_blocks=excluded_injected_blocks,
        excluded_fingerprints=excluded_fingerprints,
        injected_provenance=injected_provenance,
    )
    return ArtifactNormalization(
        artifact_id=artifact_id,
        harness=harness,
        terminal_status="quarantined",
        reason=reason,
        events=(),
        packets=(),
        coverage=coverage,
        redaction_count=redaction_count,
        excluded_injected_blocks=excluded_injected_blocks,
        excluded_fingerprints=tuple(sorted(set(excluded_fingerprints))),
        injected_provenance=dict(sorted((injected_provenance or {}).items())),
    )


def _post_serialize_packet(packet: Mapping[str, Any], *, rules_path: Path) -> tuple[dict[str, Any] | None, str | None, int]:
    """Run the same policy after serialization before a packet can be written."""

    serialized = canonical_json(packet)
    redacted = redact_text(serialized, rules_path=rules_path)
    if redacted.status is RedactionStatus.QUARANTINED or redacted.text is None:
        return None, "post_serialization_redaction_quarantine", 0
    if scan_for_unsafe_content(redacted.text, rules_path=rules_path):
        return None, "post_serialization_unsafe_content", 0
    try:
        value = json.loads(redacted.text)
    except json.JSONDecodeError:
        return None, "post_serialization_invalid_json", 0
    if not isinstance(value, dict):
        return None, "post_serialization_invalid_json", 0
    return value, None, len(redacted.text.encode("utf-8"))


def _build_packets(
    artifact_id: str,
    harness: str,
    source_version: str,
    events: Sequence[Mapping[str, Any]],
    *,
    packet_byte_limit: int,
    packet_token_limit: int,
    rules_path: Path,
    fingerprints_path: Path,
) -> tuple[tuple[dict[str, Any], ...], str | None]:
    packets: list[dict[str, Any]] = []
    current: list[Mapping[str, Any]] = []

    def packet_for(candidate_events: Sequence[Mapping[str, Any]]) -> tuple[dict[str, Any] | None, str | None, int]:
        event_ids = [str(event["event_id"]) for event in candidate_events]
        packet = {
            "schema_version": "session-packet/v1",
            "packet_id": _stable_packet_id(artifact_id, source_version, event_ids),
            "artifact_id": artifact_id,
            "harness": harness,
            "source_version": source_version,
            "redaction_policy_version": redaction_policy_version(rules_path=rules_path),
            "fingerprint_policy_version": fingerprint_policy_version(fingerprints_path=fingerprints_path),
            "event_ids": event_ids,
            "events": list(candidate_events),
        }
        safe_packet, reason, packet_bytes = _post_serialize_packet(packet, rules_path=rules_path)
        if safe_packet is None:
            return None, reason, packet_bytes
        if packet_bytes > packet_byte_limit or (packet_bytes + BYTES_PER_TOKEN - 1) // BYTES_PER_TOKEN > packet_token_limit:
            return safe_packet, "packet_too_large", packet_bytes
        return safe_packet, None, packet_bytes

    for event in events:
        proposed = [*current, event]
        packet, reason, _packet_bytes = packet_for(proposed)
        if reason is None:
            current = proposed
            continue
        if reason != "packet_too_large":
            return (), reason
        if not current:
            return (), "packet_too_large"
        completed, completed_reason, _ = packet_for(current)
        if completed is None or completed_reason is not None:
            return (), completed_reason or "packet_too_large"
        packets.append(completed)
        current = [event]
        single, single_reason, _ = packet_for(current)
        if single is None or single_reason is not None:
            return (), single_reason or "packet_too_large"
    if current:
        final_packet, final_reason, _ = packet_for(current)
        if final_packet is None or final_reason is not None:
            return (), final_reason or "packet_too_large"
        packets.append(final_packet)
    return tuple(packets), None


def normalize_records(
    artifact: Mapping[str, Any],
    records: Iterable[Mapping[str, Any]],
    *,
    window_start: datetime,
    cutoff: datetime,
    packet_byte_limit: int = MAX_PACKET_BYTES,
    packet_token_limit: int = MAX_PACKET_TOKENS,
    rules_path: Path = _DEFAULT_RULES_PATH,
    fingerprints_path: Path = _DEFAULT_FINGERPRINTS_PATH,
) -> ArtifactNormalization:
    """Normalize already decoded records into ordered, redacted evidence packets."""

    artifact_id, harness, source_version, expected_event_count = _artifact_fields(artifact)
    if packet_byte_limit <= 0 or packet_token_limit <= 0:
        raise ValueError("normalization_invalid_packet_limit")
    source_ordinal = 0
    events: list[dict[str, Any]] = []
    coverage_entries: list[dict[str, Any]] = []
    excluded_blocks = 0
    fingerprints: set[str] = set()
    redaction_count = 0
    injected_provenance: Counter[str] = Counter()
    seen_item_ids: set[str] = set()

    for source_record in records:
        if not isinstance(source_record, Mapping):
            continue
        timestamp = parse_timestamp(source_record.get("timestamp"))
        if timestamp is None or timestamp < window_start or timestamp >= cutoff:
            continue
        source_ordinal += 1
        source_event_id = _stable_source_event_id(artifact_id, source_version, source_ordinal)
        record_type = str(source_record.get("type", "unknown"))
        record_exclusions = 0
        for text_leaf in _text_leaves(source_record):
            inspection = inspect_injected_context(text_leaf, fingerprints_path=fingerprints_path)
            record_exclusions += inspection.excluded_injected_blocks
            excluded_blocks += inspection.excluded_injected_blocks
            fingerprints.update(inspection.excluded_fingerprints)
            if inspection.excluded_injected_blocks:
                injected_provenance[record_type] += inspection.excluded_injected_blocks
            if inspection.status is RedactionStatus.QUARANTINED:
                coverage_entries.append(
                    {
                        "source_event_id": source_event_id,
                        "ordinal": source_ordinal,
                        "disposition": "quarantined",
                        "reason": inspection.reason or "unknown_injected_context",
                        "packet_event_ids": [],
                    }
                )
                return _quarantined_result(
                    artifact_id,
                    harness,
                    inspection.reason or "unknown_injected_context",
                    source_ordinal,
                    event_coverage=coverage_entries,
                    redaction_count=redaction_count,
                    excluded_injected_blocks=excluded_blocks,
                    excluded_fingerprints=fingerprints,
                    injected_provenance=injected_provenance,
                )
        candidates = _codex_candidates(source_record, seen_item_ids) if harness == "codex" else _claude_candidates(source_record)
        record_event_ids: list[str] = []
        for candidate in candidates:
            inspection = inspect_injected_context(candidate.text, fingerprints_path=fingerprints_path)
            if inspection.status is RedactionStatus.QUARANTINED:
                coverage_entries.append(
                    {
                        "source_event_id": source_event_id,
                        "ordinal": source_ordinal,
                        "disposition": "quarantined",
                        "reason": inspection.reason or "unknown_injected_context",
                        "packet_event_ids": [],
                    }
                )
                return _quarantined_result(
                    artifact_id,
                    harness,
                    inspection.reason or "unknown_injected_context",
                    source_ordinal,
                    event_coverage=coverage_entries,
                    redaction_count=redaction_count,
                    excluded_injected_blocks=excluded_blocks,
                    excluded_fingerprints=fingerprints,
                    injected_provenance=injected_provenance,
                )
            assert inspection.text is not None
            if candidate.role in {"system", "developer", "hook"} and inspection.text.strip():
                coverage_entries.append(
                    {
                        "source_event_id": source_event_id,
                        "ordinal": source_ordinal,
                        "disposition": "quarantined",
                        "reason": "unknown_injected_context",
                        "packet_event_ids": [],
                    }
                )
                return _quarantined_result(
                    artifact_id,
                    harness,
                    "unknown_injected_context",
                    source_ordinal,
                    event_coverage=coverage_entries,
                    redaction_count=redaction_count,
                    excluded_injected_blocks=excluded_blocks,
                    excluded_fingerprints=fingerprints,
                    injected_provenance=injected_provenance,
                )
            if not inspection.text.strip():
                continue
            redacted = redact_text(inspection.text, rules_path=rules_path)
            if redacted.status is RedactionStatus.QUARANTINED or redacted.text is None:
                coverage_entries.append(
                    {
                        "source_event_id": source_event_id,
                        "ordinal": source_ordinal,
                        "disposition": "quarantined",
                        "reason": redacted.reason or "redaction_quarantine",
                        "packet_event_ids": [],
                    }
                )
                return _quarantined_result(
                    artifact_id,
                    harness,
                    redacted.reason or "redaction_quarantine",
                    source_ordinal,
                    event_coverage=coverage_entries,
                    redaction_count=redaction_count,
                    excluded_injected_blocks=excluded_blocks,
                    excluded_fingerprints=fingerprints,
                    injected_provenance=injected_provenance,
                )
            event_id = _stable_event_id(artifact_id, source_version, source_ordinal, candidate.part, candidate.role)
            event = {
                "event_id": event_id,
                "ordinal": source_ordinal,
                "timestamp": _format_timestamp(timestamp),
                "role": candidate.role,
                "evidence_strength": candidate.evidence_strength,
                "evidence_uri": f"session://{harness}/{artifact_id}@{source_version}#event={event_id}",
                "text": redacted.text,
            }
            if len(canonical_json(event).encode("utf-8")) > MAX_NORMALIZED_EVENT_BYTES:
                coverage_entries.append(
                    {
                        "source_event_id": source_event_id,
                        "ordinal": source_ordinal,
                        "disposition": "quarantined",
                        "reason": "event_too_large",
                        "packet_event_ids": [],
                    }
                )
                return _quarantined_result(
                    artifact_id,
                    harness,
                    "event_too_large",
                    source_ordinal,
                    event_coverage=coverage_entries,
                    redaction_count=redaction_count,
                    excluded_injected_blocks=excluded_blocks,
                    excluded_fingerprints=fingerprints,
                    injected_provenance=injected_provenance,
                )
            events.append(event)
            record_event_ids.append(event_id)
            redaction_count += redacted.redaction_count
        coverage_entries.append(
            {
                "source_event_id": source_event_id,
                "ordinal": source_ordinal,
                "disposition": "packet" if record_event_ids else ("excluded_injected_context" if record_exclusions else "unsupported_record"),
                "reason": UNKNOWN if record_event_ids else ("injected_context_removed" if record_exclusions else "no_supported_text"),
                "packet_event_ids": record_event_ids,
            }
        )
    if source_ordinal != expected_event_count:
        return _quarantined_result(
            artifact_id,
            harness,
            "manifest_event_count_mismatch",
            source_ordinal,
            event_coverage=coverage_entries,
            redaction_count=redaction_count,
            excluded_injected_blocks=excluded_blocks,
            excluded_fingerprints=fingerprints,
            injected_provenance=injected_provenance,
        )
    packets, packet_reason = _build_packets(
        artifact_id,
        harness,
        source_version,
        events,
        packet_byte_limit=packet_byte_limit,
        packet_token_limit=packet_token_limit,
        rules_path=rules_path,
        fingerprints_path=fingerprints_path,
    )
    if packet_reason:
        return _quarantined_result(
            artifact_id,
            harness,
            packet_reason,
            source_ordinal,
            event_coverage=coverage_entries,
            redaction_count=redaction_count,
            excluded_injected_blocks=excluded_blocks,
            excluded_fingerprints=fingerprints,
            injected_provenance=injected_provenance,
        )
    packet_by_event = {
        event_id: str(packet["packet_id"])
        for packet in packets
        for event_id in packet["event_ids"]
    }
    for entry in coverage_entries:
        event_ids = entry["packet_event_ids"]
        entry["packet_ids"] = [packet_by_event[event_id] for event_id in event_ids]
    coverage = {
        "artifact_id": artifact_id,
        "harness": harness,
        "terminal_status": "complete",
        "reason": UNKNOWN,
        "source_event_count": source_ordinal,
        "normalized_event_count": len(events),
        "packet_count": len(packets),
        "packet_event_count": sum(len(packet["event_ids"]) for packet in packets),
        "event_coverage": coverage_entries,
        "redaction_count": redaction_count,
        "injected_context": {
            "excluded_blocks": excluded_blocks,
            "fingerprints": sorted(fingerprints),
            "provenance": dict(sorted(injected_provenance.items())),
        },
    }
    result = ArtifactNormalization(
        artifact_id=artifact_id,
        harness=harness,
        terminal_status="complete",
        reason=UNKNOWN,
        events=tuple(events),
        packets=packets,
        coverage=coverage,
        redaction_count=redaction_count,
        excluded_injected_blocks=excluded_blocks,
        excluded_fingerprints=tuple(sorted(fingerprints)),
        injected_provenance=dict(sorted(injected_provenance.items())),
    )
    if not validate_packet_coverage(result):
        return _quarantined_result(
            artifact_id,
            harness,
            "packet_coverage_mismatch",
            source_ordinal,
            event_coverage=coverage_entries,
            redaction_count=redaction_count,
            excluded_injected_blocks=excluded_blocks,
            excluded_fingerprints=fingerprints,
            injected_provenance=injected_provenance,
        )
    return result


def validate_packet_coverage(result: ArtifactNormalization) -> bool:
    """Prove packet event IDs cover each normalized event once and in order."""

    if result.terminal_status != "complete":
        return False
    event_ids = [str(event.get("event_id", "")) for event in result.events]
    packet_event_ids = [str(event_id) for packet in result.packets for event_id in packet.get("event_ids", ())]
    coverage_event_ids = [
        str(event_id)
        for entry in result.coverage.get("event_coverage", ())
        for event_id in entry.get("packet_event_ids", ())
    ]
    if not event_ids or not packet_event_ids:
        return event_ids == packet_event_ids == coverage_event_ids
    if len(event_ids) != len(set(event_ids)):
        return False
    if event_ids != packet_event_ids or event_ids != coverage_event_ids:
        return False
    source_ids = [str(entry.get("source_event_id", "")) for entry in result.coverage.get("event_coverage", ())]
    if len(source_ids) != len(set(source_ids)):
        return False
    return int(result.coverage.get("packet_event_count", -1)) == len(event_ids)


def _read_source_records(path: Path, root: Path, window_start: datetime, cutoff: datetime) -> _SourceRead:
    descriptor, source_stat, error = _open_safe_regular(path, root)
    if error:
        return _SourceRead((), 0, UNKNOWN, UNKNOWN, error, False)
    assert descriptor is not None and source_stat is not None
    records: list[dict[str, Any]] = []
    source_hash = hashlib.sha256()
    content_hash = hashlib.sha256()
    source_events = 0
    read_reason: str | None = None
    changed = False
    try:
        with os.fdopen(descriptor, "rb", closefd=True) as stream:
            descriptor = None
            while True:
                raw = stream.readline(MAX_RECORD_BYTES + 1)
                if not raw:
                    break
                if len(raw) > MAX_RECORD_BYTES:
                    while raw and not raw.endswith(b"\n"):
                        raw = stream.readline(MAX_RECORD_BYTES + 1)
                    read_reason = "record_too_large"
                    break
                source_hash.update(raw)
                try:
                    record = json.loads(raw)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    read_reason = "malformed_jsonl"
                    break
                if not isinstance(record, dict):
                    read_reason = "malformed_jsonl"
                    break
                timestamp = parse_timestamp(record.get("timestamp"))
                if timestamp is None or timestamp < window_start or timestamp >= cutoff:
                    continue
                source_events += 1
                content_hash.update(canonical_json(record).encode("utf-8") + b"\n")
                records.append(record)
            completed = os.fstat(stream.fileno())
            changed = (completed.st_dev, completed.st_ino, completed.st_size, completed.st_mtime_ns, completed.st_ctime_ns) != (
                source_stat.st_dev,
                source_stat.st_ino,
                source_stat.st_size,
                source_stat.st_mtime_ns,
                source_stat.st_ctime_ns,
            )
    except OSError:
        read_reason = "source_read_failed"
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
    if changed and read_reason is None:
        read_reason = "source_changed_during_read"
    return _SourceRead(
        records=tuple(records),
        source_event_count=source_events,
        content_sha256=content_hash.hexdigest() if source_events else UNKNOWN,
        source_byte_sha256=source_hash.hexdigest(),
        reason=read_reason,
        source_changed_during_read=changed,
    )


def _source_paths(config: CensusConfig) -> tuple[dict[str, Path], dict[str, str]]:
    paths: dict[str, Path] = {}
    failures: dict[str, str] = {}
    for harness in ("codex", "claude"):
        configured = config.source_roots.get(harness)
        if not isinstance(configured, Path):
            failures[harness] = "source_root_missing"
            continue
        try:
            root = _validate_root(configured.expanduser())
        except (OSError, ValueError) as error:
            reason = str(error)
            failures[harness] = reason if reason in {"root_symlink_rejected", "root_not_directory", "root_unsafe_owner"} else "source_root_unavailable"
            continue
        candidates, discovery_failures = _discover_jsonl_files(root)
        if discovery_failures:
            failures[harness] = "source_discovery_failed"
        for source_path in candidates:
            paths[_artifact_id(harness, source_path.relative_to(root))] = source_path
    return paths, failures


def _aggregate_source_hashes(value: Mapping[str, str]) -> str:
    return _sha256_bytes(canonical_json(dict(sorted(value.items()))).encode("utf-8"))


def _normalization_summary(artifacts: Sequence[ArtifactNormalization]) -> dict[str, Any]:
    statuses = Counter(artifact.terminal_status for artifact in artifacts)
    reasons = Counter(artifact.reason for artifact in artifacts if artifact.reason != UNKNOWN)
    return {
        "artifact_count": len(artifacts),
        "terminal_statuses": {status: statuses[status] for status in ("complete", "excluded", "quarantined", "failed")},
        "reason_aggregates": dict(sorted(reasons.items())),
        "event_count": sum(len(artifact.events) for artifact in artifacts),
        "packet_count": sum(len(artifact.packets) for artifact in artifacts),
        "packet_bytes": sum(len(canonical_json(packet).encode("utf-8")) for artifact in artifacts for packet in artifact.packets),
        "redaction_count": sum(artifact.redaction_count for artifact in artifacts),
        "injected_excluded_blocks": sum(artifact.excluded_injected_blocks for artifact in artifacts),
        "injected_fingerprint_count": len({fingerprint for artifact in artifacts for fingerprint in artifact.excluded_fingerprints}),
    }


def normalize_census(manifest_document: Mapping[str, Any], config: CensusConfig) -> NormalizationRun:
    """Normalize only U1-complete artifacts and preserve upstream quarantines."""

    records_value = manifest_document.get("records") if isinstance(manifest_document, Mapping) else None
    window = manifest_document.get("window") if isinstance(manifest_document, Mapping) else None
    if not isinstance(records_value, list) or not isinstance(window, Mapping):
        raise ValueError("normalization_manifest_invalid")
    manifest_start = parse_timestamp(window.get("start"))
    manifest_cutoff = parse_timestamp(window.get("cutoff"))
    if manifest_start is None or manifest_cutoff is None or manifest_start != config.window_start or manifest_cutoff != config.cutoff:
        raise ValueError("normalization_manifest_window_mismatch")
    source_manifest_sha256 = _sha256_bytes(canonical_json(dict(manifest_document)).encode("utf-8"))
    paths, root_failures = _source_paths(config)
    normalized: list[ArtifactNormalization] = []
    opened_source_hashes: dict[str, str] = {}
    complete_manifest_artifacts = 0
    fixed_window_manifest_matches = 0
    source_changes_during_read = 0
    for manifest_record in sorted(records_value, key=lambda value: str(value.get("artifact_id", "")) if isinstance(value, Mapping) else ""):
        if not isinstance(manifest_record, Mapping):
            continue
        artifact_id, harness, content_sha256, expected_events = _artifact_fields(manifest_record)
        upstream_status = manifest_record.get("terminal_status")
        upstream_reason = manifest_record.get("reason")
        if upstream_status != "complete":
            status = str(upstream_status) if upstream_status in {"excluded", "quarantined", "failed"} else "failed"
            reason = str(upstream_reason) if isinstance(upstream_reason, str) and upstream_reason else "upstream_terminal_status"
            coverage = _empty_coverage(artifact_id, harness, status, reason, expected_events)
            normalized.append(
                ArtifactNormalization(
                    artifact_id=artifact_id,
                    harness=harness,
                    terminal_status=status,
                    reason=reason,
                    events=(),
                    packets=(),
                    coverage=coverage,
                    redaction_count=0,
                    excluded_injected_blocks=0,
                    excluded_fingerprints=(),
                    injected_provenance={},
                )
            )
            continue
        complete_manifest_artifacts += 1
        if harness in root_failures:
            normalized.append(_quarantined_result(artifact_id, harness, root_failures[harness], expected_events))
            continue
        source_path = paths.get(artifact_id)
        configured_root = config.source_roots.get(harness)
        if source_path is None or not isinstance(configured_root, Path):
            normalized.append(_quarantined_result(artifact_id, harness, "source_manifest_resolution_failed", expected_events))
            continue
        read = _read_source_records(source_path, configured_root.expanduser(), config.window_start, config.cutoff)
        if read.source_byte_sha256 != UNKNOWN:
            opened_source_hashes[artifact_id] = read.source_byte_sha256
        if read.source_changed_during_read:
            source_changes_during_read += 1
        if read.reason:
            normalized.append(_quarantined_result(artifact_id, harness, read.reason, read.source_event_count))
            continue
        if read.content_sha256 != content_sha256 or read.source_event_count != expected_events:
            normalized.append(_quarantined_result(artifact_id, harness, "manifest_source_mismatch", read.source_event_count))
            continue
        fixed_window_manifest_matches += 1
        normalized.append(
            normalize_records(
                manifest_record,
                read.records,
                window_start=config.window_start,
                cutoff=config.cutoff,
            )
        )
    descriptors_unchanged_during_read = source_changes_during_read == 0
    source_integrity = {
        # U2's fixed-window invariant is descriptor stability while each source
        # is read. Active harnesses can append records after the cutoff between
        # two runs without changing the selected canonical event corpus.
        "manifest_complete_artifacts": complete_manifest_artifacts,
        "opened_descriptors": len(opened_source_hashes),
        "source_changes_observed_during_read": source_changes_during_read,
        "opened_descriptor_bytes_unchanged_during_read": descriptors_unchanged_during_read,
        # Retained as a compatibility alias. It never claims that an active
        # corpus stayed globally quiescent after the descriptor was closed.
        "source_bytes_unchanged": descriptors_unchanged_during_read,
        "read_only_input_preserved": descriptors_unchanged_during_read,
        "fixed_window_manifest_matches": fixed_window_manifest_matches,
        "fixed_window_manifest_mismatches": complete_manifest_artifacts - fixed_window_manifest_matches,
        "fixed_window_manifest_match_complete": fixed_window_manifest_matches == complete_manifest_artifacts,
        "opened_source_bytes_sha256": _aggregate_source_hashes(opened_source_hashes),
    }
    packets = tuple(packet for artifact in normalized for packet in artifact.packets)
    summary = _normalization_summary(normalized)
    packet_rows = [
        {
            "packet_id": packet["packet_id"],
            "artifact_id": packet["artifact_id"],
            "harness": packet["harness"],
            "source_version": packet["source_version"],
            "event_ids": packet["event_ids"],
            "serialized_bytes": len(canonical_json(packet).encode("utf-8")),
            "estimated_tokens": (len(canonical_json(packet).encode("utf-8")) + BYTES_PER_TOKEN - 1) // BYTES_PER_TOKEN,
            "terminal_outcome": "prepared_no_egress",
        }
        for packet in packets
    ]
    packet_manifest_document = {
        "schema_version": "normalization-packet-manifest/v1",
        "source_manifest_sha256": source_manifest_sha256,
        "window": {"start": _format_timestamp(config.window_start), "cutoff": _format_timestamp(config.cutoff)},
        "redaction_policy_version": redaction_policy_version(),
        "fingerprint_policy_version": fingerprint_policy_version(),
        "packets": packet_rows,
        "summary": summary,
    }
    coverage_document = {
        "schema_version": "normalization-coverage/v1",
        "source_manifest_sha256": source_manifest_sha256,
        "window": packet_manifest_document["window"],
        "records": [artifact.coverage for artifact in normalized],
        "summary": summary,
    }
    settings = config.estimator
    prompt_tokens = int(settings.get("prompt_tokens", 800)) if isinstance(settings, Mapping) else 800
    output_tokens = int(settings.get("output_tokens_per_call", 5_000)) if isinstance(settings, Mapping) else 5_000
    concurrency = int(settings.get("concurrency", 2)) if isinstance(settings, Mapping) else 2
    per_call_minutes = int(settings.get("per_call_minutes", 20)) if isinstance(settings, Mapping) else 20
    estimate = estimate_probe_resources(
        packet_bytes=[row["serialized_bytes"] for row in packet_rows],
        prompt_tokens=prompt_tokens,
        output_tokens_per_call=output_tokens,
        calls=len(packet_rows),
        concurrency=max(1, concurrency),
        per_call_minutes=max(1, per_call_minutes),
        bytes_per_token=BYTES_PER_TOKEN,
    )
    naive_all_packet_egress_status = "within_full_poc_envelope"
    exceeded_dimension = UNKNOWN
    try:
        enforce_r25(estimate, FULL_POC_LIMITS)
    except ResourceBudgetExceeded as error:
        naive_all_packet_egress_status = "blocked_u3_compact_dependence_group_reestimate_required"
        exceeded_dimension = error.dimension
    coverage_complete = all(
        artifact.terminal_status != "complete" or validate_packet_coverage(artifact)
        for artifact in normalized
    )
    receipt_document = {
        "schema_version": "normalization-receipt/v1",
        "source_manifest_sha256": source_manifest_sha256,
        "window": packet_manifest_document["window"],
        "mode": "local_private_no_provider_egress",
        "summary": summary,
        "packet_terminal_outcomes": {"prepared_no_egress": len(packet_rows), "quarantined": summary["terminal_statuses"]["quarantined"]},
        "source_integrity": source_integrity,
        "coverage_complete": coverage_complete,
        "resource_estimate": {
            "estimate_scope": "naive_all_packet_egress_shape",
            "serialized_packet_bytes": estimate.packet_bytes,
            "estimated_input_tokens": estimate.input_tokens,
            "estimated_output_tokens": estimate.output_tokens,
            "estimated_calls": estimate.calls,
            "estimated_wall_minutes": estimate.wall_minutes,
            "estimated_monetary_cost_usd": estimate.monetary_cost_usd,
            "bytes_per_token": estimate.bytes_per_token,
            "naive_all_packet_egress_status": naive_all_packet_egress_status,
            "exceeded_dimension": exceeded_dimension,
            "u2_model_stage": "not_applicable_no_model_stage",
            "future_egress_status": "not_authorized_u2_no_provider_egress",
            "required_before_any_future_dispatch": "u3_dependence_group_compaction_and_reestimate",
        },
    }
    return NormalizationRun(
        packet_manifest_document=packet_manifest_document,
        coverage_document=coverage_document,
        receipt_document=receipt_document,
        artifacts=tuple(normalized),
        packets=packets,
        source_byte_sha256=dict(sorted(opened_source_hashes.items())),
        source_integrity=source_integrity,
        coverage_complete=coverage_complete,
    )


def _strict_private_root(output_root: Path, repository_root: Path, require_ignored: bool) -> Path:
    candidate = Path(output_root).expanduser()
    if not candidate.is_absolute():
        candidate = repository_root / candidate
    resolved_repository = repository_root.resolve(strict=True)
    resolved_candidate = candidate.resolve(strict=False)
    if not resolved_candidate.is_relative_to(resolved_repository) and require_ignored:
        raise ValueError("private_output_outside_repository")
    if require_ignored:
        relative = resolved_candidate.relative_to(resolved_repository).as_posix()
        ignored = subprocess.run(
            ["git", "-C", str(resolved_repository), "check-ignore", "--quiet", "--", relative],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if ignored.returncode != 0:
            raise ValueError("private_output_not_gitignored")
    if candidate.exists() or candidate.is_symlink():
        details = os.lstat(candidate)
        if stat.S_ISLNK(details.st_mode):
            raise ValueError("private_output_symlink")
        if not stat.S_ISDIR(details.st_mode):
            raise ValueError("private_output_not_directory")
        if details.st_uid != os.getuid():
            raise ValueError("private_output_unsafe_owner")
        if stat.S_IMODE(details.st_mode) != 0o700:
            raise ValueError("private_output_permissions_unsafe")
    else:
        candidate.mkdir(mode=0o700, parents=True)
        os.chmod(candidate, 0o700)
        details = os.lstat(candidate)
        if stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode):
            raise ValueError("private_output_not_directory")
    return candidate


def _private_subdirectory(path: Path) -> Path:
    if path.exists() or path.is_symlink():
        details = os.lstat(path)
        if stat.S_ISLNK(details.st_mode):
            raise ValueError("private_output_symlink")
        if not stat.S_ISDIR(details.st_mode) or details.st_uid != os.getuid() or stat.S_IMODE(details.st_mode) != 0o700:
            raise ValueError("private_output_permissions_unsafe")
        return path
    path.mkdir(mode=0o700)
    os.chmod(path, 0o700)
    return path


def _artifact_documents(result: ArtifactNormalization) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], tuple[dict[str, Any], ...]]:
    packet_rows = [
        {
            "packet_id": packet["packet_id"],
            "artifact_id": packet["artifact_id"],
            "harness": packet["harness"],
            "source_version": packet["source_version"],
            "event_ids": packet["event_ids"],
            "serialized_bytes": len(canonical_json(packet).encode("utf-8")),
            "estimated_tokens": (len(canonical_json(packet).encode("utf-8")) + BYTES_PER_TOKEN - 1) // BYTES_PER_TOKEN,
            "terminal_outcome": "prepared_no_egress",
        }
        for packet in result.packets
    ]
    summary = _normalization_summary((result,))
    manifest = {
        "schema_version": "normalization-packet-manifest/v1",
        "source_manifest_sha256": "fixture",
        "window": {"start": UNKNOWN, "cutoff": UNKNOWN},
        "redaction_policy_version": redaction_policy_version(),
        "fingerprint_policy_version": fingerprint_policy_version(),
        "packets": packet_rows,
        "summary": summary,
    }
    coverage = {
        "schema_version": "normalization-coverage/v1",
        "source_manifest_sha256": "fixture",
        "window": manifest["window"],
        "records": [result.coverage],
        "summary": summary,
    }
    receipt = {
        "schema_version": "normalization-receipt/v1",
        "source_manifest_sha256": "fixture",
        "window": manifest["window"],
        "mode": "local_private_no_provider_egress",
        "summary": summary,
        "coverage_complete": result.terminal_status == "complete" and validate_packet_coverage(result),
    }
    return manifest, coverage, receipt, result.packets


def write_normalization_private(
    result: ArtifactNormalization | NormalizationRun,
    output_root: Path,
    *,
    repository_root: Path = _REPOSITORY_ROOT,
    require_ignored: bool = True,
) -> NormalizationOutput:
    """Persist only redacted packets and metadata under a strict private root."""

    root = _strict_private_root(Path(output_root), Path(repository_root), require_ignored)
    if isinstance(result, NormalizationRun):
        cutoff = str(result.packet_manifest_document["window"]["cutoff"]).replace(":", "").replace("-", "")
        run_directory = root / f"fixed-{cutoff}"
        if run_directory.exists() or run_directory.is_symlink():
            raise ValueError("normalization_run_exists")
        run_directory = _private_subdirectory(run_directory)
        packet_manifest = result.packet_manifest_document
        coverage = result.coverage_document
        receipt = result.receipt_document
        packets = result.packets
    else:
        run_directory = root
        packet_manifest, coverage, receipt, packets = _artifact_documents(result)
    packet_directory = _private_subdirectory(run_directory / "packets")
    packet_paths: list[Path] = []
    for packet in packets:
        packet_path = packet_directory / f"{packet['packet_id']}.json"
        secure_write_text(packet_path, canonical_json(packet) + "\n")
        packet_paths.append(packet_path)
    manifest_path = run_directory / "packet-manifest.json"
    coverage_path = run_directory / "coverage.json"
    receipt_path = run_directory / "receipt.json"
    secure_write_text(manifest_path, canonical_json(packet_manifest) + "\n")
    secure_write_text(coverage_path, canonical_json(coverage) + "\n")
    receipt_sha256 = _sha256_bytes(canonical_json(receipt).encode("utf-8"))
    secure_write_text(receipt_path, canonical_json({"receipt_sha256": receipt_sha256, "receipt": receipt}) + "\n")
    return NormalizationOutput(
        root=root,
        run_directory=run_directory,
        files=tuple([*packet_paths, manifest_path, coverage_path, receipt_path]),
        receipt_path=receipt_path,
        receipt_sha256=receipt_sha256,
    )
