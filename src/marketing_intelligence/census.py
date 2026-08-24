"""Read-only, privacy-preserving census of Codex and Claude JSONL artifacts."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Any, BinaryIO, Iterable, Mapping

from .estimate import FULL_POC_LIMITS, ResourceBudgetExceeded, TieredStageEstimate, enforce_r25, estimate_tiered_stage
from .redact import secure_write_text


_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
WINDOW_START_TEXT = "2026-08-16T20:00:00Z"
WINDOW_CUTOFF_TEXT = "2026-08-24T14:57:36Z"
MAX_RECORD_BYTES = 2 * 1024 * 1024
UNKNOWN = "?"


def parse_timestamp(value: Any) -> datetime | None:
    """Normalize supported source timestamps to timezone-aware UTC."""

    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        seconds = float(value)
        if abs(seconds) >= 100_000_000_000:
            seconds /= 1_000
        try:
            return datetime.fromtimestamp(seconds, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


CENSUS_START = parse_timestamp(WINDOW_START_TEXT)
CENSUS_CUTOFF = parse_timestamp(WINDOW_CUTOFF_TEXT)
assert CENSUS_START is not None and CENSUS_CUTOFF is not None


_KNOWN_TYPES: dict[str, set[str]] = {
    "codex": {
        "compacted",
        "event_msg",
        "inter_agent_communication_metadata",
        "response_item",
        "session_meta",
        "turn_context",
        "world_state",
    },
    "claude": {
        "agent-name",
        "agent-setting",
        "ai-title",
        "artifact-autoreact-ledger",
        "artifact-comment-monitor",
        "assistant",
        "atis-latch",
        "attachment",
        "bridge-session",
        "custom-title",
        "file-history-delta",
        "file-history-snapshot",
        "fork-context-ref",
        "frame-link",
        "last-prompt",
        "mode",
        "permission-mode",
        "queue-operation",
        "result",
        "started",
        "system",
        "user",
    },
}
_COUNTER_KEYS = (
    "total_lines",
    "blank_lines",
    "malformed_lines",
    "oversized_records",
    "parsed_records",
    "missing_timestamp_records",
    "invalid_timestamp_records",
    "unknown_record_types",
    "missing_logical_session_ids",
    "conflicting_logical_session_ids",
    "supplemental_session_ids",
    "post_cutoff_identity_conflicts",
)
_TERMINAL_STATUSES = ("complete", "excluded", "quarantined", "failed")


@dataclass(frozen=True)
class CensusConfig:
    """Authoritative read-only roots and a fixed half-open event window."""

    source_roots: Mapping[str, Path]
    window_start: datetime = CENSUS_START
    cutoff: datetime = CENSUS_CUTOFF
    estimator: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CensusRun:
    """Canonical public-safe documents plus private in-memory source custody."""

    manifest_document: dict[str, Any]
    coverage_document: dict[str, Any]
    receipt_document: dict[str, Any]
    summary: dict[str, Any]
    manifest_sha256: str
    coverage_sha256: str
    source_byte_sha256: Mapping[str, str]
    source_integrity: Mapping[str, Any]
    observation_counters: Mapping[str, int]


@dataclass(frozen=True)
class CensusOutput:
    """Private paths returned only to local callers, never printed by the CLI."""

    root: Path
    run_directory: Path
    files: tuple[Path, ...]
    receipt_path: Path
    receipt_sha256: str


def canonical_json(value: Any) -> str:
    """Serialize deterministic JSON without copying source text into logs."""

    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _format_timestamp(value: datetime | None) -> str:
    if value is None:
        return UNKNOWN
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _artifact_id(harness: str, relative_path: Path) -> str:
    source_identity = f"{harness}\0{relative_path.as_posix()}".encode("utf-8")
    return "artifact-" + _sha256_bytes(source_identity)[:24]


def _safe_string(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    return None


def _add_metadata_value(target: set[str], value: Any) -> None:
    normalized = _safe_string(value)
    if normalized:
        target.add(normalized)


def _new_metadata() -> dict[str, Any]:
    return {
        # Identity fields are intentionally ordered. Codex session metadata can
        # contain historical records for a prior thread, and Claude can carry a
        # snake-case lineage identifier next to its primary camel-case ID.
        "codex_primary_logical_session_id": None,
        "codex_primary_session_container_id": None,
        "codex_fallback_session_ids": set(),
        "claude_primary_session_ids": set(),
        "claude_fallback_session_ids": set(),
        "supplemental_session_ids": set(),
        "parent_references": set(),
        "entry_points": set(),
        "session_kinds": set(),
        "cwd_values": set(),
        "sidechain_values": set(),
    }


def _payload(record: Mapping[str, Any]) -> Mapping[str, Any]:
    payload = record.get("payload")
    return payload if isinstance(payload, Mapping) else {}


def _remember_first(metadata: dict[str, Any], primary_key: str, supplemental_key: str, value: Any) -> bool:
    """Remember the first observed canonical value and record later aliases."""

    normalized = _safe_string(value)
    if normalized is None:
        return False
    primary = metadata[primary_key]
    if primary is None:
        metadata[primary_key] = normalized
        return True
    if primary != normalized:
        supplemental = metadata[supplemental_key]
        assert isinstance(supplemental, set)
        supplemental.add(normalized)
        return False
    return True


def _collect_metadata(harness: str, record: Mapping[str, Any], metadata: dict[str, Any]) -> None:
    """Collect observed provenance without retaining transcript bodies or paths."""

    payload = _payload(record)
    parent_references = metadata["parent_references"]
    entry_points = metadata["entry_points"]
    session_kinds = metadata["session_kinds"]
    cwd_values = metadata["cwd_values"]
    sidechain_values = metadata["sidechain_values"]
    assert isinstance(parent_references, set)
    assert isinstance(entry_points, set)
    assert isinstance(session_kinds, set)
    assert isinstance(cwd_values, set)
    assert isinstance(sidechain_values, set)

    if harness == "codex":
        if record.get("type") == "session_meta":
            # ``id`` is the concrete thread that ``parent_thread_id`` targets.
            # A different later session_meta belongs to the artifact's retained
            # historical context; it is provenance, not a contradictory primary.
            is_primary_metadata = _remember_first(
                metadata,
                "codex_primary_logical_session_id",
                "supplemental_session_ids",
                payload.get("id"),
            )
            if is_primary_metadata:
                _remember_first(
                    metadata,
                    "codex_primary_session_container_id",
                    "supplemental_session_ids",
                    payload.get("session_id"),
                )
            elif metadata["codex_primary_logical_session_id"] is not None:
                supplemental_ids = metadata["supplemental_session_ids"]
                assert isinstance(supplemental_ids, set)
                _add_metadata_value(supplemental_ids, payload.get("session_id"))
                return
        else:
            fallback_ids = metadata["codex_fallback_session_ids"]
            assert isinstance(fallback_ids, set)
            for key in ("session_id", "thread_id"):
                _add_metadata_value(fallback_ids, payload.get(key))
    else:
        primary_ids = metadata["claude_primary_session_ids"]
        fallback_ids = metadata["claude_fallback_session_ids"]
        supplemental_ids = metadata["supplemental_session_ids"]
        assert isinstance(primary_ids, set)
        assert isinstance(fallback_ids, set)
        assert isinstance(supplemental_ids, set)
        _add_metadata_value(primary_ids, record.get("sessionId"))
        primary_id = _safe_string(record.get("sessionId"))
        for key in ("session_id", "thread_id"):
            value = record.get(key)
            _add_metadata_value(fallback_ids, value)
            normalized = _safe_string(value)
            if primary_id and normalized and normalized != primary_id:
                supplemental_ids.add(normalized)
        for key in ("session_id", "thread_id"):
            value = payload.get(key)
            _add_metadata_value(fallback_ids, value)
            normalized = _safe_string(value)
            if primary_id and normalized and normalized != primary_id:
                supplemental_ids.add(normalized)
    for key in ("parentUuid", "parent_uuid", "parent_thread_id", "parent_session_id", "logicalParentUuid", "forkedFrom"):
        _add_metadata_value(parent_references, record.get(key))
        _add_metadata_value(parent_references, payload.get(key))
    for key in ("entrypoint", "entry_point"):
        _add_metadata_value(entry_points, record.get(key))
        _add_metadata_value(entry_points, payload.get(key))
    # Codex writes source/thread_source rather than Claude's entrypoint key.
    if harness == "codex":
        for key in ("source", "thread_source"):
            _add_metadata_value(entry_points, payload.get(key))
    for key in ("sessionKind", "session_kind"):
        _add_metadata_value(session_kinds, record.get(key))
        _add_metadata_value(session_kinds, payload.get(key))
    for key in ("cwd", "working_directory"):
        _add_metadata_value(cwd_values, record.get(key))
        _add_metadata_value(cwd_values, payload.get(key))
    for key in ("isSidechain", "is_sidechain"):
        value = record.get(key, payload.get(key))
        if isinstance(value, bool):
            sidechain_values.add(value)


def _observe_post_cutoff_identity_conflict(harness: str, record: Mapping[str, Any], metadata: Mapping[str, Any], counters: Counter[str]) -> None:
    """Count a late identity alias without letting it change canonical identity."""

    payload = _payload(record)
    if harness == "codex" and record.get("type") == "session_meta":
        primary = metadata["codex_primary_logical_session_id"]
        observed = _safe_string(payload.get("id"))
        if primary is not None and observed is not None and observed != primary:
            counters["post_cutoff_identity_conflicts"] += 1
        return
    if harness == "claude":
        primary_ids = metadata["claude_primary_session_ids"]
        observed = _safe_string(record.get("sessionId"))
        if isinstance(primary_ids, set) and len(primary_ids) == 1 and observed is not None and observed not in primary_ids:
            counters["post_cutoff_identity_conflicts"] += 1


def _single_value(values: Iterable[str]) -> str:
    ordered = sorted(set(values))
    return ordered[0] if len(ordered) == 1 else UNKNOWN


def _single_bool(values: Iterable[bool]) -> bool | str:
    ordered = sorted(set(values))
    return ordered[0] if len(ordered) == 1 else UNKNOWN


def _working_directory_category(cwd_values: Iterable[str]) -> tuple[str, str, str]:
    values = tuple(value.casefold().replace("\\", "/") for value in cwd_values)
    if not values:
        return "unknown", "unknown", UNKNOWN
    if any("/tests" in value or "/test/" in value for value in values):
        return "synthetic_test", "inferred", "cwd:tests"
    if any("marketing-intelligence-layer" in value for value in values):
        return "marketing_project", "inferred", "cwd:marketing-intelligence-layer"
    if any("/documents/" in value for value in values):
        return "documents", "inferred", "cwd:documents"
    return "other", "inferred", "cwd:other"


def _execution_shape(entry_point: str, session_kind: str, cwd_category: str) -> tuple[str, str, str]:
    observed = " ".join(value.casefold() for value in (entry_point, session_kind) if value != UNKNOWN)
    if "sdk" in observed:
        return "sdk", "observed", "entry_point_or_session_kind:sdk"
    if any(token in observed for token in ("cli", "interactive", "terminal")):
        return "interactive", "observed", "entry_point_or_session_kind:interactive"
    if cwd_category == "synthetic_test":
        return "synthetic_test", "inferred", "cwd:tests"
    return "unknown", "unknown", UNKNOWN


def _source_kind(parent_reference: str, sidechain: bool | str) -> str:
    if sidechain is True or parent_reference != UNKNOWN:
        return "child_agent"
    if sidechain is False:
        return "root_conversation"
    return "unknown"


def _dependence_fields(
    *,
    harness: str,
    logical_session_id: str,
    session_container_id: str,
    parent_reference: str,
    entry_point: str,
    session_kind: str,
    working_directory_category: str,
) -> tuple[str, dict[str, str]]:
    anchor = session_container_id if session_container_id != UNKNOWN else (logical_session_id if logical_session_id != UNKNOWN else parent_reference)
    fields = {
        "harness": harness,
        "group_anchor": anchor,
        "session_container_id": session_container_id,
        "parent_reference": parent_reference,
        "entry_point": entry_point,
        "session_kind": session_kind,
        "working_directory_category": working_directory_category,
        "prompt_hash": UNKNOWN,
        "input_hash": UNKNOWN,
        "code_version": UNKNOWN,
        "configuration_version": UNKNOWN,
        "source_dataset": UNKNOWN,
        "injected_context_fingerprint": UNKNOWN,
    }
    group_id = "dependence-" + _sha256_bytes(canonical_json(fields).encode("utf-8"))[:24]
    return group_id, fields


def _empty_record_counters() -> Counter[str]:
    return Counter({key: 0 for key in _COUNTER_KEYS})


def _iter_bounded_lines(stream: BinaryIO) -> Iterable[tuple[bytes | None, bool]]:
    """Yield a JSONL line or an oversize marker without retaining body content."""

    while True:
        raw = stream.readline(MAX_RECORD_BYTES + 1)
        if not raw:
            return
        if len(raw) > MAX_RECORD_BYTES:
            while raw and not raw.endswith(b"\n"):
                raw = stream.readline(MAX_RECORD_BYTES + 1)
            yield None, True
            continue
        yield raw, False


def _validate_root(root: Path) -> Path:
    root_stat = os.lstat(root)
    if stat.S_ISLNK(root_stat.st_mode):
        raise ValueError("root_symlink_rejected")
    if not stat.S_ISDIR(root_stat.st_mode):
        raise ValueError("root_not_directory")
    if root_stat.st_uid != os.getuid():
        raise ValueError("root_unsafe_owner")
    return root.resolve(strict=True)


def _discover_jsonl_files(root: Path) -> tuple[list[Path], int]:
    """Discover only JSONL candidates; never follow a symlinked directory."""

    candidates: list[Path] = []
    discovery_failures = 0
    stack = [root]
    while stack:
        directory = stack.pop()
        try:
            with os.scandir(directory) as entries:
                ordered = sorted(entries, key=lambda entry: entry.name)
        except OSError:
            discovery_failures += 1
            continue
        for entry in ordered:
            path = Path(entry.path)
            try:
                entry_stat = os.lstat(path)
            except OSError:
                discovery_failures += 1
                continue
            if stat.S_ISLNK(entry_stat.st_mode):
                if path.suffix == ".jsonl":
                    candidates.append(path)
                continue
            if stat.S_ISDIR(entry_stat.st_mode):
                stack.append(path)
            elif path.suffix == ".jsonl":
                candidates.append(path)
    return sorted(candidates, key=lambda path: path.relative_to(root).as_posix()), discovery_failures


def _open_safe_regular(path: Path, root: Path) -> tuple[int | None, os.stat_result | None, str | None]:
    """Open one regular source using no-follow and descriptor-level checks."""

    try:
        before = os.lstat(path)
    except OSError:
        return None, None, "source_unstatable"
    if stat.S_ISLNK(before.st_mode):
        return None, None, "symlink_rejected"
    if not stat.S_ISREG(before.st_mode):
        return None, None, "special_file_rejected"
    try:
        resolved_root = root.resolve(strict=True)
        resolved_path = path.resolve(strict=True)
    except OSError:
        return None, None, "source_path_unresolvable"
    if not resolved_path.is_relative_to(resolved_root):
        return None, None, "source_path_outside_root"
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return None, None, "source_open_failed"
    keep_descriptor = False
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            return None, None, "special_file_rejected"
        if opened.st_uid != os.getuid():
            return None, None, "unsafe_source_owner"
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            return None, None, "descriptor_mismatch"
        keep_descriptor = True
        return descriptor, opened, None
    except OSError:
        return None, None, "descriptor_check_failed"
    finally:
        # A successful descriptor is returned to the caller; failures close here.
        if not keep_descriptor:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _base_record(harness: str, artifact_id: str) -> dict[str, Any]:
    return {
        "artifact_id": artifact_id,
        "harness": harness,
        "logical_session_id": UNKNOWN,
        "session_container_id": UNKNOWN,
        "parent_logical_session_id": UNKNOWN,
        "parent_artifact_id": UNKNOWN,
        "sidechain": UNKNOWN,
        "source_kind": "unknown",
        "entry_point": UNKNOWN,
        "session_kind": UNKNOWN,
        "classification": {
            "execution_shape": {"value": "unknown", "provenance": "unknown", "rule": UNKNOWN},
            "working_directory": {"value": "unknown", "provenance": "unknown", "rule": UNKNOWN},
        },
        "dependence_group_id": UNKNOWN,
        "dependence_fields": {
            "harness": harness,
            "group_anchor": UNKNOWN,
            "session_container_id": UNKNOWN,
            "parent_reference": UNKNOWN,
            "entry_point": UNKNOWN,
            "session_kind": UNKNOWN,
            "working_directory_category": "unknown",
            "prompt_hash": UNKNOWN,
            "input_hash": UNKNOWN,
            "code_version": UNKNOWN,
            "configuration_version": UNKNOWN,
            "source_dataset": UNKNOWN,
            "injected_context_fingerprint": UNKNOWN,
        },
        "in_window_canonical_bytes": 0,
        "in_window_event_count": 0,
        "first_in_window_timestamp": UNKNOWN,
        "last_in_window_timestamp": UNKNOWN,
        "content_sha256": UNKNOWN,
        "terminal_status": "failed",
        "reason": "source_unavailable",
        "in_window": False,
    }


def _populate_provenance(record: dict[str, Any], metadata: dict[str, Any], counters: Counter[str]) -> None:
    parent_references = metadata["parent_references"]
    entry_points = metadata["entry_points"]
    session_kinds = metadata["session_kinds"]
    cwd_values = metadata["cwd_values"]
    sidechain_values = metadata["sidechain_values"]
    assert isinstance(parent_references, set)
    assert isinstance(entry_points, set)
    assert isinstance(session_kinds, set)
    assert isinstance(cwd_values, set)
    assert isinstance(sidechain_values, set)
    harness = str(record["harness"])
    supplemental_ids = metadata["supplemental_session_ids"]
    assert isinstance(supplemental_ids, set)
    if harness == "codex":
        primary = metadata["codex_primary_logical_session_id"]
        fallback_ids = metadata["codex_fallback_session_ids"]
        container = metadata["codex_primary_session_container_id"]
        assert isinstance(fallback_ids, set)
        if primary is not None:
            logical_session_id = str(primary)
        elif len(fallback_ids) == 1:
            logical_session_id = _single_value(fallback_ids)
        else:
            logical_session_id = UNKNOWN
        session_container_id = str(container) if container is not None else logical_session_id
        identity_conflict = primary is None and len(fallback_ids) > 1
    else:
        primary_ids = metadata["claude_primary_session_ids"]
        fallback_ids = metadata["claude_fallback_session_ids"]
        assert isinstance(primary_ids, set)
        assert isinstance(fallback_ids, set)
        if len(primary_ids) == 1:
            logical_session_id = _single_value(primary_ids)
            identity_conflict = False
        elif len(primary_ids) > 1:
            logical_session_id = UNKNOWN
            identity_conflict = True
        elif len(fallback_ids) == 1:
            logical_session_id = _single_value(fallback_ids)
            identity_conflict = False
        else:
            logical_session_id = UNKNOWN
            identity_conflict = len(fallback_ids) > 1
        session_container_id = logical_session_id
    if logical_session_id == UNKNOWN:
        counters["missing_logical_session_ids"] += 1
    if identity_conflict:
        counters["conflicting_logical_session_ids"] += 1
    counters["supplemental_session_ids"] += len(supplemental_ids)
    parent_reference = _single_value(parent_references)
    entry_point = _single_value(entry_points)
    session_kind = _single_value(session_kinds)
    sidechain = _single_bool(sidechain_values)
    cwd_category, cwd_provenance, cwd_rule = _working_directory_category(cwd_values)
    execution_shape, execution_provenance, execution_rule = _execution_shape(entry_point, session_kind, cwd_category)
    dependence_group_id, dependence_fields = _dependence_fields(
        harness=str(record["harness"]),
        logical_session_id=logical_session_id,
        session_container_id=session_container_id,
        parent_reference=parent_reference,
        entry_point=entry_point,
        session_kind=session_kind,
        working_directory_category=cwd_category,
    )
    record.update(
        {
            "logical_session_id": logical_session_id,
            "session_container_id": session_container_id,
            "parent_logical_session_id": parent_reference,
            "sidechain": sidechain,
            "source_kind": _source_kind(parent_reference, sidechain),
            "entry_point": entry_point,
            "session_kind": session_kind,
            "classification": {
                "execution_shape": {
                    "value": execution_shape,
                    "provenance": execution_provenance,
                    "rule": execution_rule,
                },
                "working_directory": {
                    "value": cwd_category,
                    "provenance": cwd_provenance,
                    "rule": cwd_rule,
                },
            },
            "dependence_group_id": dependence_group_id,
            "dependence_fields": dependence_fields,
        }
    )


def _scan_artifact(
    harness: str,
    path: Path,
    root: Path,
    config: CensusConfig,
) -> tuple[dict[str, Any], str | None, bool, dict[str, int]]:
    relative_path = path.relative_to(root)
    record = _base_record(harness, _artifact_id(harness, relative_path))
    descriptor, source_stat, error = _open_safe_regular(path, root)
    if error:
        record["terminal_status"] = "quarantined" if error in {
            "symlink_rejected",
            "special_file_rejected",
            "source_path_outside_root",
            "unsafe_source_owner",
            "descriptor_mismatch",
        } else "failed"
        record["reason"] = error
        return record, None, False, dict(_empty_record_counters())
    assert descriptor is not None and source_stat is not None
    counters = _empty_record_counters()
    metadata = _new_metadata()
    in_window_hash = hashlib.sha256()
    source_hash = hashlib.sha256()
    first_timestamp: datetime | None = None
    last_timestamp: datetime | None = None
    in_window_events = 0
    in_window_canonical_bytes = 0
    malformed = False
    oversized = False
    read_error: str | None = None
    source_changed_during_scan = False
    try:
        with os.fdopen(descriptor, "rb", closefd=True) as stream:
            descriptor = None
            for raw, was_oversized in _iter_bounded_lines(stream):
                counters["total_lines"] += 1
                if was_oversized:
                    counters["oversized_records"] += 1
                    oversized = True
                    continue
                assert raw is not None
                source_hash.update(raw)
                if not raw.strip():
                    counters["blank_lines"] += 1
                    continue
                try:
                    decoded = json.loads(raw)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    counters["malformed_lines"] += 1
                    malformed = True
                    continue
                if not isinstance(decoded, Mapping):
                    counters["malformed_lines"] += 1
                    malformed = True
                    continue
                counters["parsed_records"] += 1
                record_type = decoded.get("type")
                if not isinstance(record_type, str) or record_type not in _KNOWN_TYPES[harness]:
                    counters["unknown_record_types"] += 1
                if "timestamp" not in decoded:
                    counters["missing_timestamp_records"] += 1
                    continue
                timestamp = parse_timestamp(decoded.get("timestamp"))
                if timestamp is None:
                    counters["invalid_timestamp_records"] += 1
                    continue
                if timestamp >= config.cutoff:
                    _observe_post_cutoff_identity_conflict(harness, decoded, metadata, counters)
                    continue
                # Identity and provenance must be cutoff-stable too. A late
                # append may improve diagnostics, but it cannot change a
                # frozen manifest or coverage record.
                _collect_metadata(harness, decoded, metadata)
                if timestamp < config.window_start:
                    continue
                in_window_events += 1
                canonical = canonical_json(decoded).encode("utf-8") + b"\n"
                in_window_hash.update(canonical)
                in_window_canonical_bytes += len(canonical)
                first_timestamp = timestamp if first_timestamp is None or timestamp < first_timestamp else first_timestamp
                last_timestamp = timestamp if last_timestamp is None or timestamp > last_timestamp else last_timestamp
            completed_stat = os.fstat(stream.fileno())
            source_changed_during_scan = (
                (completed_stat.st_dev, completed_stat.st_ino, completed_stat.st_size, completed_stat.st_mtime_ns, completed_stat.st_ctime_ns)
                != (source_stat.st_dev, source_stat.st_ino, source_stat.st_size, source_stat.st_mtime_ns, source_stat.st_ctime_ns)
            )
    except OSError:
        read_error = "source_read_failed"
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass

    _populate_provenance(record, metadata, counters)
    record["in_window_event_count"] = in_window_events
    record["in_window_canonical_bytes"] = in_window_canonical_bytes
    record["in_window"] = in_window_events > 0
    record["first_in_window_timestamp"] = _format_timestamp(first_timestamp)
    record["last_in_window_timestamp"] = _format_timestamp(last_timestamp)
    record["content_sha256"] = in_window_hash.hexdigest() if in_window_events else UNKNOWN
    if read_error:
        record["terminal_status"] = "failed"
        record["reason"] = read_error
    elif source_changed_during_scan:
        record["terminal_status"] = "quarantined"
        record["reason"] = "source_changed_during_read"
    elif oversized:
        record["terminal_status"] = "quarantined"
        record["reason"] = "record_too_large"
    elif malformed:
        record["terminal_status"] = "quarantined"
        record["reason"] = "malformed_jsonl"
    elif in_window_events:
        record["terminal_status"] = "complete"
        record["reason"] = UNKNOWN
    else:
        record["terminal_status"] = "excluded"
        record["reason"] = "no_in_window_events"
    return record, source_hash.hexdigest(), source_changed_during_scan, {key: int(counters[key]) for key in _COUNTER_KEYS}


def _resolve_parent_artifacts(records: list[dict[str, Any]]) -> None:
    by_logical_id: dict[str, list[str]] = defaultdict(list)
    for record in records:
        logical_id = str(record["logical_session_id"])
        if logical_id != UNKNOWN:
            by_logical_id[logical_id].append(str(record["artifact_id"]))
    for record in records:
        parent = str(record["parent_logical_session_id"])
        matches = sorted(by_logical_id.get(parent, ()))
        record["parent_artifact_id"] = matches[0] if len(matches) == 1 else UNKNOWN


def _relationship_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    logical_artifacts: dict[str, list[str]] = defaultdict(list)
    source_kinds: Counter[str] = Counter()
    execution_shapes: Counter[str] = Counter()
    provenance: Counter[str] = Counter()
    sidechains: Counter[str] = Counter()
    for record in records:
        logical_id = str(record["logical_session_id"])
        if logical_id != UNKNOWN:
            logical_artifacts[logical_id].append(str(record["artifact_id"]))
        source_kinds[str(record["source_kind"])] += 1
        execution = record["classification"]["execution_shape"]
        execution_shapes[str(execution["value"])] += 1
        provenance[str(execution["provenance"])] += 1
        sidechain = record["sidechain"]
        sidechains["true" if sidechain is True else "false" if sidechain is False else UNKNOWN] += 1
    return {
        "logical_session_count": len(logical_artifacts),
        "logical_sessions_shared_by_multiple_artifacts": sum(1 for members in logical_artifacts.values() if len(members) > 1),
        "with_parent_reference": sum(1 for record in records if record["parent_logical_session_id"] != UNKNOWN),
        "resolved_parent_artifacts": sum(1 for record in records if record["parent_artifact_id"] != UNKNOWN),
        "sidechain": dict(sorted(sidechains.items())),
        "source_kinds": dict(sorted(source_kinds.items())),
        "execution_shapes": dict(sorted(execution_shapes.items())),
        "execution_shape_provenance": dict(sorted(provenance.items())),
    }


def _dependence_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    all_groups: dict[str, list[str]] = defaultdict(list)
    eligible_groups: dict[str, list[str]] = defaultdict(list)
    for record in records:
        group_id = str(record["dependence_group_id"])
        if group_id == UNKNOWN:
            continue
        all_groups[group_id].append(str(record["artifact_id"]))
        if record["terminal_status"] == "complete":
            eligible_groups[group_id].append(str(record["artifact_id"]))
    multiplicities = [len(members) for members in all_groups.values()]
    return {
        "dependence_group_count": len(all_groups),
        "eligible_dependence_group_count": len(eligible_groups),
        "groups_with_multiple_artifacts": sum(1 for members in all_groups.values() if len(members) > 1),
        "maximum_group_multiplicity": max(multiplicities, default=0),
    }


def _summary(records: list[dict[str, Any]], root_failures: Mapping[str, str]) -> dict[str, Any]:
    statuses = Counter({status: 0 for status in _TERMINAL_STATUSES})
    by_harness: dict[str, dict[str, Any]] = {}
    for harness in ("codex", "claude"):
        harness_records = [record for record in records if record["harness"] == harness]
        harness_statuses = Counter({status: 0 for status in _TERMINAL_STATUSES})
        harness_statuses.update(str(record["terminal_status"]) for record in harness_records)
        by_harness[harness] = {
            "scanned_artifacts": len(harness_records),
            "included": harness_statuses["complete"],
            "excluded": harness_statuses["excluded"],
            "quarantined": harness_statuses["quarantined"],
            "failed": harness_statuses["failed"],
            "terminal_statuses": {status: harness_statuses[status] for status in _TERMINAL_STATUSES},
        }
    statuses.update(str(record["terminal_status"]) for record in records)
    scanned = len(records)
    accounted = sum(statuses.values())
    dependence = _dependence_summary(records)
    in_window_event_count = sum(int(record["in_window_event_count"]) for record in records if record["terminal_status"] == "complete")
    return {
        "scanned_artifacts": scanned,
        "included": statuses["complete"],
        "excluded": statuses["excluded"],
        "quarantined": statuses["quarantined"],
        "failed": statuses["failed"],
        "terminal_statuses": {status: statuses[status] for status in _TERMINAL_STATUSES},
        "unaccounted_artifacts": scanned - accounted,
        "zero_unaccounted": scanned == accounted and not root_failures,
        "root_failures": dict(sorted(root_failures.items())),
        "by_harness": by_harness,
        "relationship_summary": _relationship_summary(records),
        "dependence_summary": dependence,
        "eligible_in_window_event_count": in_window_event_count,
    }


def _integer_setting(settings: Mapping[str, Any], name: str, default: int) -> int:
    value = settings.get(name, default)
    if isinstance(value, bool):
        raise ValueError(f"invalid_estimator_{name}")
    try:
        return int(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"invalid_estimator_{name}") from error


def _float_setting(settings: Mapping[str, Any], name: str, default: float) -> float:
    value = settings.get(name, default)
    if isinstance(value, bool):
        raise ValueError(f"invalid_estimator_{name}")
    try:
        return float(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"invalid_estimator_{name}") from error


def _estimate_from_summary(summary: Mapping[str, Any], settings: Mapping[str, Any]) -> dict[str, Any]:
    dependence = summary["dependence_summary"]
    estimate = estimate_tiered_stage(
        artifact_count=int(summary["included"]),
        dependence_group_count=int(dependence["eligible_dependence_group_count"]),
        in_window_event_count=int(summary["eligible_in_window_event_count"]),
        full_extract_fraction=_float_setting(settings, "full_extract_fraction", 0.10),
        mixed_sample_fraction=_float_setting(settings, "mixed_sample_fraction", 0.05),
        classification_packet_bytes=_integer_setting(settings, "classification_packet_bytes", 1_024),
        full_packet_bytes=_integer_setting(settings, "full_packet_bytes", 10_240),
        max_packet_bytes=_integer_setting(settings, "max_packet_bytes", 100 * 1024),
        max_packet_tokens=_integer_setting(settings, "max_packet_tokens", 32_000),
        bytes_per_token=_integer_setting(settings, "bytes_per_token", 3),
        prompt_tokens=_integer_setting(settings, "prompt_tokens", 800),
        output_tokens_per_call=_integer_setting(settings, "output_tokens_per_call", 5_000),
        concurrency=_integer_setting(settings, "concurrency", 2),
        per_call_minutes=_integer_setting(settings, "per_call_minutes", 20),
    )
    envelope_status = "within_full_poc_envelope"
    exceeded_dimension = UNKNOWN
    try:
        enforce_r25(estimate.resource_estimate, FULL_POC_LIMITS)
    except ResourceBudgetExceeded as error:
        envelope_status = "full_poc_envelope_exceeded"
        exceeded_dimension = error.dimension
    resource = estimate.resource_estimate
    return {
        "artifact_count": estimate.artifact_count,
        "dependence_group_count": estimate.dependence_group_count,
        "in_window_event_count": estimate.in_window_event_count,
        "classification_representative_count": estimate.classification_representative_count,
        "full_extract_group_count": estimate.full_extract_group_count,
        "mixed_sample_group_count": estimate.mixed_sample_group_count,
        "full_stage_group_count": estimate.full_stage_group_count,
        "classification_groups_per_call": estimate.classification_groups_per_call,
        "full_extract_groups_per_call": estimate.full_extract_groups_per_call,
        "classification_calls": estimate.classification_calls,
        "full_extract_calls": estimate.full_extract_calls,
        "estimated_input_tokens": resource.input_tokens,
        "estimated_output_tokens": resource.output_tokens,
        "estimated_calls": resource.calls,
        "estimated_wall_minutes": resource.wall_minutes,
        "estimated_monetary_cost_usd": resource.monetary_cost_usd,
        "envelope_status": envelope_status,
        "exceeded_dimension": exceeded_dimension,
    }


def scan_corpus(config: CensusConfig) -> CensusRun:
    """Census every JSONL artifact without writing source data or logs."""

    if config.window_start.tzinfo is None or config.cutoff.tzinfo is None or config.window_start >= config.cutoff:
        raise ValueError("invalid_census_window")
    records: list[dict[str, Any]] = []
    source_byte_sha256: dict[str, str] = {}
    read_only_descriptors = 0
    source_changes_observed_during_scan = 0
    observation_counters = _empty_record_counters()
    root_failures: dict[str, str] = {}
    for harness in ("codex", "claude"):
        configured_root = config.source_roots.get(harness)
        if not isinstance(configured_root, Path):
            root_failures[harness] = "source_root_missing"
            continue
        try:
            root = _validate_root(configured_root.expanduser())
        except (OSError, ValueError) as error:
            root_failures[harness] = str(error) if str(error) in {
                "root_symlink_rejected",
                "root_not_directory",
                "root_unsafe_owner",
            } else "source_root_unavailable"
            continue
        paths, discovery_failures = _discover_jsonl_files(root)
        if discovery_failures:
            root_failures[harness] = "source_discovery_failed"
        for path in paths:
            record, source_hash, source_changed, counters = _scan_artifact(harness, path, root, config)
            records.append(record)
            observation_counters.update(counters)
            if source_hash:
                source_byte_sha256[str(record["artifact_id"])] = source_hash
                read_only_descriptors += 1
            if source_changed:
                source_changes_observed_during_scan += 1
    _resolve_parent_artifacts(records)
    records.sort(key=lambda record: (str(record["harness"]), str(record["artifact_id"])))
    summary = _summary(records, root_failures)
    resource_estimate = _estimate_from_summary(summary, config.estimator)
    manifest_document = {
        "schema_version": "session-manifest/v1",
        "window": {"start": _format_timestamp(config.window_start), "cutoff": _format_timestamp(config.cutoff)},
        "records": records,
        "summary": summary,
    }
    coverage_records = [
        {
            "artifact_id": record["artifact_id"],
            "harness": record["harness"],
            "terminal_status": record["terminal_status"],
            "reason": record["reason"],
            "in_window": record["in_window"],
            "manifest_content_sha256": record["content_sha256"],
        }
        for record in records
    ]
    coverage_document = {
        "schema_version": "coverage-record/v1",
        "window": {"start": _format_timestamp(config.window_start), "cutoff": _format_timestamp(config.cutoff)},
        "records": coverage_records,
        "summary": summary,
    }
    manifest_sha256 = _sha256_bytes(canonical_json(manifest_document).encode("utf-8"))
    coverage_sha256 = _sha256_bytes(canonical_json(coverage_document).encode("utf-8"))
    receipt_document = {
        "schema_version": "census-receipt/v1",
        "window": manifest_document["window"],
        "manifest_sha256": manifest_sha256,
        "coverage_sha256": coverage_sha256,
        "summary": summary,
        "observation_counters": {key: int(observation_counters[key]) for key in _COUNTER_KEYS},
        "resource_estimate": resource_estimate,
        "source_integrity": {
            "read_only_descriptors": read_only_descriptors,
            "source_changes_observed_during_scan": source_changes_observed_during_scan,
            "read_only_input_preserved": source_changes_observed_during_scan == 0,
        },
        "output_files": ["manifest.json", "coverage.json", "receipt.json"],
    }
    return CensusRun(
        manifest_document=manifest_document,
        coverage_document=coverage_document,
        receipt_document=receipt_document,
        summary=summary,
        manifest_sha256=manifest_sha256,
        coverage_sha256=coverage_sha256,
        source_byte_sha256=dict(sorted(source_byte_sha256.items())),
        source_integrity={
            "read_only_descriptors": read_only_descriptors,
            "source_changes_observed_during_scan": source_changes_observed_during_scan,
            "read_only_input_preserved": source_changes_observed_during_scan == 0,
        },
        observation_counters={key: int(observation_counters[key]) for key in _COUNTER_KEYS},
    )


def _validate_schema(value: Any, schema: Mapping[str, Any], location: str) -> list[str]:
    errors: list[str] = []
    expected = schema.get("type")
    if expected is not None:
        expected_types = expected if isinstance(expected, list) else [expected]
        checks = {
            "object": lambda item: isinstance(item, Mapping),
            "array": lambda item: isinstance(item, list),
            "string": lambda item: isinstance(item, str),
            "integer": lambda item: isinstance(item, int) and not isinstance(item, bool),
            "boolean": lambda item: isinstance(item, bool),
            "number": lambda item: isinstance(item, (int, float)) and not isinstance(item, bool),
        }
        if not any(checks.get(name, lambda _item: False)(value) for name in expected_types):
            return [f"{location}:expected_{'|'.join(str(name) for name in expected_types)}"]
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{location}:enum")
    if isinstance(value, str) and "pattern" in schema and re.fullmatch(str(schema["pattern"]), value) is None:
        errors.append(f"{location}:pattern")
    if isinstance(value, int) and "minimum" in schema and value < int(schema["minimum"]):
        errors.append(f"{location}:minimum")
    if isinstance(value, Mapping):
        required = schema.get("required", [])
        for key in required:
            if key not in value:
                errors.append(f"{location}.{key}:required")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            for key in value:
                if key not in properties:
                    errors.append(f"{location}.{key}:unexpected")
        for key, child_schema in properties.items():
            if key in value and isinstance(child_schema, Mapping):
                errors.extend(_validate_schema(value[key], child_schema, f"{location}.{key}"))
    if isinstance(value, list):
        if "minItems" in schema and len(value) < int(schema["minItems"]):
            errors.append(f"{location}:minItems")
        item_schema = schema.get("items")
        if isinstance(item_schema, Mapping):
            for index, item in enumerate(value):
                errors.extend(_validate_schema(item, item_schema, f"{location}[{index}]"))
    return errors


def validate_schema_document(document: Mapping[str, Any], schema_path: Path) -> tuple[str, ...]:
    """Validate U1 schemas with the standard library only."""

    with Path(schema_path).open("r", encoding="utf-8") as stream:
        schema = json.load(stream)
    if not isinstance(schema, Mapping):
        return ("$:schema_not_object",)
    return tuple(_validate_schema(document, schema, "$"))


def _ensure_private_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    path_stat = os.lstat(path)
    if stat.S_ISLNK(path_stat.st_mode) or not stat.S_ISDIR(path_stat.st_mode):
        raise ValueError("private_output_not_directory")
    if path_stat.st_uid != os.getuid():
        raise PermissionError("private_output_unsafe_owner")
    os.chmod(path, 0o700)


def _private_root(output_root: Path, repository_root: Path, require_ignored: bool) -> Path:
    candidate = output_root.expanduser()
    if not candidate.is_absolute():
        candidate = repository_root / candidate
    resolved_repository = repository_root.resolve(strict=True)
    resolved_candidate = candidate.resolve(strict=False)
    if require_ignored:
        if not resolved_candidate.is_relative_to(resolved_repository):
            raise ValueError("private_output_outside_repository")
        relative = resolved_candidate.relative_to(resolved_repository).as_posix()
        ignored = subprocess.run(
            ["git", "-C", str(resolved_repository), "check-ignore", "--quiet", "--", relative],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if ignored.returncode != 0:
            raise ValueError("private_output_not_gitignored")
    _ensure_private_directory(resolved_candidate)
    return resolved_candidate


def write_census_private(
    result: CensusRun,
    output_root: Path,
    *,
    repository_root: Path = _REPOSITORY_ROOT,
    require_ignored: bool = True,
) -> CensusOutput:
    """Write only canonical metadata to a private, ignored 0700/0600 root."""

    root = _private_root(Path(output_root), Path(repository_root), require_ignored)
    cutoff = str(result.manifest_document["window"]["cutoff"]).replace(":", "").replace("-", "")
    run_directory = root / f"fixed-{cutoff}"
    _ensure_private_directory(run_directory)
    manifest_path = run_directory / "manifest.json"
    coverage_path = run_directory / "coverage.json"
    receipt_path = run_directory / "receipt.json"
    secure_write_text(manifest_path, canonical_json(result.manifest_document) + "\n")
    secure_write_text(coverage_path, canonical_json(result.coverage_document) + "\n")
    receipt_sha256 = _sha256_bytes(canonical_json(result.receipt_document).encode("utf-8"))
    receipt_wrapper = {"receipt_sha256": receipt_sha256, "receipt": result.receipt_document}
    secure_write_text(receipt_path, canonical_json(receipt_wrapper) + "\n")
    return CensusOutput(
        root=root,
        run_directory=run_directory,
        files=(manifest_path, coverage_path, receipt_path),
        receipt_path=receipt_path,
        receipt_sha256=receipt_sha256,
    )


def load_census_config(path: Path) -> tuple[CensusConfig, Path]:
    """Load an explicit local config; source locations never enter outputs."""

    with Path(path).open("r", encoding="utf-8") as stream:
        payload = json.load(stream)
    if not isinstance(payload, Mapping):
        raise ValueError("census_config_not_object")
    roots = payload.get("source_roots")
    if not isinstance(roots, Mapping):
        raise ValueError("census_config_source_roots_missing")
    source_roots: dict[str, Path] = {}
    for harness in ("codex", "claude"):
        value = roots.get(harness)
        if not isinstance(value, str) or not value:
            raise ValueError("census_config_source_root_missing")
        source_roots[harness] = Path(value).expanduser()
    start = parse_timestamp(payload.get("window_start", WINDOW_START_TEXT))
    cutoff = parse_timestamp(payload.get("window_cutoff", WINDOW_CUTOFF_TEXT))
    if start is None or cutoff is None:
        raise ValueError("census_config_invalid_window")
    estimator = payload.get("estimator", {})
    if not isinstance(estimator, Mapping):
        raise ValueError("census_config_invalid_estimator")
    output_root = payload.get("output_root")
    if not isinstance(output_root, str) or not output_root:
        raise ValueError("census_config_output_root_missing")
    return CensusConfig(source_roots=source_roots, window_start=start, cutoff=cutoff, estimator=estimator), Path(output_root).expanduser()
