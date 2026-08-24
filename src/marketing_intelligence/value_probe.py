"""Bounded, provider-affine U8 value probe for Claude root transcripts.

The module never copies a raw source transcript into the repository. It reads
selected sources through no-follow descriptors, builds redacted packets in
memory, sends only those packets to the matching first-party provider, and
writes a private machine-readable receipt.
"""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import time
from typing import Any, Callable, Iterable, Mapping, Sequence

from .estimate import R25_LIMITS, ResourceBudgetExceeded, ResourceEstimate, enforce_r25, estimate_probe_resources
from .redact import RedactionStatus, redact_records, redact_text, scan_for_unsafe_content, secure_write_text


_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_CONFIG_ROOT = _REPOSITORY_ROOT / "config"
_PROMPT_PATH = _REPOSITORY_ROOT / "prompts" / "value-probe.md"
_SOURCE_ROOT = Path.home() / ".claude" / "projects"
_WINDOW_START = "2026-08-16T20:00:00Z"
_WINDOW_CUTOFF = "2026-08-24T14:57:36Z"
_MAX_EVENTS_PER_ARTIFACT = 16
_MAX_CHARS_PER_EVENT = 2_400


# This is a predeclared metadata-only selection, not a corpus census. Session
# IDs and their strata are safe identifiers; source paths never enter a packet
# or receipt.
_FIXED_CLAUDE_SAMPLE: tuple[tuple[str, str], ...] = (
    ("ef4b85b8-5989-4257-bfe3-08c956f30892", "competitive-ad-library"),
    ("40e215b0-a78d-4b5d-88a8-d189a4ed174b", "reddit-hpp"),
    ("a7ebf60e-9360-4db8-8dcb-c818ee44f78e", "google-ads"),
    ("f52fdbe7-18b2-4b80-a616-7c7aedb5256f", "general-documents"),
    ("1dd762db-f0a3-4707-a997-45510e8a9587", "general-documents"),
    ("7e04de09-9795-4422-a525-2d33d98efc16", "general-documents"),
    ("86b5bf68-8b73-4b9b-8def-1719070ebfd9", "general-documents"),
    ("0780e964-aba4-45ed-8e05-dbb494761022", "general-documents"),
)

_MARKETING_TERMS = {
    "ad",
    "advertising",
    "audience",
    "brand",
    "budget",
    "buyer",
    "campaign",
    "cpc",
    "crm",
    "creative",
    "content",
    "conversion",
    "ctr",
    "customer",
    "demand",
    "keyword",
    "lead",
    "marketing",
    "media",
    "paid",
    "reddit",
    "search",
    "seo",
    "serp",
    "social",
    "traffic",
}
_DECISION_TERMS = {"change", "choose", "defer", "increase", "launch", "pause", "prioritize", "reduce", "shift", "test", "use"}
_HARNESS_TERMS = {
    "agent",
    "checkpoint",
    "fixture",
    "harness",
    "model",
    "packet",
    "pipeline",
    "prompt",
    "provider",
    "retry",
    "schema",
    "test",
    "token",
    "transcript",
}
_TOKEN_SYNONYMS = {
    "adding": "add",
    "adds": "add",
    "audiences": "audience",
    "campaigns": "campaign",
    "cross": "verify",
    "reference": "verify",
    "checks": "verify",
    "checking": "verify",
    "check": "verify",
    "conversions": "conversion",
    "keywords": "keyword",
    "negative": "negative",
    "negatives": "negative",
    "targeting": "target",
    "targets": "target",
    "targeted": "target",
    "using": "use",
    "used": "use",
}
_STOP_TOKENS = {
    "a",
    "an",
    "and",
    "are",
    "as",
    "at",
    "by",
    "for",
    "from",
    "in",
    "is",
    "of",
    "on",
    "or",
    "s",
    "the",
    "to",
    "with",
}
_EVIDENCE_POINTER = re.compile(r"^session://(?P<harness>[a-z0-9_-]+)/(?P<artifact>[a-z0-9_-]+)@(?P<version>[a-f0-9]+|[A-Za-z0-9._-]+)#event=(?P<event>[A-Za-z0-9._-]+)$")


class ProbeStatus(str, Enum):
    PASSED = "passed"
    REDUCED_SCOPE = "reduced_scope"
    BLOCKED = "blocked"


class EvidenceStrength(str, Enum):
    """The deterministic support class of one normalized evidence event."""

    OBSERVED = "observed"
    ASSERTED = "asserted"
    REASONED = "reasoned"


@dataclass(frozen=True)
class ArtifactMetadata:
    artifact_id: str
    harness: str
    source_kind: str
    source_path: str
    stratum: str
    in_window_events: int
    marketing_events: int
    byte_size: int
    event_ids: tuple[str, ...]
    content_sha256: str
    parent_artifact_id: str | None


@dataclass(frozen=True)
class SelectionManifest:
    artifacts: tuple[ArtifactMetadata, ...]
    selection_reason: str
    claims_corpus_coverage: bool
    sha256: str


@dataclass(frozen=True)
class NoveltyBaseline:
    items: tuple[tuple[str, str], ...]
    sha256: str


@dataclass(frozen=True)
class CandidateDecision:
    candidate_id: str
    accepted: bool
    reason: str
    candidate: Mapping[str, Any]


@dataclass(frozen=True)
class ProviderDispatchResult:
    candidates: tuple[Mapping[str, Any], ...]
    input_tokens: int | str = "?"
    output_tokens: int | str = "?"
    calls: int = 1
    wall_minutes: float | str = "?"
    model: str = "?"
    monetary_cost_usd: str = "?"


@dataclass(frozen=True)
class ProbeReceipt:
    status: ProbeStatus
    reason: str
    qualifying_learnings: int
    sample_ids: tuple[str, ...]
    sample_sha256: str
    baseline_sha256: str
    provider_release: Mapping[str, Any]
    estimated_resources: ResourceEstimate | None
    actual_resources: Mapping[str, Any]
    candidate_decisions: tuple[CandidateDecision, ...]
    quarantined_artifacts: tuple[str, ...] = ()
    resource_dimension: str | None = None
    source_files_used: tuple[str, ...] = ()
    safety: Mapping[str, Any] | None = None
    provider_error: str | None = None
    validation_summary: Mapping[str, Any] | None = None


@dataclass(frozen=True)
class PreparedRealProbe:
    """Private in-memory state that has passed deterministic preflight."""

    baseline: NoveltyBaseline
    prompt_text: str
    selection: SelectionManifest
    packets: tuple[Mapping[str, Any], ...]
    sources: tuple[Mapping[str, Any], ...]
    provider_release: Mapping[str, Any]


class ProviderDispatchError(RuntimeError):
    """A provider failure represented without returning provider output bodies."""


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_text(value: str) -> str:
    return _sha256_bytes(value.encode("utf-8"))


def _semantic_tokens(text: str) -> set[str]:
    tokens: set[str] = set()
    for raw in re.findall(r"[a-z0-9]+", text.casefold()):
        if raw in _STOP_TOKENS:
            continue
        token = _TOKEN_SYNONYMS.get(raw, raw)
        if len(token) > 2:
            tokens.add(token)
    return tokens


def freeze_novelty_baseline(items: Mapping[str, str]) -> NoveltyBaseline:
    """Freeze baseline identity before candidate evaluation."""

    normalized_items = tuple(sorted((str(key), str(value).strip()) for key, value in items.items()))
    return NoveltyBaseline(items=normalized_items, sha256=_sha256_text(_canonical_json(normalized_items)))


def is_novel_against_baseline(content: str, baseline: NoveltyBaseline) -> tuple[bool, str]:
    """Reject exact and high-overlap semantic restatements of the baseline."""

    normalized = " ".join(sorted(_semantic_tokens(content)))
    candidate_tokens = _semantic_tokens(content)
    for baseline_id, baseline_content in baseline.items:
        baseline_tokens = _semantic_tokens(baseline_content)
        if normalized and normalized == " ".join(sorted(baseline_tokens)):
            return False, f"exact_baseline_match:{baseline_id}"
        if not candidate_tokens or not baseline_tokens:
            continue
        intersection = len(candidate_tokens & baseline_tokens)
        union = len(candidate_tokens | baseline_tokens)
        similarity = intersection / union
        if intersection >= 4 and similarity >= 0.60:
            return False, f"semantic_baseline_match:{baseline_id}"
    return True, "novel"


def build_evidence_pointer(artifact: ArtifactMetadata, event_id: str, version: str) -> str:
    """Build a versioned source URI without a local source path."""

    return f"session://{artifact.harness}/{artifact.artifact_id}@{version}#event={event_id}"


def select_root_artifacts(artifacts: Iterable[ArtifactMetadata], minimum: int = 8, maximum: int = 8) -> SelectionManifest:
    """Select a deterministic root-only high-density sample, never a census."""

    eligible = [artifact for artifact in artifacts if artifact.source_kind == "root" and artifact.parent_artifact_id is None]
    eligible.sort(key=lambda artifact: (-artifact.marketing_events, -artifact.in_window_events, artifact.artifact_id))
    selected = tuple(eligible[:maximum])
    if len(selected) < minimum:
        raise ValueError(f"value probe requires {minimum}-{maximum} root artifacts")
    manifest_payload = [
        {
            "artifact_id": artifact.artifact_id,
            "content_sha256": artifact.content_sha256,
            "stratum": artifact.stratum,
            "marketing_events": artifact.marketing_events,
        }
        for artifact in selected
    ]
    return SelectionManifest(
        artifacts=selected,
        selection_reason="verified_high_density_root_strata",
        claims_corpus_coverage=False,
        sha256=_sha256_text(_canonical_json(manifest_payload)),
    )


def _candidate_text(candidate: Mapping[str, Any]) -> str:
    return " ".join(str(candidate.get(key, "")) for key in ("title", "content", "decision", "topic", "type"))


def _marketing_candidate_text(candidate: Mapping[str, Any]) -> str:
    """Use the substantive fields; topic names cannot turn harness work into marketing."""

    return " ".join(str(candidate.get(key, "")) for key in ("content", "decision"))


def _has_marketing_content(candidate: Mapping[str, Any]) -> bool:
    tokens = _semantic_tokens(_marketing_candidate_text(candidate))
    return bool(tokens & _MARKETING_TERMS)


def _is_harness_only(candidate: Mapping[str, Any]) -> bool:
    tokens = _semantic_tokens(_marketing_candidate_text(candidate))
    harness = tokens & _HARNESS_TERMS
    marketing = tokens & _MARKETING_TERMS
    return bool(harness) and not marketing


def validate_candidate(
    candidate: Mapping[str, Any],
    baseline: NoveltyBaseline,
    *,
    evidence_strength_by_pointer: Mapping[str, str] | None = None,
    evidence_resolver: Callable[[str], bool] | None = None,
) -> CandidateDecision:
    """Apply the R23 candidate gate without treating provider prose as truth."""

    candidate_id = str(candidate.get("id", "?"))
    required = ("id", "title", "content", "label", "topic", "type", "decision", "evidence")
    if any(not candidate.get(field) for field in required):
        return CandidateDecision(candidate_id, False, "missing_required_field", candidate)
    if candidate.get("label") not in {"[DATA]", "[LOGIC]", "[HYPOTHESIS]"}:
        return CandidateDecision(candidate_id, False, "invalid_claim_label", candidate)
    evidence = candidate.get("evidence")
    if not isinstance(evidence, list) or not evidence or any(not isinstance(pointer, str) or not _EVIDENCE_POINTER.match(pointer) for pointer in evidence):
        return CandidateDecision(candidate_id, False, "invalid_evidence", candidate)
    if evidence_resolver is not None and any(not evidence_resolver(pointer) for pointer in evidence):
        return CandidateDecision(candidate_id, False, "unresolvable_evidence", candidate)
    if _is_harness_only(candidate):
        return CandidateDecision(candidate_id, False, "harness_only", candidate)
    if not _has_marketing_content(candidate):
        return CandidateDecision(candidate_id, False, "not_marketing", candidate)
    if not str(candidate.get("decision", "")).strip():
        return CandidateDecision(candidate_id, False, "no_marketing_decision", candidate)
    novel, novelty_reason = is_novel_against_baseline(str(candidate["content"]), baseline)
    if not novel:
        return CandidateDecision(candidate_id, False, novelty_reason, candidate)
    if candidate["label"] == "[DATA]":
        if evidence_strength_by_pointer is None:
            return CandidateDecision(candidate_id, False, "data_evidence_strength_unavailable", candidate)
        if not any(evidence_strength_by_pointer.get(pointer) == EvidenceStrength.OBSERVED.value for pointer in evidence):
            return CandidateDecision(candidate_id, False, "data_evidence_not_observed", candidate)
    return CandidateDecision(candidate_id, True, "accepted", candidate)


def _release_is_provider_affine(provider_release: Mapping[str, Any]) -> bool:
    provider = str(provider_release.get("provider", "")).casefold()
    harness = str(provider_release.get("harness", "")).casefold()
    account = str(provider_release.get("account", "")).casefold()
    expected = {
        "claude": ("anthropic", "authenticated-claude"),
        "codex": ("openai", "authenticated-codex"),
    }
    return harness in expected and (provider, account) == expected[harness]


def _sample_pointer_is_resolvable(pointer: str, sample: Sequence[ArtifactMetadata]) -> bool:
    match = _EVIDENCE_POINTER.match(pointer)
    if not match:
        return False
    for artifact in sample:
        if artifact.harness == match.group("harness") and artifact.artifact_id == match.group("artifact"):
            return match.group("event") in artifact.event_ids
    return False


def _packet_evidence_strength_index(
    packets: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, str], dict[str, int]]:
    """Index only valid normalized packet events; malformed events never support DATA."""

    index: dict[str, str] = {}
    distribution = {strength.value: 0 for strength in EvidenceStrength}
    distribution["unknown"] = 0
    for packet in packets:
        events = packet.get("events")
        if not isinstance(events, list):
            if events is not None:
                distribution["unknown"] += 1
            continue
        for event in events:
            if not isinstance(event, Mapping):
                distribution["unknown"] += 1
                continue
            pointer = event.get("evidence")
            strength = event.get("evidence_strength")
            if (
                not isinstance(pointer, str)
                or not _EVIDENCE_POINTER.match(pointer)
                or not isinstance(strength, str)
                or strength not in distribution
                or strength == "unknown"
            ):
                distribution["unknown"] += 1
                continue
            distribution[strength] += 1
            prior = index.get(pointer)
            index[pointer] = strength if prior in {None, strength} else "unknown"
    return index, distribution


def _validation_summary(
    decisions: Sequence[CandidateDecision],
    evidence_strength_distribution: Mapping[str, int],
) -> Mapping[str, Mapping[str, int]]:
    labels: Counter[str] = Counter()
    accepted_labels: Counter[str] = Counter()
    rejection_reasons: Counter[str] = Counter()
    for decision in decisions:
        label = str(decision.candidate.get("label", "unknown"))
        labels[label] += 1
        if decision.accepted:
            accepted_labels[label] += 1
        else:
            rejection_reasons[decision.reason] += 1
    for label in ("[DATA]", "[LOGIC]", "[HYPOTHESIS]"):
        labels.setdefault(label, 0)
        accepted_labels.setdefault(label, 0)
    return {
        "claim_labels": dict(sorted(labels.items())),
        "accepted_claim_labels": dict(sorted(accepted_labels.items())),
        "rejection_reasons": dict(sorted(rejection_reasons.items())),
        "evidence_strength_distribution": dict(sorted(evidence_strength_distribution.items())),
    }


def _empty_actual_resources() -> dict[str, Any]:
    return {"input_tokens": "?", "output_tokens": "?", "calls": 0, "wall_minutes": "?", "monetary_cost_usd": "?"}


def _estimate_from_packets(packets: Sequence[Mapping[str, Any]], provider_release: Mapping[str, Any]) -> ResourceEstimate:
    call_count = int(provider_release.get("planned_calls", 1))
    return estimate_probe_resources(
        packet_bytes=tuple(int(packet.get("bytes", 0)) for packet in packets),
        prompt_tokens=int(provider_release.get("prompt_tokens", 800)),
        output_tokens_per_call=int(provider_release.get("output_tokens_per_call", 5_000)),
        calls=call_count,
        concurrency=int(provider_release.get("concurrency", 1)),
        per_call_minutes=int(provider_release.get("per_call_minutes", 20)),
    )


def run_value_probe(
    artifacts: Sequence[ArtifactMetadata],
    *,
    baseline: NoveltyBaseline,
    redacted_packets: Sequence[Mapping[str, Any]],
    dispatch: Callable[[Sequence[Mapping[str, Any]]], Sequence[Mapping[str, Any]] | ProviderDispatchResult],
    provider_release: Mapping[str, Any],
) -> ProbeReceipt:
    """Run a pre-redacted sample through R23, R24, and R25 gates.

    This generic function accepts a dispatch seam for tests. ``run_real_probe``
    supplies the only real dispatcher: a first-party Claude CLI invocation for
    Claude transcript packets.
    """

    sample = tuple(artifacts)
    sample_ids = tuple(artifact.artifact_id for artifact in sample)
    sample_sha256 = _sha256_text(_canonical_json([(artifact.artifact_id, artifact.content_sha256) for artifact in sample]))
    evidence_strength_by_pointer, evidence_strength_distribution = _packet_evidence_strength_index(redacted_packets)
    empty_validation_summary = _validation_summary((), evidence_strength_distribution)
    if not 8 <= len(sample) <= 12:
        return ProbeReceipt(
            ProbeStatus.BLOCKED,
            "invalid_sample_size",
            0,
            sample_ids,
            sample_sha256,
            baseline.sha256,
            provider_release,
            None,
            _empty_actual_resources(),
            (),
            validation_summary=empty_validation_summary,
        )
    if not _release_is_provider_affine(provider_release):
        return ProbeReceipt(
            ProbeStatus.BLOCKED,
            "provider_affinity_mismatch",
            0,
            sample_ids,
            sample_sha256,
            baseline.sha256,
            provider_release,
            None,
            _empty_actual_resources(),
            (),
            validation_summary=empty_validation_summary,
        )

    quarantined = tuple(sorted({str(packet.get("artifact_id", "?")) for packet in redacted_packets if str(packet.get("status", "")).casefold() == "quarantined"}))
    if quarantined:
        return ProbeReceipt(
            ProbeStatus.REDUCED_SCOPE,
            "redaction_quarantine",
            0,
            sample_ids,
            sample_sha256,
            baseline.sha256,
            provider_release,
            None,
            _empty_actual_resources(),
            (),
            quarantined_artifacts=quarantined,
            validation_summary=empty_validation_summary,
        )

    try:
        estimate = _estimate_from_packets(redacted_packets, provider_release)
        enforce_r25(estimate)
    except ResourceBudgetExceeded as error:
        return ProbeReceipt(
            ProbeStatus.REDUCED_SCOPE,
            "resource_envelope_exceeded",
            0,
            sample_ids,
            sample_sha256,
            baseline.sha256,
            provider_release,
            _estimate_from_packets(redacted_packets, provider_release),
            _empty_actual_resources(),
            (),
            resource_dimension=error.dimension,
            validation_summary=empty_validation_summary,
        )

    try:
        dispatched = dispatch(redacted_packets)
    except ProviderDispatchError as error:
        return ProbeReceipt(
            ProbeStatus.BLOCKED,
            "provider_call_failed",
            0,
            sample_ids,
            sample_sha256,
            baseline.sha256,
            provider_release,
            estimate,
            _empty_actual_resources(),
            (),
            provider_error=str(error),
            validation_summary=empty_validation_summary,
        )

    if isinstance(dispatched, ProviderDispatchResult):
        provider_result = dispatched
    else:
        provider_result = ProviderDispatchResult(candidates=tuple(dispatched))
    actual_resources = {
        "input_tokens": provider_result.input_tokens,
        "output_tokens": provider_result.output_tokens,
        "calls": provider_result.calls,
        "wall_minutes": provider_result.wall_minutes,
        "monetary_cost_usd": provider_result.monetary_cost_usd,
    }

    decisions: list[CandidateDecision] = []
    for candidate in provider_result.candidates:
        if not isinstance(candidate, Mapping):
            decisions.append(CandidateDecision("?", False, "invalid_candidate_shape", {}))
            continue
        serialized_candidate = _canonical_json(candidate)
        if scan_for_unsafe_content(serialized_candidate):
            decisions.append(CandidateDecision(str(candidate.get("id", "?")), False, "unsafe_candidate", candidate))
            continue
        decision = validate_candidate(
            candidate,
            baseline,
            evidence_strength_by_pointer=evidence_strength_by_pointer,
            evidence_resolver=lambda pointer: (
                pointer in evidence_strength_by_pointer
                and _sample_pointer_is_resolvable(pointer, sample)
            ),
        )
        decisions.append(decision)

    qualifying = sum(1 for decision in decisions if decision.accepted)
    status = ProbeStatus.PASSED if qualifying >= 8 else ProbeStatus.REDUCED_SCOPE
    reason = "r23_passed" if status is ProbeStatus.PASSED else "r23_threshold_not_met"
    return ProbeReceipt(
        status,
        reason,
        qualifying,
        sample_ids,
        sample_sha256,
        baseline.sha256,
        provider_release,
        estimate,
        actual_resources,
        tuple(decisions),
        validation_summary=_validation_summary(decisions, evidence_strength_distribution),
    )


def _jsonable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Path):
        return str(value)
    if hasattr(value, "__dataclass_fields__"):
        return {key: _jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


def write_probe_receipt(path: Path, receipt: ProbeReceipt) -> Mapping[str, Any]:
    """Write a private, machine-readable receipt and return safe identity data."""

    payload = _jsonable(receipt)
    canonical = _canonical_json(payload)
    receipt_hash = _sha256_text(canonical)
    persisted = {"receipt_sha256": receipt_hash, "receipt": payload}
    secure_write_text(path, _canonical_json(persisted) + "\n")
    return {"receipt_sha256": receipt_hash, "path": str(path)}


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _tool_result_text(value: Any) -> str:
    """Extract only text-form tool output from a verified tool-result block."""

    if isinstance(value, str):
        return value
    if not isinstance(value, list):
        return ""
    chunks: list[str] = []
    for block in value:
        if not isinstance(block, Mapping) or block.get("type") != "text":
            continue
        text = block.get("text")
        if isinstance(text, str):
            chunks.append(text)
    return "\n".join(chunks)


def _source_event_text(record: Mapping[str, Any]) -> str:
    message = record.get("message")
    if not isinstance(message, Mapping):
        return ""
    content = message.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        chunks: list[str] = []
        for block in content:
            if not isinstance(block, Mapping):
                continue
            if block.get("type") == "text":
                text = block.get("text")
            elif block.get("type") == "tool_result":
                text = _tool_result_text(block.get("content"))
            else:
                text = None
            if isinstance(text, str):
                chunks.append(text)
        return "\n".join(chunks)
    return ""


def _is_verified_tool_result(record: Mapping[str, Any]) -> bool:
    """Recognize the observed Claude shape without trusting prose in the event."""

    if record.get("type") != "user" or "toolUseResult" not in record:
        return False
    message = record.get("message")
    if not isinstance(message, Mapping) or message.get("role") != "user":
        return False
    content = message.get("content")
    if not isinstance(content, list) or not content:
        return False
    return all(
        isinstance(block, Mapping)
        and block.get("type") == "tool_result"
        and isinstance(block.get("tool_use_id"), str)
        and bool(block["tool_use_id"].strip())
        for block in content
    )


def _source_event_evidence_strength(record: Mapping[str, Any]) -> EvidenceStrength | None:
    """Classify source shape deterministically; unsupported records stay out."""

    if record.get("type") == "user":
        return EvidenceStrength.OBSERVED if _is_verified_tool_result(record) else EvidenceStrength.ASSERTED
    if record.get("type") == "assistant":
        return EvidenceStrength.REASONED
    return None


def _marketing_score(text: str) -> int:
    tokens = _semantic_tokens(text)
    marketing = len(tokens & _MARKETING_TERMS)
    decisions = len(tokens & _DECISION_TERMS)
    observed = sum(token in tokens for token in {"cpc", "ctr", "conversion", "budget", "campaign", "keyword", "search"})
    return marketing * 5 + decisions * 2 + observed


def _safe_open_source(path: Path, root: Path):
    resolved_root = root.resolve(strict=True)
    if path.is_symlink() or not path.resolve(strict=True).is_relative_to(resolved_root):
        raise ValueError("source_path_outside_authoritative_root")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    source_stat = os.fstat(descriptor)
    if not stat.S_ISREG(source_stat.st_mode) or source_stat.st_uid != os.getuid():
        os.close(descriptor)
        raise ValueError("unsafe_source_file")
    return descriptor, source_stat


def _find_fixed_source(source_root: Path, artifact_id: str) -> Path:
    matches = [path for path in source_root.rglob(f"{artifact_id}.jsonl") if path.is_file() and not path.is_symlink()]
    if len(matches) != 1:
        raise ValueError(f"source_resolution_failed:{artifact_id}:matches={len(matches)}")
    return matches[0]


def _build_claude_artifact(source_path: Path, source_root: Path, artifact_id: str, stratum: str, window_start: datetime, cutoff: datetime) -> tuple[ArtifactMetadata, Mapping[str, Any], Mapping[str, Any]]:
    """Build one in-memory safe packet and source-free manifest metadata."""

    descriptor, source_stat = _safe_open_source(source_path, source_root)
    all_in_window_raw: list[bytes] = []
    safe_events: list[tuple[int, int, str, str, str, str]] = []
    event_ids: list[str] = []
    all_event_ids: list[str] = []
    system_fingerprints: set[str] = set()
    injected_exclusions = 0
    redaction_count = 0
    root_valid = True
    quarantine_reason: str | None = None
    total_events = 0
    try:
        with os.fdopen(descriptor, "rb", closefd=True) as stream:
            for index, raw in enumerate(stream):
                try:
                    record = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                timestamp = _parse_timestamp(record.get("timestamp"))
                if timestamp is None or timestamp < window_start or timestamp > cutoff:
                    continue
                total_events += 1
                all_in_window_raw.append(raw)
                if record.get("isSidechain") is True:
                    root_valid = False
                event_id = "e-" + _sha256_bytes(raw)[:20]
                all_event_ids.append(event_id)
                record_type = str(record.get("type", ""))
                if record_type == "system":
                    system_text = _source_event_text(record)
                    if system_text:
                        system_fingerprints.add(_sha256_text(re.sub(r"\s+", " ", system_text).strip()))
                        injected_exclusions += 1
                    continue
                evidence_strength = _source_event_evidence_strength(record)
                if evidence_strength is None:
                    continue
                text = _source_event_text(record)
                if not text:
                    continue
                redacted = redact_records(
                    [{"role": record_type, "content": text}],
                    rules_path=_CONFIG_ROOT / "redaction-rules.json",
                    fingerprints_path=_CONFIG_ROOT / "injected-context-fingerprints.json",
                )
                injected_exclusions += redacted.excluded_injected_blocks
                system_fingerprints.update(redacted.excluded_fingerprints)
                redaction_count += redacted.redaction_count
                if redacted.status is RedactionStatus.QUARANTINED:
                    quarantine_reason = redacted.reason or "redaction_quarantine"
                    break
                if not redacted.records:
                    continue
                safe_text = redacted.records[0]["content"]
                score = _marketing_score(safe_text)
                if score > 0:
                    safe_events.append((score, index, event_id, record_type, safe_text, evidence_strength.value))
    finally:
        # fdopen closes on the normal path. An exception before fdopen would
        # leave the descriptor owned here only when it was not consumed.
        try:
            os.close(descriptor)
        except OSError:
            pass

    if not root_valid:
        raise ValueError(f"non_root_source:{artifact_id}")
    if total_events == 0:
        raise ValueError(f"fixed_window_empty:{artifact_id}")
    content_sha256 = _sha256_bytes(b"".join(all_in_window_raw))
    safe_events.sort(key=lambda item: (-item[0], item[1], item[2]))
    selected_events = safe_events[:_MAX_EVENTS_PER_ARTIFACT]
    event_payload: list[dict[str, str]] = []
    for _score, _index, event_id, role, text, evidence_strength in selected_events:
        event_ids.append(event_id)
        event_payload.append(
            {
                "evidence": f"session://claude/{artifact_id}@{content_sha256}#event={event_id}",
                "role": role,
                "evidence_strength": evidence_strength,
                "text": text[:_MAX_CHARS_PER_EVENT],
            }
        )
    metadata = ArtifactMetadata(
        artifact_id=artifact_id,
        harness="claude",
        source_kind="root",
        source_path=str(source_path),
        stratum=stratum,
        in_window_events=total_events,
        marketing_events=len(safe_events),
        byte_size=sum(len(item[4].encode("utf-8")) for item in selected_events),
        event_ids=tuple(event_ids),
        content_sha256=content_sha256,
        parent_artifact_id=None,
    )
    packet: dict[str, Any] = {
        "artifact_id": artifact_id,
        "harness": "claude",
        "stratum": stratum,
        "version": content_sha256,
        "events": event_payload,
        "injected_context": {
            "excluded_blocks": injected_exclusions,
            "fingerprints": sorted(system_fingerprints),
        },
        "redaction_count": redaction_count,
    }
    packet["bytes"] = len(_canonical_json(packet).encode("utf-8"))
    if quarantine_reason:
        packet = {
            "artifact_id": artifact_id,
            "status": "quarantined",
            "reason": quarantine_reason,
            "bytes": 0,
        }
    source_manifest = {
        "artifact_id": artifact_id,
        "source_filename": source_path.name,
        "stratum": stratum,
        "in_window_events": total_events,
        "content_sha256": content_sha256,
        "root_validated": True,
    }
    return metadata, packet, source_manifest


def _load_baseline(path: Path) -> NoveltyBaseline:
    with path.open("r", encoding="utf-8") as stream:
        payload = json.load(stream)
    items = payload.get("items")
    if not isinstance(items, Mapping):
        raise ValueError("novelty baseline has no items object")
    return freeze_novelty_baseline({str(key): str(value) for key, value in items.items()})


def _claude_schema() -> dict[str, Any]:
    candidate = {
        "type": "object",
        "additionalProperties": False,
        "required": ["id", "title", "content", "label", "topic", "type", "decision", "evidence"],
        "properties": {
            "id": {"type": "string"},
            "title": {"type": "string"},
            "content": {"type": "string"},
            "label": {"type": "string", "enum": ["[DATA]", "[LOGIC]", "[HYPOTHESIS]"]},
            "topic": {"type": "string"},
            "type": {"type": "string"},
            "decision": {"type": "string"},
            "evidence": {"type": "array", "items": {"type": "string"}, "minItems": 1},
        },
    }
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["candidates"],
        "properties": {"candidates": {"type": "array", "maxItems": 16, "items": candidate}},
    }


def _extract_structured_output(response: Mapping[str, Any]) -> Mapping[str, Any]:
    if isinstance(response.get("structured_output"), Mapping):
        return response["structured_output"]
    result = response.get("result")
    if isinstance(result, Mapping):
        return result
    if isinstance(result, str):
        try:
            decoded = json.loads(result)
        except json.JSONDecodeError as error:
            raise ProviderDispatchError("claude_output_not_json") from error
        if isinstance(decoded, Mapping):
            return decoded
    if isinstance(response.get("candidates"), list):
        return response
    raise ProviderDispatchError("claude_output_missing_structured_result")


def _safe_provider_failure(stdout: str, stderr: str, returncode: int) -> str:
    """Return an exact failure class without surfacing model or packet bodies."""

    # CLI errors may repeat prompt context. Persisting a hash makes the output
    # auditable privately without printing transcript-derived material.
    combined = stdout + "\n" + stderr
    redacted = redact_text(combined, rules_path=_CONFIG_ROOT / "redaction-rules.json")
    if redacted.status is RedactionStatus.SAFE:
        compact = re.sub(r"\s+", " ", redacted.text or "").strip()[:500]
    else:
        compact = "[quarantined-provider-output]"
    return f"claude_exit={returncode}; output_sha256={_sha256_text(combined)}; output={compact}"


def _claude_total_input_tokens(usage: Mapping[str, Any]) -> int | str:
    """Return cache-inclusive input usage, or unknown when the report is incomplete."""

    component_names = (
        "input_tokens",
        "cache_creation_input_tokens",
        "cache_read_input_tokens",
    )
    present = {name: usage.get(name) for name in component_names if name in usage}
    if not present or any(not isinstance(value, int) or value < 0 for value in present.values()):
        return "?"
    # A tiny uncached count alongside a large cached prompt is normal. A tiny
    # count without cache accounting is not a complete total for this probe.
    if set(present) == {"input_tokens"} and present["input_tokens"] < 100:
        return "?"
    return sum(present.values())


def _claude_dispatch_one(packets: Sequence[Mapping[str, Any]], baseline: NoveltyBaseline, prompt_text: str, model: str) -> ProviderDispatchResult:
    payload = {
        "novelty_baseline": {key: value for key, value in baseline.items},
        "packets": list(packets),
    }
    prompt = f"{prompt_text.strip()}\n\nReturn schema-valid JSON for this redacted input only:\n{_canonical_json(payload)}"
    command = [
        "claude",
        "--print",
        "--safe-mode",
        "--no-session-persistence",
        "--tools",
        "",
        "--permission-mode",
        "plan",
        "--output-format",
        "json",
        "--json-schema",
        _canonical_json(_claude_schema()),
        "--max-budget-usd",
        "5",
        "--model",
        model,
    ]
    started = time.monotonic()
    completed = subprocess.run(
        command,
        input=prompt,
        text=True,
        capture_output=True,
        cwd=_REPOSITORY_ROOT,
        timeout=20 * 60,
        check=False,
    )
    elapsed_minutes = (time.monotonic() - started) / 60
    if completed.returncode != 0:
        raise ProviderDispatchError(_safe_provider_failure(completed.stdout, completed.stderr, completed.returncode))
    try:
        response = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise ProviderDispatchError(f"claude_output_invalid_json; output_sha256={_sha256_text(completed.stdout)}") from error
    if not isinstance(response, Mapping):
        raise ProviderDispatchError("claude_output_invalid_shape")
    structured = _extract_structured_output(response)
    candidates = structured.get("candidates")
    if not isinstance(candidates, list):
        raise ProviderDispatchError("claude_structured_candidates_missing")
    usage = response.get("usage") if isinstance(response.get("usage"), Mapping) else {}
    input_tokens = _claude_total_input_tokens(usage)
    output_tokens = usage.get("output_tokens", "?")
    return ProviderDispatchResult(
        candidates=tuple(item for item in candidates if isinstance(item, Mapping)),
        input_tokens=input_tokens,
        output_tokens=output_tokens if isinstance(output_tokens, int) else "?",
        calls=1,
        wall_minutes=elapsed_minutes,
        model=model,
    )


def _combined_claude_dispatch(packets: Sequence[Mapping[str, Any]], baseline: NoveltyBaseline, prompt_text: str, model: str) -> ProviderDispatchResult:
    batches = tuple(tuple(packets[index:index + 4]) for index in range(0, len(packets), 4))
    results = tuple(_claude_dispatch_one(batch, baseline, prompt_text, model) for batch in batches)
    numeric_input = [result.input_tokens for result in results if isinstance(result.input_tokens, int)]
    numeric_output = [result.output_tokens for result in results if isinstance(result.output_tokens, int)]
    numeric_wall = [result.wall_minutes for result in results if isinstance(result.wall_minutes, (int, float))]
    return ProviderDispatchResult(
        candidates=tuple(candidate for result in results for candidate in result.candidates),
        input_tokens=sum(numeric_input) if len(numeric_input) == len(results) else "?",
        output_tokens=sum(numeric_output) if len(numeric_output) == len(results) else "?",
        calls=sum(result.calls for result in results),
        wall_minutes=sum(numeric_wall) if len(numeric_wall) == len(results) else "?",
        model=model,
    )


def _claude_credential_ready() -> tuple[bool, str]:
    completed = subprocess.run(["cred", "locate", "claude"], text=True, capture_output=True, check=False)
    output = completed.stdout + completed.stderr
    return completed.returncode == 0 and "status=ready" in output, _sha256_text(output)


def prepare_real_probe(
    *,
    source_root: Path = _SOURCE_ROOT,
    baseline_path: Path = _CONFIG_ROOT / "novelty-baseline.example.json",
    prompt_path: Path = _PROMPT_PATH,
    model: str = "claude-sonnet-5",
    start: str = _WINDOW_START,
    cutoff: str = _WINDOW_CUTOFF,
) -> PreparedRealProbe:
    """Build and estimate the fixed sample without any provider egress."""

    start_time = _parse_timestamp(start)
    cutoff_time = _parse_timestamp(cutoff)
    if start_time is None or cutoff_time is None or cutoff_time < start_time:
        raise ValueError("invalid_fixed_window")
    baseline = _load_baseline(baseline_path)
    prompt_text = prompt_path.read_text(encoding="utf-8")
    prompt_id = "value-probe-" + _sha256_text(prompt_text)[:16]
    metadata: list[ArtifactMetadata] = []
    packets: list[Mapping[str, Any]] = []
    sources: list[Mapping[str, Any]] = []
    for artifact_id, stratum in _FIXED_CLAUDE_SAMPLE:
        path = _find_fixed_source(source_root, artifact_id)
        artifact, packet, source_manifest = _build_claude_artifact(path, source_root, artifact_id, stratum, start_time, cutoff_time)
        metadata.append(artifact)
        packets.append(packet)
        sources.append(source_manifest)
    selection = select_root_artifacts(metadata)
    packet_by_id = {str(packet["artifact_id"]): packet for packet in packets}
    ordered_packets = tuple(packet_by_id[artifact.artifact_id] for artifact in selection.artifacts)
    provider_release: dict[str, Any] = {
        "provider": "anthropic",
        "account": "authenticated-claude",
        "harness": "claude",
        "model": model,
        "prompt_id": prompt_id,
        "policy_id": "u8-private-redacted-claude-v1",
        "planned_calls": math.ceil(len(ordered_packets) / 4),
        "prompt_tokens": 1_100,
        "output_tokens_per_call": 5_000,
        "concurrency": 1,
        "per_call_minutes": 20,
        "credential_status": "?",
    }
    return PreparedRealProbe(
        baseline=baseline,
        prompt_text=prompt_text,
        selection=selection,
        packets=ordered_packets,
        sources=tuple(sources),
        provider_release=provider_release,
    )


def run_real_probe(
    *,
    source_root: Path = _SOURCE_ROOT,
    output_root: Path = _REPOSITORY_ROOT / ".u8-private",
    baseline_path: Path = _CONFIG_ROOT / "novelty-baseline.example.json",
    prompt_path: Path = _PROMPT_PATH,
    model: str = "claude-sonnet-5",
    start: str = _WINDOW_START,
    cutoff: str = _WINDOW_CUTOFF,
) -> tuple[ProbeReceipt, Mapping[str, Any]]:
    """Run the actual bounded U8 value probe with first-party Claude egress."""

    prepared = prepare_real_probe(
        source_root=source_root,
        baseline_path=baseline_path,
        prompt_path=prompt_path,
        model=model,
        start=start,
        cutoff=cutoff,
    )
    baseline = prepared.baseline
    prompt_text = prepared.prompt_text
    selection = prepared.selection
    ordered_packets = prepared.packets
    sources = prepared.sources
    provider_release = dict(prepared.provider_release)
    credential_ready, credential_output_hash = _claude_credential_ready()
    provider_release["credential_status"] = "ready" if credential_ready else "not_ready"
    provider_release["credential_check_output_sha256"] = credential_output_hash
    if not credential_ready:
        receipt = ProbeReceipt(
            ProbeStatus.BLOCKED,
            "claude_credential_not_ready",
            0,
            tuple(artifact.artifact_id for artifact in selection.artifacts),
            selection.sha256,
            baseline.sha256,
            provider_release,
            None,
            _empty_actual_resources(),
            (),
            source_files_used=tuple(str(source["source_filename"]) for source in sources),
            safety={"source_files": sources, "provider_dispatch": "not_attempted"},
        )
    else:
        receipt = run_value_probe(
            selection.artifacts,
            baseline=baseline,
            redacted_packets=ordered_packets,
            dispatch=lambda packet_batch: _combined_claude_dispatch(packet_batch, baseline, prompt_text, model),
            provider_release=provider_release,
        )
        receipt = replace(
            receipt,
            source_files_used=tuple(str(source["source_filename"]) for source in sources),
            safety={
                "source_files": sources,
                "selection_reason": selection.selection_reason,
                "claims_corpus_coverage": selection.claims_corpus_coverage,
                "redacted_packet_count": len(ordered_packets),
                "provider_dispatch": "attempted" if receipt.reason != "redaction_quarantine" else "blocked_before_egress",
            },
        )
    receipt_dir = output_root / f"u8-{cutoff.replace(':', '').replace('Z', 'Z')}"
    receipt_path = receipt_dir / "receipt.json"
    receipt_identity = write_probe_receipt(receipt_path, receipt)
    return receipt, {**receipt_identity, "source_files": receipt.source_files_used}


def _cli() -> int:
    parser = argparse.ArgumentParser(description="Run the bounded U8 Claude value probe.")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--run-real", action="store_true", help="run the fixed sample using the first-party Claude CLI")
    mode.add_argument("--preflight", action="store_true", help="build the redacted sample and R25 estimate without provider egress")
    parser.add_argument("--source-root", type=Path, default=_SOURCE_ROOT)
    parser.add_argument("--output-root", type=Path, default=_REPOSITORY_ROOT / ".u8-private")
    parser.add_argument("--model", default="claude-sonnet-5")
    parser.add_argument("--start", default=_WINDOW_START)
    parser.add_argument("--cutoff", default=_WINDOW_CUTOFF)
    arguments = parser.parse_args()
    if arguments.preflight:
        prepared = prepare_real_probe(
            source_root=arguments.source_root,
            model=arguments.model,
            start=arguments.start,
            cutoff=arguments.cutoff,
        )
        quarantined = tuple(sorted(str(packet["artifact_id"]) for packet in prepared.packets if str(packet.get("status", "")).casefold() == "quarantined"))
        estimate = _estimate_from_packets(prepared.packets, prepared.provider_release)
        try:
            enforce_r25(estimate)
            preflight_status = "ready" if not quarantined else "redaction_quarantine"
            resource_dimension = "?"
        except ResourceBudgetExceeded as error:
            preflight_status = "resource_envelope_exceeded"
            resource_dimension = error.dimension
        print(_canonical_json({
            "status": preflight_status,
            "sample_count": len(prepared.selection.artifacts),
            "sample_sha256": prepared.selection.sha256,
            "baseline_sha256": prepared.baseline.sha256,
            "estimated_input_tokens": estimate.input_tokens,
            "estimated_output_tokens": estimate.output_tokens,
            "estimated_calls": estimate.calls,
            "estimated_wall_minutes": estimate.wall_minutes,
            "estimated_monetary_cost_usd": estimate.monetary_cost_usd,
            "quarantined_artifacts": quarantined,
            "resource_dimension": resource_dimension,
        }))
        return 0 if preflight_status == "ready" else 3
    receipt, identity = run_real_probe(
        source_root=arguments.source_root,
        output_root=arguments.output_root,
        model=arguments.model,
        start=arguments.start,
        cutoff=arguments.cutoff,
    )
    # Deliberately omit candidate and packet bodies. The private receipt holds
    # only redacted candidate data and non-path source identifiers.
    validation = receipt.validation_summary or {}
    print(_canonical_json({
        "status": receipt.status.value,
        "reason": receipt.reason,
        "qualifying_learnings": receipt.qualifying_learnings,
        "receipt": identity["path"],
        "receipt_sha256": identity["receipt_sha256"],
        "sample_count": len(receipt.sample_ids),
        "estimated_input_tokens": receipt.estimated_resources.input_tokens if receipt.estimated_resources else "?",
        "estimated_output_tokens": receipt.estimated_resources.output_tokens if receipt.estimated_resources else "?",
        "estimated_calls": receipt.estimated_resources.calls if receipt.estimated_resources else "?",
        "estimated_wall_minutes": receipt.estimated_resources.wall_minutes if receipt.estimated_resources else "?",
        "estimated_monetary_cost_usd": receipt.estimated_resources.monetary_cost_usd if receipt.estimated_resources else "?",
        "actual_input_tokens": receipt.actual_resources.get("input_tokens", "?"),
        "actual_output_tokens": receipt.actual_resources.get("output_tokens", "?"),
        "actual_calls": receipt.actual_resources.get("calls", "?"),
        "actual_wall_minutes": receipt.actual_resources.get("wall_minutes", "?"),
        "actual_monetary_cost_usd": receipt.actual_resources.get("monetary_cost_usd", "?"),
        "claim_labels": validation.get("claim_labels", {}),
        "accepted_claim_labels": validation.get("accepted_claim_labels", {}),
        "rejection_reasons": validation.get("rejection_reasons", {}),
        "evidence_strength_distribution": validation.get("evidence_strength_distribution", {}),
        "resource_dimension": receipt.resource_dimension or "?",
    }))
    return 0 if receipt.status is not ProbeStatus.BLOCKED else 2


if __name__ == "__main__":
    raise SystemExit(_cli())
