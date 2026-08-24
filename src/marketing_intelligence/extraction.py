"""Schema-bound session-learning extraction and provider release gates."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
from typing import Any, Mapping, Sequence

from .census import canonical_json, validate_schema_document


_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_SCHEMA_PATH = _REPOSITORY_ROOT / "schemas" / "candidate-learning.schema.json"

CLAIM_LABELS = frozenset({"[DATA]", "[LOGIC]", "[HYPOTHESIS]"})
TOPICS = frozenset({
    "demand_generation",
    "paid_advertising",
    "seo",
    "content_marketing",
    "attribution_measurement",
    "product_marketing",
    "activation_onboarding",
    "leadership_strategy",
    "ai_and_marketing_operations",
})
LEARNING_TYPES = frozenset({"metric", "finding", "formula", "win", "loss", "callout", "channel"})


@dataclass(frozen=True)
class CandidateValidationResult:
    """A deterministic result of validating one model-shaped response."""

    accepted: bool
    terminal_status: str
    candidates: tuple[dict[str, Any], ...]
    errors: tuple[str, ...]


@dataclass(frozen=True)
class ProviderReleaseValidation:
    """A provider-affinity decision with no provider fallback path."""

    approved: bool
    errors: tuple[str, ...]


def stable_candidate_id(packet_id: str, candidate: Mapping[str, Any]) -> str:
    """Return the stable candidate identity from packet coverage and content."""

    identity = {key: value for key, value in candidate.items() if key != "candidate_id"}
    digest = hashlib.sha256(
        (str(packet_id) + "\0" + canonical_json(identity)).encode("utf-8")
    ).hexdigest()
    return "candidate-" + digest[:24]


def approved_packet_fields(stage: str) -> tuple[str, ...]:
    """Return the only redacted packet fields a provider may receive."""

    if stage not in {"classification", "full_extraction"}:
        raise ValueError("unknown_analysis_stage")
    return ("packet_id", "harness", "source_version", "event_ids", "events")


def _packet_evidence(packet: Mapping[str, Any]) -> dict[str, str]:
    events = packet.get("events")
    if not isinstance(events, Sequence) or isinstance(events, (str, bytes)):
        return {}
    packet_event_ids = {
        value for value in packet.get("event_ids", ())
        if isinstance(value, str)
    }
    evidence: dict[str, str] = {}
    for event in events:
        if not isinstance(event, Mapping):
            continue
        event_id = event.get("event_id")
        uri = event.get("evidence_uri")
        strength = event.get("evidence_strength")
        if (
            isinstance(event_id, str)
            and event_id in packet_event_ids
            and isinstance(uri, str)
            and uri.endswith(f"#event={event_id}")
            and isinstance(strength, str)
        ):
            evidence[uri] = strength
    return evidence


def _is_harness_only_ai_lesson(candidate: Mapping[str, Any]) -> bool:
    """Reject workflow mechanics unless they state a marketing consequence."""

    if candidate.get("topic") != "ai_and_marketing_operations":
        return False
    text = " ".join(
        str(candidate.get(field, ""))
        for field in ("summary", "transferability_rationale")
    ).casefold()
    harness_terms = {"agent", "harness", "model", "prompt", "sdk", "tool", "fixture", "cli", "retry", "token"}
    marketing_terms = {
        "marketing", "campaign", "demand", "lead", "pipeline", "buyer", "audience",
        "advertising", "paid", "seo", "content", "attribution", "conversion", "revenue",
    }
    tokens = set(re.findall(r"[a-z0-9_]+", text))
    return bool(tokens & harness_terms) and not bool(tokens & marketing_terms)


def validate_candidate_document(
    document: Mapping[str, Any],
    packet: Mapping[str, Any],
    *,
    schema_path: Path = _SCHEMA_PATH,
) -> CandidateValidationResult:
    """Validate a candidate or no-learning response against packet coverage.

    The function never trusts response prose. In particular, a `[DATA]` label
    is valid only if all cited evidence is present in the current redacted
    packet and marked as observed by U2.
    """

    errors = list(validate_schema_document(document, schema_path))
    packet_id = packet.get("packet_id")
    if not isinstance(packet_id, str):
        errors.append("packet.packet_id:invalid")
        packet_id = "?"
    if document.get("packet_id") != packet_id:
        errors.append("document.packet_id:packet_mismatch")

    result_type = document.get("result_type")
    candidates = document.get("candidates")
    if not isinstance(candidates, list):
        candidates = []
    if result_type == "no_learning":
        reason = document.get("no_learning_reason")
        if candidates:
            errors.append("no_learning.candidates:must_be_empty")
        if not isinstance(reason, str) or not reason.strip():
            errors.append("no_learning_reason:required")
        return CandidateValidationResult(
            accepted=not errors,
            terminal_status="no_learning" if not errors else "rejected_invalid",
            candidates=(),
            errors=tuple(sorted(set(errors))),
        )
    if result_type == "candidates" and not candidates:
        errors.append("candidates:minItems")
    if result_type not in {"candidates", "no_learning"}:
        errors.append("result_type:invalid")

    evidence_strength = _packet_evidence(packet)
    validated: list[dict[str, Any]] = []
    candidate_ids: set[str] = set()
    for index, candidate in enumerate(candidates):
        if not isinstance(candidate, Mapping):
            errors.append(f"candidate[{index}]:invalid")
            continue
        candidate_id = candidate.get("candidate_id")
        expected_id = stable_candidate_id(packet_id, candidate)
        if candidate_id != expected_id:
            errors.append(f"candidate[{index}].candidate_id:not_stable")
        if isinstance(candidate_id, str):
            if candidate_id in candidate_ids:
                errors.append(f"candidate[{index}].candidate_id:duplicate")
            candidate_ids.add(candidate_id)
        if candidate.get("topic") not in TOPICS:
            errors.append(f"candidate[{index}].topic:unsupported")
        if candidate.get("learning_type") not in LEARNING_TYPES:
            errors.append(f"candidate[{index}].learning_type:unsupported")
        if candidate.get("claim_label") not in CLAIM_LABELS:
            errors.append(f"candidate[{index}].claim_label:unsupported")
        if _is_harness_only_ai_lesson(candidate):
            errors.append(f"candidate[{index}]:harness_only_ai_lesson")
        uris = candidate.get("evidence_uris")
        if isinstance(uris, list):
            for evidence_index, uri in enumerate(uris):
                if not isinstance(uri, str) or uri not in evidence_strength:
                    errors.append(f"candidate.evidence_uris[{evidence_index}]:not_in_packet")
                elif candidate.get("claim_label") == "[DATA]" and evidence_strength[uri] != "observed":
                    errors.append(f"candidate.evidence_uris[{evidence_index}]:not_observed")
        validated.append(dict(candidate))
    return CandidateValidationResult(
        accepted=not errors,
        terminal_status="extracted" if not errors else "rejected_invalid",
        candidates=tuple(validated) if not errors else (),
        errors=tuple(sorted(set(errors))),
    )


def validate_provider_release(
    release: Mapping[str, Any],
    work_item: Mapping[str, Any],
) -> ProviderReleaseValidation:
    """Apply KTD14 to one work item without attempting a provider fallback."""

    harness = work_item.get("harness")
    expected = {
        "codex": ("openai", "authenticated-first-party-codex"),
        "claude": ("anthropic", "authenticated-first-party-claude"),
    }
    errors: list[str] = []
    if harness not in expected:
        errors.append("work_item_harness_invalid")
        return ProviderReleaseValidation(False, tuple(errors))
    expected_provider, expected_account = expected[str(harness)]
    if release.get("provider") != expected_provider:
        errors.append("provider_affinity_mismatch")
    if release.get("account") != expected_account:
        errors.append("account_affinity_mismatch")
    if release.get("account_verified") is not True:
        errors.append("account_unverified")
    if not isinstance(release.get("model"), str) or not str(release.get("model")).strip():
        errors.append("model_unverified")
    if release.get("model_verified") is not True:
        errors.append("model_unverified")
    if release.get("prompt_sha256") != work_item.get("prompt_sha256"):
        errors.append("prompt_mismatch")
    if release.get("policy_version") != work_item.get("policy_version"):
        errors.append("policy_mismatch")
    if tuple(release.get("approved_fields", ())) != tuple(work_item.get("approved_fields", ())):
        errors.append("approved_fields_mismatch")
    if release.get("raw_tools") != []:
        errors.append("raw_tools_not_disabled")
    if "fallback_provider" in release:
        errors.append("fallback_provider_forbidden")
    if release.get("encrypted_transport_verified") is not True:
        errors.append("transport_unverified")
    return ProviderReleaseValidation(not errors, tuple(sorted(errors)))
