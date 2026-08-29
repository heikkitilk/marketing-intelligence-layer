"""Deterministic, private U7 extraction-quality pilot controls.

This module deliberately contains no provider client. It selects only U2
redacted packets, freezes the reviewer material before result ingestion, and
checks the pilot against a reviewer-owned reference set.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Any, Mapping, Sequence

from .census import canonical_json
from .extraction import TOPICS, validate_candidate_document


PILOT_PACKET_COUNT = 24
SELECTION_POLICY_VERSION = "quality-pilot-selector/v2"
REVIEWER_LABEL_SCHEMA_VERSION = "quality-reviewer-labels/v1"
EXTRACTOR_RESULTS_SCHEMA_VERSION = "quality-extractor-results/v1"
LEARNING_EXPECTATION_RULE_VERSION = "redacted_packet_heuristic_v1"

_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_CORE_DIMENSIONS = ("harness", "execution_kind", "artifact_role", "learning_expectation")
_DIMENSION_WEIGHTS = {
    # A higher-order dimension must not be relaxed merely because several
    # lower-order dimensions differ. This is the predeclared substitution
    # policy used in every selection receipt.
    "harness": 16,
    "execution_kind": 8,
    "artifact_role": 4,
    "learning_expectation": 2,
    "workload_class": 1,
}
_MARKETING_TERMS = frozenset({
    "marketing", "campaign", "audience", "buyer", "demand", "lead", "pipeline",
    "advertising", "paid", "seo", "content", "attribution", "conversion", "revenue",
    "budget", "brand", "activation", "product",
})
_DECISION_TERMS = frozenset({
    "action", "allocate", "budget", "change", "decision", "decrease", "increase",
    "launch", "measure", "prioritize", "reallocate", "segment", "stop", "target", "test",
})
_HARNESS_TERMS = frozenset({
    "agent", "cli", "fixture", "harness", "model", "prompt", "sdk", "token", "tool"})
_EXECUTION_KINDS = frozenset({"interactive", "sdk", "synthetic_test", "unknown"})
_WORKLOAD_CLASSES = frozenset({"marketing_project", "synthetic_test", "documents", "other", "unknown", "?"})
_ARTIFACT_ROLES_BY_SOURCE_KIND = {
    "root_conversation": "root",
    "child_agent": "child",
    "unknown": "unknown",
}


class QualityPilotError(ValueError):
    """A fail-closed U7 contract error with no source-content detail."""


class QualityPilotBlocked(QualityPilotError):
    """The selected packet population cannot authorize a blind pilot."""


class QualityPilotOrderError(QualityPilotError):
    """A reviewer/extractor artifact was attempted in the wrong order."""


@dataclass(frozen=True)
class PilotSelection:
    """A hash-bound reference-set proposal with explicit substitutions."""

    selected_packet_ids: tuple[str, ...]
    selected_rows: tuple[dict[str, Any], ...]
    substitutions: tuple[dict[str, Any], ...]
    absent_optional_strata: tuple[str, ...]
    absent_required_strata: tuple[str, ...]
    hard_blockers: tuple[str, ...]
    selection_sha256: str
    document: dict[str, Any]


@dataclass(frozen=True)
class ArtifactReceipt:
    """A content-addressed private artifact receipt."""

    artifact_kind: str
    relative_path: str
    sha256: str
    selection_sha256: str
    status: str = "written"


@dataclass(frozen=True)
class FrozenReferenceSet:
    """Hashes the reviewer-visible reference set without exposing it in logs."""

    selection_sha256: str
    reviewer_label_schema_sha256: str
    reference_set_sha256: str
    packet_count: int


@dataclass(frozen=True)
class QualityPilotEvaluation:
    """A deterministic gate result used to authorize or block U4-U6."""

    selection_sha256: str
    status: str
    metrics: dict[str, dict[str, Any]]
    failing_metrics: tuple[str, ...]
    blocked_units: tuple[str, ...]
    document: dict[str, Any]


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_sha256(value: Mapping[str, Any]) -> str:
    return _sha256_bytes(canonical_json(dict(value)).encode("utf-8"))


def _target_slots() -> tuple[dict[str, Any], ...]:
    """Return the fixed 24-slot policy before looking at any packet rows."""

    slots: list[dict[str, Any]] = []
    for harness in ("claude", "codex"):
        for execution_kind in ("interactive", "sdk"):
            for artifact_role in ("root", "child"):
                for learning_expectation in ("likely_learning", "no_learning"):
                    slots.append({
                        "slot_id": f"base-{len(slots) + 1:02d}",
                        "requested": {
                            "harness": harness,
                            "execution_kind": execution_kind,
                            "artifact_role": artifact_role,
                            "learning_expectation": learning_expectation,
                            "workload_class": "any",
                        },
                    })

    # The remaining eight slots reserve an observable mixed-work check without
    # claiming it exists. If it is absent, the weighted policy below chooses a
    # disclosed nearest packet instead of fabricating a mixed-work stratum.
    for index, (harness, execution_kind, artifact_role) in enumerate(
        (
            (harness, execution_kind, artifact_role)
            for harness in ("claude", "codex")
            for execution_kind in ("interactive", "sdk")
            for artifact_role in ("root", "child")
        ),
        start=1,
    ):
        slots.append({
            "slot_id": f"mixed-{index:02d}",
            "requested": {
                "harness": harness,
                "execution_kind": execution_kind,
                "artifact_role": artifact_role,
                "learning_expectation": "likely_learning" if index % 2 else "no_learning",
                "workload_class": "mixed_work",
            },
        })
    assert len(slots) == PILOT_PACKET_COUNT
    return tuple(slots)


_TARGET_SLOTS = _target_slots()


def _source_records_by_artifact(
    packet_manifest: Mapping[str, Any],
    source_manifest: Mapping[str, Any],
) -> tuple[str, dict[str, Mapping[str, Any]]]:
    """Bind U2 rows to one canonical U1 document before selection."""

    expected_hash = packet_manifest.get("source_manifest_sha256")
    if not isinstance(expected_hash, str) or re.fullmatch(r"[a-f0-9]{64}", expected_hash) is None:
        raise QualityPilotError("quality_source_manifest_hash_invalid")
    if _canonical_sha256(source_manifest) != expected_hash:
        raise QualityPilotError("quality_source_manifest_hash_mismatch")
    if source_manifest.get("schema_version") != "session-manifest/v1":
        raise QualityPilotError("quality_source_manifest_invalid")
    rows = source_manifest.get("records")
    if not isinstance(rows, list):
        raise QualityPilotError("quality_source_manifest_invalid")

    records: dict[str, Mapping[str, Any]] = {}
    for row in rows:
        if not isinstance(row, Mapping):
            raise QualityPilotError("quality_source_manifest_record_invalid")
        artifact_id = row.get("artifact_id")
        if not isinstance(artifact_id, str) or re.fullmatch(r"artifact-[a-f0-9]{24}", artifact_id) is None:
            raise QualityPilotError("quality_source_manifest_record_invalid")
        if artifact_id in records:
            raise QualityPilotError("quality_source_manifest_duplicate_artifact")
        records[artifact_id] = row
    return expected_hash, records


def _source_selection_dimensions(
    packet_row: Mapping[str, Any],
    source_record: Mapping[str, Any],
) -> dict[str, str]:
    """Use only safe, structured U1 fields for non-judgment selector strata."""

    harness = packet_row.get("harness")
    source_harness = source_record.get("harness")
    if harness not in {"claude", "codex"} or source_harness != harness:
        raise QualityPilotError("quality_source_manifest_harness_mismatch")
    if source_record.get("terminal_status") != "complete" or source_record.get("in_window") is not True:
        raise QualityPilotError("quality_source_manifest_artifact_not_eligible")
    source_version = packet_row.get("source_version")
    if not isinstance(source_version, str) or source_record.get("content_sha256") != source_version:
        raise QualityPilotError("quality_source_manifest_source_version_mismatch")

    classification = source_record.get("classification")
    dependence_fields = source_record.get("dependence_fields")
    if not isinstance(classification, Mapping) or not isinstance(dependence_fields, Mapping):
        raise QualityPilotError("quality_source_manifest_record_invalid")
    execution_shape = classification.get("execution_shape")
    working_directory = classification.get("working_directory")
    if not isinstance(execution_shape, Mapping) or not isinstance(working_directory, Mapping):
        raise QualityPilotError("quality_source_manifest_record_invalid")

    execution_kind = execution_shape.get("value")
    execution_provenance = execution_shape.get("provenance")
    execution_rule = execution_shape.get("rule")
    if (
        not isinstance(execution_kind, str)
        or execution_kind not in _EXECUTION_KINDS
        or not isinstance(execution_provenance, str)
        or not isinstance(execution_rule, str)
    ):
        raise QualityPilotError("quality_source_manifest_execution_shape_invalid")

    source_kind = source_record.get("source_kind")
    if not isinstance(source_kind, str) or source_kind not in _ARTIFACT_ROLES_BY_SOURCE_KIND:
        raise QualityPilotError("quality_source_manifest_source_kind_invalid")

    classification_workload = working_directory.get("value")
    dependence_workload = dependence_fields.get("working_directory_category")
    if (
        not isinstance(classification_workload, str)
        or classification_workload not in _WORKLOAD_CLASSES
        or not isinstance(dependence_workload, str)
        or dependence_workload not in _WORKLOAD_CLASSES
    ):
        raise QualityPilotError("quality_source_manifest_workload_invalid")
    known_workloads = {value for value in (classification_workload, dependence_workload) if value not in {"unknown", "?"}}
    if len(known_workloads) > 1:
        raise QualityPilotError("quality_source_manifest_workload_mismatch")
    if classification_workload not in {"unknown", "?"}:
        workload_class = classification_workload
        workload_provenance = "u1_classification_working_directory"
    elif dependence_workload not in {"unknown", "?"}:
        workload_class = dependence_workload
        workload_provenance = "u1_dependence_working_directory"
    else:
        workload_class = "unknown"
        workload_provenance = "u1_workload_metadata_unknown"

    return {
        "harness": str(harness),
        "execution_kind": execution_kind,
        "execution_kind_provenance": execution_provenance,
        "execution_kind_rule": execution_rule,
        "artifact_role": _ARTIFACT_ROLES_BY_SOURCE_KIND[source_kind],
        "artifact_role_provenance": "u1_source_kind",
        "artifact_role_rule": "root_conversation=root;child_agent=child;unknown=unknown",
        "workload_class": workload_class,
        "workload_class_provenance": workload_provenance,
        "workload_class_rule": "u1.classification.working_directory.value_then_dependence_fields.working_directory_category",
    }


def _redacted_packet_text(packet_row: Mapping[str, Any], packet: Mapping[str, Any]) -> str:
    """Return only selected U2 redacted event text after identity validation."""

    if (
        packet.get("packet_id") != packet_row.get("packet_id")
        or packet.get("artifact_id") != packet_row.get("artifact_id")
        or packet.get("harness") != packet_row.get("harness")
        or packet.get("source_version") != packet_row.get("source_version")
    ):
        raise QualityPilotError("quality_prelabel_packet_identity_mismatch")
    event_ids = packet.get("event_ids")
    events = packet.get("events")
    expected_event_ids = packet_row.get("event_ids")
    if (
        not isinstance(event_ids, list)
        or not isinstance(expected_event_ids, list)
        or not isinstance(events, list)
        or any(not isinstance(event_id, str) for event_id in event_ids)
        or any(not isinstance(event_id, str) for event_id in expected_event_ids)
        or len(event_ids) != len(set(event_ids))
        or len(expected_event_ids) != len(set(expected_event_ids))
        or set(event_ids) != set(expected_event_ids)
    ):
        raise QualityPilotError("quality_prelabel_packet_coverage_invalid")
    text_parts: list[str] = []
    for event in events:
        if not isinstance(event, Mapping) or not isinstance(event.get("text"), str):
            raise QualityPilotError("quality_prelabel_packet_text_invalid")
        text_parts.append(str(event["text"]))
    return "\n".join(text_parts)


def _learning_expectation(packet_row: Mapping[str, Any], packet: Mapping[str, Any]) -> dict[str, Any]:
    """Pre-label only redacted text with a fixed, non-provider heuristic."""

    tokens = _token_set(_redacted_packet_text(packet_row, packet))
    marketing_terms = len(tokens & _MARKETING_TERMS)
    decision_terms = len(tokens & _DECISION_TERMS)
    harness_terms = len(tokens & _HARNESS_TERMS)
    likely_learning = marketing_terms >= 2 and decision_terms >= 1 and marketing_terms > harness_terms
    return {
        "learning_expectation": "likely_learning" if likely_learning else "no_learning",
        "learning_expectation_provenance": LEARNING_EXPECTATION_RULE_VERSION,
        "learning_expectation_rule": "marketing_terms>=2_and_decision_terms>=1_and_marketing_terms>harness_terms",
        "learning_expectation_signals": {
            "marketing_term_count": marketing_terms,
            "decision_term_count": decision_terms,
            "harness_term_count": harness_terms,
        },
    }


def _prepared_rows(
    packet_manifest: Mapping[str, Any],
    source_manifest: Mapping[str, Any],
    packet_documents: Mapping[str, Mapping[str, Any]],
) -> tuple[str, tuple[dict[str, Any], ...]]:
    rows = packet_manifest.get("packets")
    if not isinstance(rows, list):
        raise QualityPilotError("quality_packet_manifest_invalid")
    source_manifest_sha256, source_records = _source_records_by_artifact(packet_manifest, source_manifest)
    prepared: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in rows:
        if not isinstance(raw, Mapping) or raw.get("terminal_outcome") != "prepared_no_egress":
            continue
        packet_id = raw.get("packet_id")
        artifact_id = raw.get("artifact_id")
        if (
            not isinstance(packet_id, str)
            or re.fullmatch(r"packet-[a-f0-9]{24}", packet_id) is None
            or not isinstance(artifact_id, str)
            or re.fullmatch(r"artifact-[a-f0-9]{24}", artifact_id) is None
            or packet_id in seen
        ):
            raise QualityPilotError("quality_packet_manifest_identity_invalid")
        seen.add(packet_id)
        source_record = source_records.get(artifact_id)
        if source_record is None:
            raise QualityPilotError("quality_source_manifest_artifact_missing")
        packet = packet_documents.get(packet_id)
        if not isinstance(packet, Mapping):
            raise QualityPilotError("quality_prelabel_packet_missing")
        row = dict(raw)
        row.update(_source_selection_dimensions(raw, source_record))
        row.update(_learning_expectation(row, packet))
        prepared.append(row)
    return source_manifest_sha256, tuple(sorted(prepared, key=lambda row: str(row["packet_id"])))


def _candidate_distance(requested: Mapping[str, str], candidate: Mapping[str, Any]) -> tuple[int, tuple[str, ...]]:
    mismatches = tuple(
        dimension
        for dimension in _DIMENSION_WEIGHTS
        if requested.get(dimension) not in {None, "any"}
        and candidate.get(dimension) != requested.get(dimension)
    )
    return sum(_DIMENSION_WEIGHTS[dimension] for dimension in mismatches), mismatches


def _stable_choice_key(slot_id: str, candidate: Mapping[str, Any]) -> str:
    return _sha256_bytes(f"{slot_id}\0{candidate['packet_id']}".encode("utf-8"))


def _minimum_cost_assignment(costs: Sequence[Sequence[int]]) -> tuple[int, ...]:
    """Return a deterministic minimum-cost row-to-column assignment for n <= m."""

    if not costs or not costs[0] or len(costs) > len(costs[0]):
        raise QualityPilotError("quality_selection_assignment_invalid")
    row_count = len(costs)
    column_count = len(costs[0])
    if any(len(row) != column_count for row in costs):
        raise QualityPilotError("quality_selection_assignment_invalid")

    # Hungarian algorithm for a rectangular minimum-cost assignment. Costs are
    # integers, so the exact same candidate population yields the same result.
    potentials_row = [0] * (row_count + 1)
    potentials_column = [0] * (column_count + 1)
    matching = [0] * (column_count + 1)
    previous_column = [0] * (column_count + 1)
    for row_index in range(1, row_count + 1):
        matching[0] = row_index
        current_column = 0
        minimum = [10**18] * (column_count + 1)
        used = [False] * (column_count + 1)
        while True:
            used[current_column] = True
            current_row = matching[current_column]
            delta = 10**18
            next_column = 0
            for column_index in range(1, column_count + 1):
                if used[column_index]:
                    continue
                reduced = costs[current_row - 1][column_index - 1] - potentials_row[current_row] - potentials_column[column_index]
                if reduced < minimum[column_index]:
                    minimum[column_index] = reduced
                    previous_column[column_index] = current_column
                if minimum[column_index] < delta:
                    delta = minimum[column_index]
                    next_column = column_index
            if next_column == 0:
                raise QualityPilotError("quality_selection_assignment_invalid")
            for column_index in range(column_count + 1):
                if used[column_index]:
                    potentials_row[matching[column_index]] += delta
                    potentials_column[column_index] -= delta
                else:
                    minimum[column_index] -= delta
            current_column = next_column
            if matching[current_column] == 0:
                break
        while True:
            prior = previous_column[current_column]
            matching[current_column] = matching[prior]
            current_column = prior
            if current_column == 0:
                break

    assignment = [-1] * row_count
    for column_index in range(1, column_count + 1):
        if matching[column_index]:
            assignment[matching[column_index] - 1] = column_index - 1
    if any(value < 0 for value in assignment):
        raise QualityPilotError("quality_selection_assignment_invalid")
    return tuple(assignment)


def _select_unique_rows(prepared: Sequence[Mapping[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    """Globally minimize weighted substitutions while preserving packet uniqueness."""

    if len(prepared) < len(_TARGET_SLOTS):
        selected: list[dict[str, Any]] = []
        used_packet_ids: set[str] = set()
        for slot in _TARGET_SLOTS:
            choices = [row for row in prepared if str(row["packet_id"]) not in used_packet_ids]
            if not choices:
                break
            chosen = min(
                choices,
                key=lambda row: (
                    _candidate_distance(slot["requested"], row)[0],
                    _candidate_distance(slot["requested"], row)[1],
                    _stable_choice_key(str(slot["slot_id"]), row),
                ),
            )
            used_packet_ids.add(str(chosen["packet_id"]))
            selected_row = dict(chosen)
            selected_row["selection_slot_id"] = slot["slot_id"]
            selected.append(selected_row)
        return selected, [str(slot["slot_id"]) for slot in _TARGET_SLOTS[len(selected):]]

    candidates = tuple(sorted(prepared, key=lambda row: str(row["packet_id"])))
    scale = 1_000_000
    costs: list[list[int]] = []
    for slot in _TARGET_SLOTS:
        rank_by_packet = {
            str(candidate["packet_id"]): rank
            for rank, candidate in enumerate(
                sorted(candidates, key=lambda candidate: _stable_choice_key(str(slot["slot_id"]), candidate)),
                start=1,
            )
        }
        costs.append([
            _candidate_distance(slot["requested"], candidate)[0] * scale + rank_by_packet[str(candidate["packet_id"])]
            for candidate in candidates
        ])
    assignment = _minimum_cost_assignment(costs)
    selected = []
    for slot, candidate_index in zip(_TARGET_SLOTS, assignment, strict=True):
        selected_row = dict(candidates[candidate_index])
        selected_row["selection_slot_id"] = slot["slot_id"]
        selected.append(selected_row)
    return selected, []


def _count_strata(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    counts = Counter(
        tuple(str(row.get(dimension, "unknown")) for dimension in _CORE_DIMENSIONS)
        for row in rows
    )
    return [
        {
            "harness": values[0],
            "execution_kind": values[1],
            "artifact_role": values[2],
            "learning_expectation": values[3],
            "packet_count": count,
        }
        for values, count in sorted(counts.items())
    ]


def select_reference_packets(
    packet_manifest: Mapping[str, Any],
    source_manifest: Mapping[str, Any],
    packet_documents: Mapping[str, Mapping[str, Any]],
) -> PilotSelection:
    """Join U1/U2 metadata and pre-label only redacted U2 text for the fixed U7 sample."""

    source_manifest_sha256, prepared = _prepared_rows(packet_manifest, source_manifest, packet_documents)
    observed_harnesses = {str(row["harness"]) for row in prepared}
    hard_blockers: list[str] = []
    if "claude" not in observed_harnesses:
        hard_blockers.append("claude_packets_absent")
    if "codex" not in observed_harnesses:
        hard_blockers.append("codex_packets_absent")
    if len(prepared) < PILOT_PACKET_COUNT:
        hard_blockers.append("prepared_packets_below_24")

    observed_workload_classes = {str(row["workload_class"]) for row in prepared}
    absent_optional_strata = tuple(
        value for value in ("mixed_work",) if value not in observed_workload_classes
    )
    absent_required_strata = tuple(
        f"{dimension}:{value}"
        for dimension, values in (
            ("execution_kind", ("interactive", "sdk")),
            ("artifact_role", ("root", "child")),
            ("learning_expectation", ("likely_learning", "no_learning")),
        )
        for value in values
        if not any(str(row[dimension]) == value for row in prepared)
    )
    metadata_absences = tuple(
        dimension
        for dimension in ("execution_kind", "artifact_role", "workload_class")
        if not any(str(row[dimension]) != "unknown" for row in prepared)
    )

    selected, unfilled_slots = _select_unique_rows(prepared)
    substitutions: list[dict[str, Any]] = []
    slots_by_id = {str(slot["slot_id"]): slot for slot in _TARGET_SLOTS}
    for chosen in selected:
        slot = slots_by_id[str(chosen["selection_slot_id"])]
        requested = slot["requested"]
        actual = {dimension: str(chosen[dimension]) for dimension in _DIMENSION_WEIGHTS}
        distance, mismatches = _candidate_distance(requested, chosen)
        if mismatches:
            substitutions.append({
                "slot_id": chosen["selection_slot_id"],
                "requested": dict(requested),
                "actual": actual,
                "mismatched_dimensions": list(mismatches),
                "weighted_distance": distance,
                "policy": "global_minimum_weighted_hamming_v1",
            })

    if unfilled_slots and "prepared_packets_below_24" not in hard_blockers:
        hard_blockers.append("selection_slots_unfilled")
    selection_rows = [
        {
            "slot_id": row["selection_slot_id"],
            "packet_id": row["packet_id"],
            "artifact_id": row["artifact_id"],
            "harness": row["harness"],
            "source_version": row.get("source_version", "?"),
            "event_ids": list(row.get("event_ids", ())),
            "execution_kind": row["execution_kind"],
            "execution_kind_provenance": row["execution_kind_provenance"],
            "execution_kind_rule": row["execution_kind_rule"],
            "artifact_role": row["artifact_role"],
            "artifact_role_provenance": row["artifact_role_provenance"],
            "artifact_role_rule": row["artifact_role_rule"],
            "learning_expectation": row["learning_expectation"],
            "learning_expectation_provenance": row["learning_expectation_provenance"],
            "learning_expectation_rule": row["learning_expectation_rule"],
            "learning_expectation_signals": dict(row["learning_expectation_signals"]),
            "workload_class": row["workload_class"],
            "workload_class_provenance": row["workload_class_provenance"],
            "workload_class_rule": row["workload_class_rule"],
        }
        for row in selected
    ]
    document: dict[str, Any] = {
        "schema_version": SELECTION_POLICY_VERSION,
        "status": "ready" if not hard_blockers else "reduced_scope",
        "target_packet_count": PILOT_PACKET_COUNT,
        "source_manifest_sha256": source_manifest_sha256,
        "source_manifest_join": {
            "key": "artifact_id",
            "harness_consistency": "required",
            "source_version_consistency": "required",
        },
        "selection_policy": {
            "version": SELECTION_POLICY_VERSION,
            "substitution_weights": dict(_DIMENSION_WEIGHTS),
            "target_slots": list(_TARGET_SLOTS),
            "assignment": "global_minimum_weighted_hamming_v1",
        },
        "learning_expectation_policy": {
            "version": LEARNING_EXPECTATION_RULE_VERSION,
            "input": "redacted_u2_event_text_only",
            "provider_or_model_output": "not_used",
            "rule": "marketing_terms>=2_and_decision_terms>=1_and_marketing_terms>harness_terms",
        },
        "workload_class_policy": {
            "input": "u1_classification_or_dependence_metadata_only",
            "mixed_work": "absent_unless_explicitly_present_in_source_metadata",
        },
        "prepared_packet_count": len(prepared),
        "observed_stratum_counts": _count_strata(prepared),
        "selected_stratum_counts": _count_strata(selection_rows),
        "selected": selection_rows,
        "substitutions": substitutions,
        "unfilled_slots": unfilled_slots,
        "absent_optional_strata": list(absent_optional_strata),
        "absent_required_strata": list(absent_required_strata),
        "metadata_absences": list(metadata_absences),
        "hard_blockers": sorted(hard_blockers),
    }
    selection_sha256 = _canonical_sha256(document)
    document["selection_sha256"] = selection_sha256
    return PilotSelection(
        selected_packet_ids=tuple(str(row["packet_id"]) for row in selected),
        selected_rows=tuple(selection_rows),
        substitutions=tuple(substitutions),
        absent_optional_strata=absent_optional_strata,
        absent_required_strata=absent_required_strata,
        hard_blockers=tuple(sorted(hard_blockers)),
        selection_sha256=selection_sha256,
        document=document,
    )


def _ensure_private_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    details = os.lstat(path)
    if stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode):
        raise QualityPilotError("quality_private_output_not_directory")
    if details.st_uid != os.getuid():
        raise PermissionError("quality_private_output_unsafe_owner")
    os.chmod(path, 0o700)


def _safe_relative_path(value: str) -> Path:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise QualityPilotError("quality_artifact_path_invalid")
    return path


def _private_file(path: Path) -> tuple[int, os.stat_result]:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    details = os.fstat(descriptor)
    if details.st_uid != os.getuid() or not stat.S_ISREG(details.st_mode):
        os.close(descriptor)
        raise QualityPilotError("quality_artifact_unsafe")
    return descriptor, details


class PilotArtifactStore:
    """Append-only proof of reviewer-before-extractor artifact ordering."""

    def __init__(self, root: Path, *, require_ignored: bool = True, fresh: bool = False) -> None:
        self.root = Path(root).expanduser()
        if fresh and (self.root.exists() or self.root.is_symlink()):
            raise QualityPilotError("quality_pilot_root_not_fresh")
        if require_ignored:
            self._require_ignored(self.root)
        _ensure_private_directory(self.root)
        self.ledger_path = self.root / "artifact-order.jsonl"

    @staticmethod
    def _require_ignored(root: Path) -> None:
        try:
            relative = root.resolve(strict=False).relative_to(_REPOSITORY_ROOT.resolve())
        except ValueError as error:
            raise QualityPilotError("quality_private_output_outside_repository") from error
        checked = subprocess.run(
            ["git", "check-ignore", "--quiet", "--", relative.as_posix()],
            cwd=_REPOSITORY_ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if checked.returncode != 0:
            raise QualityPilotError("quality_private_output_not_gitignored")

    def _read_ledger(self) -> tuple[dict[str, Any], ...]:
        if not self.ledger_path.exists():
            return ()
        descriptor, _ = _private_file(self.ledger_path)
        try:
            with os.fdopen(descriptor, "r", encoding="utf-8", closefd=False) as stream:
                lines = tuple(line for line in stream if line.strip())
        finally:
            os.close(descriptor)
        entries: list[dict[str, Any]] = []
        previous = ""
        for sequence, line in enumerate(lines, start=1):
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as error:
                raise QualityPilotError("quality_artifact_ledger_invalid") from error
            if not isinstance(entry, dict) or entry.get("sequence") != sequence:
                raise QualityPilotError("quality_artifact_ledger_invalid")
            relative = entry.get("relative_path")
            digest = entry.get("sha256")
            entry_digest = entry.get("entry_sha256")
            if not isinstance(relative, str) or not isinstance(digest, str) or not isinstance(entry_digest, str):
                raise QualityPilotError("quality_artifact_ledger_invalid")
            if entry.get("previous_entry_sha256") != previous:
                raise QualityPilotError("quality_artifact_ledger_chain_invalid")
            unsigned = {key: value for key, value in entry.items() if key != "entry_sha256"}
            if _canonical_sha256(unsigned) != entry_digest:
                raise QualityPilotError("quality_artifact_ledger_chain_invalid")
            artifact_path = self.root / _safe_relative_path(relative)
            artifact_descriptor, _ = _private_file(artifact_path)
            try:
                with os.fdopen(artifact_descriptor, "rb", closefd=False) as stream:
                    payload = stream.read()
            finally:
                os.close(artifact_descriptor)
            if _sha256_bytes(payload) != digest:
                raise QualityPilotError("quality_artifact_hash_mismatch")
            entries.append(entry)
            previous = entry_digest
        return tuple(entries)

    def _ledger_entry(self, relative_path: str) -> dict[str, Any] | None:
        return next((entry for entry in self._read_ledger() if entry["relative_path"] == relative_path), None)

    def _kind_entry(self, kind: str) -> dict[str, Any] | None:
        return next((entry for entry in self._read_ledger() if entry["artifact_kind"] == kind), None)

    def _append_ledger(self, entry: Mapping[str, Any]) -> None:
        encoded = (canonical_json(dict(entry)) + "\n").encode("utf-8")
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(self.ledger_path, flags, 0o600)
        try:
            details = os.fstat(descriptor)
            if details.st_uid != os.getuid() or not stat.S_ISREG(details.st_mode):
                raise QualityPilotError("quality_artifact_ledger_unsafe")
            os.write(descriptor, encoded)
            os.fsync(descriptor)
            os.chmod(self.ledger_path, 0o600)
        finally:
            os.close(descriptor)

    def _write_immutable(
        self,
        relative_path: str,
        artifact_kind: str,
        value: Mapping[str, Any],
        *,
        selection_sha256: str,
        status: str = "written",
    ) -> ArtifactReceipt:
        relative = _safe_relative_path(relative_path)
        path = self.root / relative
        _ensure_private_directory(path.parent)
        encoded = (canonical_json(dict(value)) + "\n").encode("utf-8")
        digest = _sha256_bytes(encoded)
        existing_entry = self._ledger_entry(relative_path)
        if path.exists() or path.is_symlink():
            descriptor, _ = _private_file(path)
            try:
                with os.fdopen(descriptor, "rb", closefd=False) as stream:
                    existing = stream.read()
            finally:
                os.close(descriptor)
            if existing != encoded or existing_entry is None or existing_entry.get("sha256") != digest:
                raise QualityPilotError("quality_artifact_immutable_mismatch")
            return ArtifactReceipt(artifact_kind, relative_path, digest, selection_sha256, "existing")
        if existing_entry is not None:
            raise QualityPilotError("quality_artifact_ledger_path_collision")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags, 0o600)
        except FileExistsError as error:
            raise QualityPilotError("quality_artifact_immutable_race") from error
        try:
            details = os.fstat(descriptor)
            if details.st_uid != os.getuid() or not stat.S_ISREG(details.st_mode):
                raise QualityPilotError("quality_artifact_unsafe")
            os.write(descriptor, encoded)
            os.fsync(descriptor)
            os.chmod(path, 0o600)
        finally:
            os.close(descriptor)
        ledger = self._read_ledger()
        previous = ledger[-1]["entry_sha256"] if ledger else ""
        entry: dict[str, Any] = {
            "sequence": len(ledger) + 1,
            "artifact_kind": artifact_kind,
            "relative_path": relative_path,
            "sha256": digest,
            "previous_entry_sha256": previous,
        }
        entry["entry_sha256"] = _canonical_sha256(entry)
        self._append_ledger(entry)
        return ArtifactReceipt(artifact_kind, relative_path, digest, selection_sha256, status)

    def read_artifact(self, relative_path: str) -> dict[str, Any]:
        entry = self._ledger_entry(relative_path)
        if entry is None:
            raise QualityPilotError("quality_artifact_missing")
        path = self.root / _safe_relative_path(relative_path)
        descriptor, _ = _private_file(path)
        try:
            with os.fdopen(descriptor, "r", encoding="utf-8", closefd=False) as stream:
                value = json.load(stream)
        except json.JSONDecodeError as error:
            raise QualityPilotError("quality_artifact_invalid") from error
        finally:
            os.close(descriptor)
        if not isinstance(value, dict):
            raise QualityPilotError("quality_artifact_invalid")
        return value

    def _selection_document(self) -> dict[str, Any]:
        return self.read_artifact("selection.json")

    @staticmethod
    def _validate_packet(row: Mapping[str, Any], packet: Mapping[str, Any]) -> None:
        if packet.get("packet_id") != row.get("packet_id"):
            raise QualityPilotError("quality_reviewer_packet_id_mismatch")
        if (
            packet.get("artifact_id") != row.get("artifact_id")
            or packet.get("harness") != row.get("harness")
            or packet.get("source_version") != row.get("source_version")
        ):
            raise QualityPilotError("quality_reviewer_packet_identity_mismatch")
        event_ids = packet.get("event_ids")
        events = packet.get("events")
        if not isinstance(event_ids, list) or not isinstance(events, list):
            raise QualityPilotError("quality_reviewer_packet_shape_invalid")
        if set(event_ids) != set(row.get("event_ids", ())):
            raise QualityPilotError("quality_reviewer_packet_manifest_coverage_invalid")
        known = set(event_ids)
        for event in events:
            if not isinstance(event, Mapping):
                raise QualityPilotError("quality_reviewer_packet_shape_invalid")
            event_id = event.get("event_id")
            uri = event.get("evidence_uri")
            if not isinstance(event_id, str) or event_id not in known or not isinstance(uri, str) or not uri.endswith(f"#event={event_id}"):
                raise QualityPilotError("quality_reviewer_packet_evidence_invalid")

    def freeze_reference_set(
        self,
        selection: PilotSelection,
        packet_documents: Mapping[str, Mapping[str, Any]],
        reviewer_label_schema_path: Path,
    ) -> FrozenReferenceSet:
        """Write a reviewer-only packet set before any labels or results exist."""

        if selection.hard_blockers:
            raise QualityPilotBlocked(selection.hard_blockers[0])
        if len(selection.selected_packet_ids) != PILOT_PACKET_COUNT:
            raise QualityPilotBlocked("quality_reference_packet_count_invalid")
        if self._kind_entry("extractor_results") is not None:
            raise QualityPilotOrderError("extractor_results_already_written")
        try:
            schema_value = json.loads(Path(reviewer_label_schema_path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise QualityPilotError("quality_reviewer_label_schema_invalid") from error
        if not isinstance(schema_value, dict):
            raise QualityPilotError("quality_reviewer_label_schema_invalid")

        self._write_immutable("selection.json", "selection", selection.document, selection_sha256=selection.selection_sha256)
        schema_receipt = self._write_immutable(
            "reviewer-label-schema.json",
            "reviewer_label_schema",
            schema_value,
            selection_sha256=selection.selection_sha256,
        )
        packet_hashes: dict[str, str] = {}
        selected_by_id = {str(row["packet_id"]): row for row in selection.selected_rows}
        for packet_id in selection.selected_packet_ids:
            packet = packet_documents.get(packet_id)
            if not isinstance(packet, Mapping):
                raise QualityPilotError("quality_reviewer_packet_missing")
            self._validate_packet(selected_by_id[packet_id], packet)
            receipt = self._write_immutable(
                f"reviewer-packets/{packet_id}.json",
                "reviewer_packet",
                packet,
                selection_sha256=selection.selection_sha256,
            )
            packet_hashes[packet_id] = receipt.sha256
        index = {
            "schema_version": "quality-pilot-reference-set/v1",
            "selection_sha256": selection.selection_sha256,
            "reviewer_label_schema_sha256": schema_receipt.sha256,
            "packet_count": len(packet_hashes),
            "packet_sha256": dict(sorted(packet_hashes.items())),
        }
        index_receipt = self._write_immutable(
            "reviewer-index.json",
            "reference_set",
            index,
            selection_sha256=selection.selection_sha256,
        )
        self._write_immutable(
            "reference-set-receipt.json",
            "reference_set_receipt",
            {
                "schema_version": "quality-pilot-reference-receipt/v1",
                "selection_sha256": selection.selection_sha256,
                "reviewer_label_schema_sha256": schema_receipt.sha256,
                "reference_set_sha256": index_receipt.sha256,
                "creation_order_proof": "artifact-order.jsonl",
            },
            selection_sha256=selection.selection_sha256,
        )
        return FrozenReferenceSet(
            selection_sha256=selection.selection_sha256,
            reviewer_label_schema_sha256=schema_receipt.sha256,
            reference_set_sha256=index_receipt.sha256,
            packet_count=len(packet_hashes),
        )

    def _validate_labels(self, labels: Mapping[str, Any]) -> None:
        selection = self._selection_document()
        if labels.get("schema_version") != REVIEWER_LABEL_SCHEMA_VERSION or labels.get("selection_sha256") != selection.get("selection_sha256"):
            raise QualityPilotError("quality_reviewer_labels_binding_invalid")
        rows = labels.get("labels")
        selected = selection.get("selected")
        if not isinstance(rows, list) or not isinstance(selected, list):
            raise QualityPilotError("quality_reviewer_labels_invalid")
        expected_ids = {row.get("packet_id") for row in selected if isinstance(row, Mapping)}
        labels_by_id: dict[str, Mapping[str, Any]] = {}
        for row in rows:
            if not isinstance(row, Mapping) or not isinstance(row.get("packet_id"), str):
                raise QualityPilotError("quality_reviewer_labels_invalid")
            packet_id = str(row["packet_id"])
            if packet_id in labels_by_id or row.get("expected_outcome") not in {"learning", "no_learning"}:
                raise QualityPilotError("quality_reviewer_labels_invalid")
            labels_by_id[packet_id] = row
            topics = row.get("approved_topics")
            if not isinstance(topics, list) or not topics or any(topic not in TOPICS for topic in topics):
                raise QualityPilotError("quality_reviewer_labels_invalid")
            if any(row.get(name) not in {True, False} for name in ("requires_relevance", "requires_transferability", "baseline_novel", "non_harness_useful")):
                raise QualityPilotError("quality_reviewer_labels_invalid")
            approved = row.get("approved_data_evidence_uris")
            if not isinstance(approved, list) or any(not isinstance(uri, str) for uri in approved):
                raise QualityPilotError("quality_reviewer_labels_invalid")
            packet = self.read_artifact(f"reviewer-packets/{packet_id}.json")
            valid_uris = {
                event.get("evidence_uri") for event in packet.get("events", ())
                if isinstance(event, Mapping) and event.get("evidence_strength") == "observed"
            }
            if not set(approved).issubset(valid_uris):
                raise QualityPilotError("quality_reviewer_labels_evidence_invalid")
        if set(labels_by_id) != expected_ids:
            raise QualityPilotError("quality_reviewer_labels_coverage_invalid")

    def write_reviewer_labels(self, labels: Mapping[str, Any]) -> ArtifactReceipt:
        """Append the blind labels only while extractor output is absent."""

        if self._kind_entry("reference_set") is None or self._kind_entry("reviewer_label_schema") is None:
            raise QualityPilotOrderError("reference_set_required")
        if self._kind_entry("extractor_results") is not None:
            raise QualityPilotOrderError("extractor_results_already_written")
        self._validate_labels(labels)
        selection_sha256 = str(self._selection_document()["selection_sha256"])
        return self._write_immutable(
            "reviewer-labels.json",
            "reviewer_labels",
            labels,
            selection_sha256=selection_sha256,
        )

    def write_extractor_results(self, results: Mapping[str, Any]) -> ArtifactReceipt:
        """Accept a result artifact only after the immutable blind labels exist."""

        labels_entry = self._kind_entry("reviewer_labels")
        if labels_entry is None:
            raise QualityPilotOrderError("reviewer_labels_required")
        selection_sha256 = str(self._selection_document()["selection_sha256"])
        if (
            results.get("schema_version") != EXTRACTOR_RESULTS_SCHEMA_VERSION
            or results.get("selection_sha256") != selection_sha256
            or results.get("reviewer_labels_sha256") != labels_entry.get("sha256")
        ):
            raise QualityPilotError("quality_extractor_results_binding_invalid")
        documents = results.get("documents")
        if not isinstance(documents, list):
            raise QualityPilotError("quality_extractor_results_invalid")
        return self._write_immutable(
            "extractor-results.json",
            "extractor_results",
            results,
            selection_sha256=selection_sha256,
        )

    def write_gate_receipt(self, evaluation: QualityPilotEvaluation) -> ArtifactReceipt:
        """Persist the terminal U7 outcome after labels and results are immutable."""

        if self._kind_entry("reviewer_labels") is None or self._kind_entry("extractor_results") is None:
            raise QualityPilotOrderError("reviewer_labels_and_extractor_results_required")
        selection_sha256 = str(self._selection_document()["selection_sha256"])
        if evaluation.selection_sha256 != selection_sha256:
            raise QualityPilotError("quality_gate_selection_mismatch")
        return self._write_immutable(
            "pilot-gate-receipt.json",
            "pilot_gate",
            evaluation.document,
            selection_sha256=selection_sha256,
            status=evaluation.status,
        )

    def write_reduced_scope_selection_receipt(self, selection: PilotSelection) -> ArtifactReceipt:
        """Record a hard selector block without freezing reviewer material."""

        if not selection.hard_blockers:
            raise QualityPilotError("quality_reduced_scope_without_blocker")
        return self._write_immutable(
            "reduced-scope-selection-receipt.json",
            "reduced_scope_selection",
            {
                "schema_version": "quality-pilot-reduced-scope-receipt/v1",
                "status": "reduced_scope",
                "reasons": list(selection.hard_blockers),
                "blocked_units": ["U4", "U5", "U6"],
                "reviewer_packet": "not_frozen",
                "extractor_results": "not_started",
                "selection": selection.document,
            },
            selection_sha256=selection.selection_sha256,
            status="reduced_scope",
        )


def _token_set(value: object) -> set[str]:
    return set(re.findall(r"[a-z0-9_]+", str(value).casefold()))


def _candidate_is_relevant(candidate: Mapping[str, Any], label: Mapping[str, Any]) -> bool:
    if candidate.get("topic") not in set(label.get("approved_topics", ())):
        return False
    summary_tokens = _token_set(candidate.get("summary"))
    rationale_tokens = _token_set(candidate.get("transferability_rationale"))
    return (
        len(summary_tokens) >= 8
        and bool((summary_tokens | rationale_tokens) & _MARKETING_TERMS)
        and bool((summary_tokens | rationale_tokens) & _DECISION_TERMS)
    )


def _candidate_is_transferable(candidate: Mapping[str, Any]) -> bool:
    rationale_tokens = _token_set(candidate.get("transferability_rationale"))
    return (
        len(rationale_tokens) >= 12
        and bool(rationale_tokens & {"when", "if", "because"})
        and bool(rationale_tokens & _DECISION_TERMS)
        and bool(rationale_tokens & _MARKETING_TERMS)
    )


def _candidate_is_non_harness_useful(candidate: Mapping[str, Any]) -> bool:
    tokens = _token_set(candidate.get("summary")) | _token_set(candidate.get("transferability_rationale"))
    return not bool(tokens & _HARNESS_TERMS) or bool(tokens & _MARKETING_TERMS)


def _metric(numerator: int, denominator: int, threshold: float) -> dict[str, Any]:
    rate = 1.0 if denominator == 0 else numerator / denominator
    return {
        "numerator": numerator,
        "denominator": denominator,
        "rate": rate,
        "threshold": threshold,
        "passed": rate >= threshold,
    }


def _exact_candidate_identity(candidate: Mapping[str, Any]) -> str:
    identity = {
        key: value
        for key, value in candidate.items()
        if key not in {"candidate_id", "evidence_uris"}
    }
    return canonical_json(identity)


def _labels_by_packet(
    selection: PilotSelection,
    packet_documents: Mapping[str, Mapping[str, Any]],
    labels_document: Mapping[str, Any],
) -> dict[str, Mapping[str, Any]]:
    if labels_document.get("schema_version") != REVIEWER_LABEL_SCHEMA_VERSION or labels_document.get("selection_sha256") != selection.selection_sha256:
        raise QualityPilotError("quality_reviewer_labels_binding_invalid")
    labels = labels_document.get("labels")
    if not isinstance(labels, list):
        raise QualityPilotError("quality_reviewer_labels_invalid")
    by_packet: dict[str, Mapping[str, Any]] = {}
    for label in labels:
        if not isinstance(label, Mapping) or not isinstance(label.get("packet_id"), str):
            raise QualityPilotError("quality_reviewer_labels_invalid")
        packet_id = str(label["packet_id"])
        if packet_id in by_packet or label.get("expected_outcome") not in {"learning", "no_learning"}:
            raise QualityPilotError("quality_reviewer_labels_invalid")
        if not isinstance(label.get("approved_topics"), list) or any(topic not in TOPICS for topic in label["approved_topics"]):
            raise QualityPilotError("quality_reviewer_labels_invalid")
        if any(label.get(name) not in {True, False} for name in ("requires_relevance", "requires_transferability", "baseline_novel", "non_harness_useful")):
            raise QualityPilotError("quality_reviewer_labels_invalid")
        packet = packet_documents.get(packet_id)
        if not isinstance(packet, Mapping):
            raise QualityPilotError("quality_reviewer_packet_missing")
        observed_uris = {
            event.get("evidence_uri") for event in packet.get("events", ())
            if isinstance(event, Mapping) and event.get("evidence_strength") == "observed"
        }
        approved = label.get("approved_data_evidence_uris")
        if not isinstance(approved, list) or any(not isinstance(uri, str) for uri in approved) or not set(approved).issubset(observed_uris):
            raise QualityPilotError("quality_reviewer_labels_evidence_invalid")
        by_packet[packet_id] = label
    if set(by_packet) != set(selection.selected_packet_ids):
        raise QualityPilotError("quality_reviewer_labels_coverage_invalid")
    return by_packet


def evaluate_quality_pilot(
    selection: PilotSelection,
    packet_documents: Mapping[str, Mapping[str, Any]],
    labels_document: Mapping[str, Any],
    extractor_results: Mapping[str, Any],
) -> QualityPilotEvaluation:
    """Score frozen labels and extractor outputs without consulting raw sources."""

    labels = _labels_by_packet(selection, packet_documents, labels_document)
    if extractor_results.get("schema_version") != EXTRACTOR_RESULTS_SCHEMA_VERSION or extractor_results.get("selection_sha256") != selection.selection_sha256:
        raise QualityPilotError("quality_extractor_results_binding_invalid")
    documents = extractor_results.get("documents")
    if not isinstance(documents, list):
        raise QualityPilotError("quality_extractor_results_invalid")
    documents_by_packet: dict[str, Mapping[str, Any]] = {}
    for document in documents:
        if not isinstance(document, Mapping) or not isinstance(document.get("packet_id"), str):
            raise QualityPilotError("quality_extractor_results_invalid")
        packet_id = str(document["packet_id"])
        if packet_id in documents_by_packet:
            raise QualityPilotError("quality_extractor_results_duplicate_packet")
        documents_by_packet[packet_id] = document
    if set(documents_by_packet) != set(selection.selected_packet_ids):
        raise QualityPilotError("quality_extractor_results_coverage_invalid")

    expected_learning = 0
    relevance_numerator = 0
    relevance_denominator = 0
    transferability_numerator = 0
    transferability_denominator = 0
    novelty_numerator = 0
    novelty_denominator = 0
    no_learning_numerator = 0
    data_numerator = 0
    data_denominator = 0
    candidates_by_id: dict[str, Mapping[str, Any]] = {}
    for packet_id in selection.selected_packet_ids:
        packet = packet_documents.get(packet_id)
        if not isinstance(packet, Mapping):
            raise QualityPilotError("quality_reviewer_packet_missing")
        label = labels[packet_id]
        document = documents_by_packet[packet_id]
        validation = validate_candidate_document(document, packet)
        expected_no_learning = label["expected_outcome"] == "no_learning"
        predicted_no_learning = validation.accepted and validation.terminal_status == "no_learning"
        if predicted_no_learning == expected_no_learning:
            no_learning_numerator += 1
        for candidate in document.get("candidates", ()) if isinstance(document.get("candidates"), list) else ():
            if not isinstance(candidate, Mapping):
                continue
            candidate_id = candidate.get("candidate_id")
            if isinstance(candidate_id, str):
                candidates_by_id[candidate_id] = candidate
            if candidate.get("claim_label") == "[DATA]":
                data_denominator += 1
                approved_data = set(label["approved_data_evidence_uris"])
                candidate_uris = candidate.get("evidence_uris")
                if validation.accepted and isinstance(candidate_uris, list) and set(candidate_uris).issubset(approved_data):
                    data_numerator += 1
        if expected_no_learning:
            continue
        expected_learning += 1
        if bool(label["requires_relevance"]):
            relevance_denominator += 1
        if bool(label["requires_transferability"]):
            transferability_denominator += 1
        if bool(label["baseline_novel"]) and bool(label["non_harness_useful"]):
            novelty_denominator += 1
        relevant = False
        transferable = False
        novel_and_useful = False
        for candidate in document.get("candidates", ()) if isinstance(document.get("candidates"), list) else ():
            if not isinstance(candidate, Mapping):
                continue
            candidate_relevant = validation.accepted and _candidate_is_relevant(candidate, label)
            relevant = relevant or candidate_relevant
            transferable = transferable or (
                candidate_relevant
                and bool(label["requires_transferability"])
                and _candidate_is_transferable(candidate)
            )
            novel_and_useful = novel_and_useful or (
                candidate_relevant
                and bool(label["baseline_novel"])
                and bool(label["non_harness_useful"])
                and _candidate_is_non_harness_useful(candidate)
            )
        if relevant and bool(label["requires_relevance"]):
            relevance_numerator += 1
        if transferable:
            transferability_numerator += 1
        if novel_and_useful:
            novelty_numerator += 1

    false_exact_deduplications = 0
    deduplications = extractor_results.get("exact_deduplications", [])
    if not isinstance(deduplications, list):
        raise QualityPilotError("quality_exact_deduplication_invalid")
    for row in deduplications:
        if not isinstance(row, Mapping):
            false_exact_deduplications += 1
            continue
        retained = candidates_by_id.get(str(row.get("retained_candidate_id", "")))
        collapsed = candidates_by_id.get(str(row.get("collapsed_candidate_id", "")))
        if retained is None or collapsed is None or _exact_candidate_identity(retained) != _exact_candidate_identity(collapsed):
            false_exact_deduplications += 1

    metrics: dict[str, dict[str, Any]] = {
        "data_faithfulness": _metric(data_numerator, data_denominator, 1.0),
        "relevance": _metric(relevance_numerator, relevance_denominator, 0.8),
        "transferability": _metric(transferability_numerator, transferability_denominator, 0.7),
        "no_learning_accuracy": _metric(no_learning_numerator, len(selection.selected_packet_ids), 0.8),
        "novelty_non_harness_usefulness": _metric(novelty_numerator, novelty_denominator, 1.0),
        "false_exact_deduplication_collapses": {
            "count": false_exact_deduplications,
            "maximum": 0,
            "passed": false_exact_deduplications == 0,
        },
    }
    if selection.hard_blockers:
        metrics["selection_coverage"] = {
            "reasons": list(selection.hard_blockers),
            "passed": False,
        }
    failing_metrics = tuple(sorted(name for name, metric in metrics.items() if not metric["passed"]))
    status = "passed" if not failing_metrics else "reduced_scope"
    blocked_units = () if status == "passed" else ("U4", "U5", "U6")
    document = {
        "schema_version": "quality-pilot-gate-receipt/v1",
        "status": status,
        "selection_sha256": selection.selection_sha256,
        "metrics": metrics,
        "failing_metrics": list(failing_metrics),
        "blocked_units": list(blocked_units),
        "decision": "continue_to_u4" if status == "passed" else "delivered_reduced_scope",
    }
    return QualityPilotEvaluation(
        selection_sha256=selection.selection_sha256,
        status=status,
        metrics=metrics,
        failing_metrics=failing_metrics,
        blocked_units=blocked_units,
        document=document,
    )
