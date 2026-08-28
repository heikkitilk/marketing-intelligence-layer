"""Deterministic, no-egress routing for U3 session analysis.

This module turns U1 provenance and U2's already-redacted packet manifest into
small, immutable classification work.  It deliberately has no provider client:
U3 can prove coverage and resource bounds, but cannot send a packet anywhere.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from math import ceil
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any, Mapping, Sequence

from .census import canonical_json
from .checkpoint import CheckpointStore
from .estimate import (
    FULL_POC_LIMITS,
    ResourceEstimate,
    ResourceLimits,
    estimate_probe_resources,
    enforce_r25,
)
from .extraction import approved_packet_fields
from .normalize import _REPOSITORY_ROOT, _strict_private_root
from .redact import secure_write_text


MAX_PROVIDER_PACKET_BYTES = 100 * 1024
MAX_PROVIDER_PACKET_TOKENS = 32_000
BYTES_PER_TOKEN = 3
MAX_PROVIDER_INPUT_BYTES = min(MAX_PROVIDER_PACKET_BYTES, MAX_PROVIDER_PACKET_TOKENS * BYTES_PER_TOKEN)
COMPACT_CLASSIFICATION_BYTES = 4 * 1024
CLASSIFICATION_PROMPT_TOKENS = 800
CLASSIFICATION_OUTPUT_TOKENS = 800
CLASSIFICATION_CONCURRENCY = 2
CLASSIFICATION_PER_CALL_MINUTES = 20
FULL_EXTRACTION_PROMPT_TOKENS = 1_200
FULL_EXTRACTION_OUTPUT_TOKENS = 3_500
FULL_EXTRACTION_CONCURRENCY = 2
FULL_EXTRACTION_PER_CALL_MINUTES = 20

_PROVENANCE_FIELDS = (
    "harness",
    "group_anchor",
    "session_container_id",
    "parent_reference",
    "entry_point",
    "session_kind",
    "working_directory_category",
    "prompt_hash",
    "input_hash",
    "code_version",
    "configuration_version",
    "source_dataset",
    "injected_context_fingerprint",
)
_UNKNOWN = "?"


@dataclass(frozen=True)
class DependenceGroup:
    """One deterministic KTD7 group, derived from U1 rather than its label."""

    group_id: str
    harness: str
    session_kind: str
    provenance_sha256: str
    member_artifact_ids: tuple[str, ...]
    packet_ids: tuple[str, ...]
    representative_packet_id: str


@dataclass(frozen=True)
class SessionPreflight:
    """The complete no-egress classification plan for eligible U2 packets."""

    preflight_id: str
    groups: tuple[DependenceGroup, ...]
    classification_work_items: tuple[dict[str, Any], ...]
    classification_call_batches: tuple[dict[str, Any], ...]
    coverage: Mapping[str, int]
    resource_estimate: ResourceEstimate
    prompt_sha256: str
    policy_version: str
    source_manifest_sha256: str
    packet_manifest_sha256: str
    packet_documents: Mapping[str, Mapping[str, Any]] = field(repr=False, compare=False)


@dataclass(frozen=True)
class FullExtractionRoute:
    """A post-classification route; no provider dispatch is performed here."""

    extraction_work_items: tuple[dict[str, Any], ...]
    extraction_call_batches: tuple[dict[str, Any], ...]
    group_terminal_statuses: Mapping[str, str]
    resource_estimate: ResourceEstimate


@dataclass(frozen=True)
class PreflightOutput:
    """Local-only paths and hashes for a persisted U3 preflight."""

    root: Path
    run_directory: Path
    receipt_path: Path
    receipt_sha256: str
    release_plan_sha256: str
    created_work_items: int
    pending_work_items: int


def _sha256(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _nonempty_string(value: object, fallback: str = _UNKNOWN) -> str:
    return value.strip() if isinstance(value, str) and value.strip() else fallback


def _first_known_string(*values: object) -> str:
    """Return the first populated provenance value that is not U1 unknown."""

    for value in values:
        normalized = _nonempty_string(value)
        if normalized != _UNKNOWN:
            return normalized
    return _UNKNOWN


def _manifest_records(manifest_document: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    records = manifest_document.get("records")
    if not isinstance(records, list):
        raise ValueError("preflight_manifest_records_invalid")
    indexed: dict[str, Mapping[str, Any]] = {}
    for record in records:
        if not isinstance(record, Mapping):
            raise ValueError("preflight_manifest_record_invalid")
        artifact_id = record.get("artifact_id")
        if not isinstance(artifact_id, str) or not artifact_id.startswith("artifact-"):
            raise ValueError("preflight_manifest_artifact_invalid")
        if artifact_id in indexed:
            raise ValueError("preflight_manifest_duplicate_artifact")
        indexed[artifact_id] = record
    return indexed


def _packet_rows(packet_manifest_document: Mapping[str, Any]) -> tuple[Mapping[str, Any], ...]:
    rows = packet_manifest_document.get("packets")
    if not isinstance(rows, list):
        raise ValueError("preflight_packet_manifest_invalid")
    identifiers: set[str] = set()
    validated: list[Mapping[str, Any]] = []
    for row in rows:
        if not isinstance(row, Mapping):
            raise ValueError("preflight_packet_manifest_row_invalid")
        packet_id = row.get("packet_id")
        artifact_id = row.get("artifact_id")
        harness = row.get("harness")
        if (
            not isinstance(packet_id, str)
            or not packet_id.startswith("packet-")
            or not isinstance(artifact_id, str)
            or not artifact_id.startswith("artifact-")
            or harness not in {"codex", "claude"}
        ):
            raise ValueError("preflight_packet_manifest_identity_invalid")
        if packet_id in identifiers:
            raise ValueError("preflight_packet_manifest_duplicate_packet")
        identifiers.add(packet_id)
        validated.append(row)
    return tuple(validated)


def _provenance_identity(record: Mapping[str, Any]) -> tuple[dict[str, str], bool]:
    """Canonicalize U1 provenance and include the injected-context fingerprint.

    U1's declared ``dependence_group_id`` is intentionally not an input.  A
    record with no usable provenance becomes its own group, because merging it
    would be an unjustified dependence claim.
    """

    raw_fields = record.get("dependence_fields")
    fields = raw_fields if isinstance(raw_fields, Mapping) else {}
    classification = record.get("classification")
    execution_shape = classification.get("execution_shape") if isinstance(classification, Mapping) else {}
    observed_execution_kind = (
        execution_shape.get("value")
        if isinstance(execution_shape, Mapping) and execution_shape.get("provenance") == "observed"
        else _UNKNOWN
    )
    harness = _first_known_string(fields.get("harness"), record.get("harness"))
    session_kind = _first_known_string(record.get("session_kind"), fields.get("session_kind"), observed_execution_kind)
    parent_reference = _first_known_string(
        fields.get("parent_reference"),
        record.get("parent_logical_session_id"),
        record.get("parent_artifact_id"),
    )
    group_anchor = _first_known_string(
        fields.get("group_anchor"),
        fields.get("session_container_id"),
        record.get("logical_session_id"),
    )
    identity = {
        "harness": harness,
        "group_anchor": group_anchor,
        "session_container_id": _first_known_string(fields.get("session_container_id"), record.get("session_container_id")),
        "parent_reference": parent_reference,
        "entry_point": _first_known_string(fields.get("entry_point"), record.get("entry_point")),
        "session_kind": session_kind,
        "working_directory_category": _nonempty_string(fields.get("working_directory_category")),
        "prompt_hash": _nonempty_string(fields.get("prompt_hash")),
        "input_hash": _nonempty_string(fields.get("input_hash")),
        "code_version": _nonempty_string(fields.get("code_version")),
        "configuration_version": _nonempty_string(fields.get("configuration_version")),
        "source_dataset": _nonempty_string(fields.get("source_dataset")),
        "injected_context_fingerprint": _nonempty_string(fields.get("injected_context_fingerprint")),
    }
    usable = any(
        identity[field] != _UNKNOWN
        for field in _PROVENANCE_FIELDS
        if field not in {"harness", "session_kind"}
    )
    if not usable:
        artifact_id = record.get("artifact_id")
        if not isinstance(artifact_id, str):
            raise ValueError("preflight_manifest_artifact_invalid")
        identity["unknown_provenance_artifact"] = artifact_id
    return identity, usable


def _eligible_record_packet_rows(
    manifest_document: Mapping[str, Any],
    packet_manifest_document: Mapping[str, Any],
) -> tuple[tuple[Mapping[str, Any], Mapping[str, Any]], ...]:
    records = _manifest_records(manifest_document)
    eligible: list[tuple[Mapping[str, Any], Mapping[str, Any]]] = []
    for row in _packet_rows(packet_manifest_document):
        if row.get("terminal_outcome") != "prepared_no_egress":
            continue
        artifact_id = str(row["artifact_id"])
        record = records.get(artifact_id)
        if record is None:
            raise ValueError("preflight_packet_artifact_not_in_manifest")
        if record.get("terminal_status") != "complete" or record.get("in_window") is not True:
            raise ValueError("preflight_packet_not_eligible")
        if record.get("harness") != row.get("harness"):
            raise ValueError("preflight_packet_harness_mismatch")
        eligible.append((record, row))
    return tuple(eligible)


def build_dependence_groups(
    manifest_document: Mapping[str, Any],
    packet_manifest_document: Mapping[str, Any],
) -> tuple[DependenceGroup, ...]:
    """Account for every U2-prepared packet in a provenance-derived group."""

    grouped: dict[str, dict[str, Any]] = {}
    for record, packet_row in _eligible_record_packet_rows(manifest_document, packet_manifest_document):
        identity, _usable = _provenance_identity(record)
        provenance_sha256 = _sha256(identity)
        group_id = "dependence-" + provenance_sha256[:24]
        group = grouped.setdefault(
            group_id,
            {
                "identity": identity,
                "harness": identity["harness"],
                "session_kind": identity["session_kind"],
                "artifacts": [],
                "packets": [],
            },
        )
        if group["identity"] != identity:
            raise ValueError("preflight_dependence_hash_collision")
        artifact_id = str(record["artifact_id"])
        packet_id = str(packet_row["packet_id"])
        group["artifacts"].append(artifact_id)
        group["packets"].append(packet_id)

    result: list[DependenceGroup] = []
    for group_id, value in grouped.items():
        artifact_ids = tuple(sorted(set(value["artifacts"])))
        packet_ids = tuple(sorted(set(value["packets"])))
        if not artifact_ids or not packet_ids:
            raise ValueError("preflight_dependence_group_empty")
        result.append(
            DependenceGroup(
                group_id=group_id,
                harness=str(value["harness"]),
                session_kind=str(value["session_kind"]),
                provenance_sha256=group_id.removeprefix("dependence-"),
                member_artifact_ids=artifact_ids,
                packet_ids=packet_ids,
                representative_packet_id=packet_ids[0],
            )
        )
    return tuple(sorted(result, key=lambda group: group.group_id))


def _validated_packet_document(
    packet_id: str,
    row: Mapping[str, Any],
    packet_documents: Mapping[str, Mapping[str, Any]],
) -> Mapping[str, Any]:
    packet = packet_documents.get(packet_id)
    if not isinstance(packet, Mapping):
        raise ValueError("preflight_packet_document_missing")
    if packet.get("packet_id") != packet_id:
        raise ValueError("preflight_packet_document_identity_mismatch")
    for field in ("artifact_id", "harness", "source_version"):
        if packet.get(field) != row.get(field):
            raise ValueError("preflight_packet_document_manifest_mismatch")
    event_ids = packet.get("event_ids")
    events = packet.get("events")
    if not isinstance(event_ids, list) or not isinstance(events, list):
        raise ValueError("preflight_packet_document_shape_invalid")
    if tuple(event_ids) != tuple(row.get("event_ids", ())):
        raise ValueError("preflight_packet_document_event_coverage_mismatch")
    return packet


def _project_packet(packet: Mapping[str, Any], event_rows: Sequence[Mapping[str, Any]], event_ids: Sequence[str]) -> dict[str, Any]:
    """Select the only packet fields any later provider release may receive."""

    return {
        "packet_id": packet.get("packet_id"),
        "harness": packet.get("harness"),
        "source_version": packet.get("source_version"),
        "event_ids": list(event_ids),
        "events": [
            {
                key: event[key]
                for key in ("event_id", "evidence_uri", "evidence_strength", "role", "timestamp", "text")
                if key in event
            }
            for event in event_rows
        ],
    }


def _compact_packet(packet: Mapping[str, Any]) -> dict[str, Any]:
    """Build a deterministic bounded representative without omitting its group."""

    raw_events = packet.get("events")
    events = [event for event in raw_events if isinstance(event, Mapping)] if isinstance(raw_events, list) else []
    events = sorted(events, key=lambda event: str(event.get("event_id", "")))
    selected_events: list[Mapping[str, Any]] = []
    selected_ids: list[str] = []
    all_event_ids = [str(item) for item in packet.get("event_ids", ()) if isinstance(item, str)]
    for event in events:
        event_id = event.get("event_id")
        if not isinstance(event_id, str):
            continue
        candidate = _project_packet(packet, [*selected_events, event], [*selected_ids, event_id])
        if len(canonical_json(candidate).encode("utf-8")) <= COMPACT_CLASSIFICATION_BYTES:
            selected_events.append(event)
            selected_ids.append(event_id)
            continue
        text = event.get("text")
        if not selected_events and isinstance(text, str):
            low, high = 0, len(text)
            best = ""
            while low <= high:
                midpoint = (low + high) // 2
                shortened = {**event, "text": text[:midpoint]}
                candidate = _project_packet(packet, [shortened], [event_id])
                if len(canonical_json(candidate).encode("utf-8")) <= COMPACT_CLASSIFICATION_BYTES:
                    best = text[:midpoint]
                    low = midpoint + 1
                else:
                    high = midpoint - 1
            if best:
                selected_events.append({**event, "text": best})
                selected_ids.append(event_id)
        break
    compact = _project_packet(packet, selected_events, selected_ids)
    # Event-less packets still receive a classified work item. Their outcome
    # can explicitly be no-learning; silence must not turn into missing scope.
    if len(canonical_json(compact).encode("utf-8")) > COMPACT_CLASSIFICATION_BYTES:
        raise ValueError("classification_compact_packet_exceeds_cap")
    if len(selected_ids) < len(all_event_ids):
        compact["event_ids"] = selected_ids
    return compact


def _work_item_id(stage: str, identity: Mapping[str, Any]) -> str:
    return "work-" + _sha256({"stage": stage, **dict(identity)})[:24]


def _batch_items(items: Sequence[Mapping[str, Any]], *, stage: str) -> tuple[dict[str, Any], ...]:
    """Pack immutable group work below both KTD15 input constraints."""

    batches: list[dict[str, Any]] = []
    current_ids: list[str] = []
    current_bytes = 0
    for item in items:
        item_id = item.get("work_item_id")
        payload = item.get("analysis_packet")
        if not isinstance(item_id, str) or not isinstance(payload, Mapping):
            raise ValueError("analysis_work_item_invalid")
        item_bytes = len(canonical_json(payload).encode("utf-8"))
        if item_bytes > MAX_PROVIDER_INPUT_BYTES:
            raise ValueError(f"{stage}_packet_bytes_exceeds_ktd15_cap")
        if current_ids and current_bytes + item_bytes > MAX_PROVIDER_INPUT_BYTES:
            batches.append({
                "batch_id": "batch-" + _sha256({"stage": stage, "work_item_ids": current_ids})[:24],
                "stage": stage,
                "work_item_ids": tuple(current_ids),
                "analysis_packet_bytes": current_bytes,
            })
            current_ids = []
            current_bytes = 0
        current_ids.append(item_id)
        current_bytes += item_bytes
    if current_ids:
        batches.append({
            "batch_id": "batch-" + _sha256({"stage": stage, "work_item_ids": current_ids})[:24],
            "stage": stage,
            "work_item_ids": tuple(current_ids),
            "analysis_packet_bytes": current_bytes,
        })
    return tuple(batches)


def _estimate_batches(
    batches: Sequence[Mapping[str, Any]],
    *,
    prompt_tokens: int,
    output_tokens_per_call: int,
    concurrency: int,
    per_call_minutes: int,
) -> ResourceEstimate:
    return estimate_probe_resources(
        packet_bytes=[int(batch["analysis_packet_bytes"]) for batch in batches],
        prompt_tokens=prompt_tokens,
        output_tokens_per_call=output_tokens_per_call,
        calls=len(batches),
        concurrency=concurrency,
        per_call_minutes=per_call_minutes,
        bytes_per_token=BYTES_PER_TOKEN,
    )


def _combined_estimate(first: ResourceEstimate, second: ResourceEstimate) -> ResourceEstimate:
    """Use serial-stage wall time; this is conservative before any dispatch."""

    return ResourceEstimate(
        input_tokens=first.input_tokens + second.input_tokens,
        output_tokens=first.output_tokens + second.output_tokens,
        calls=first.calls + second.calls,
        wall_minutes=first.wall_minutes + second.wall_minutes,
        packet_bytes=first.packet_bytes + second.packet_bytes,
        prompt_tokens=first.prompt_tokens + second.prompt_tokens,
        retry_overhead_tokens=first.retry_overhead_tokens + second.retry_overhead_tokens,
        bytes_per_token=BYTES_PER_TOKEN,
        concurrency=min(first.concurrency, second.concurrency),
        per_call_minutes=max(first.per_call_minutes, second.per_call_minutes),
    )


def build_session_preflight(
    manifest_document: Mapping[str, Any],
    packet_manifest_document: Mapping[str, Any],
    packet_documents: Mapping[str, Mapping[str, Any]],
    *,
    prompt_sha256: str,
    policy_version: str,
    limits: ResourceLimits = FULL_POC_LIMITS,
) -> SessionPreflight:
    """Create a complete compact classification plan and enforce R25 first."""

    if not isinstance(prompt_sha256, str) or not prompt_sha256:
        raise ValueError("preflight_prompt_sha256_invalid")
    if not isinstance(policy_version, str) or not policy_version:
        raise ValueError("preflight_policy_version_invalid")
    groups = build_dependence_groups(manifest_document, packet_manifest_document)
    row_by_packet = {str(row["packet_id"]): row for row in _packet_rows(packet_manifest_document)}
    safe_packets: dict[str, Mapping[str, Any]] = {}
    items: list[dict[str, Any]] = []
    for group in groups:
        representative_id = group.representative_packet_id
        row = row_by_packet.get(representative_id)
        if row is None:
            raise ValueError("preflight_representative_not_in_packet_manifest")
        packet = _validated_packet_document(representative_id, row, packet_documents)
        safe_packets[representative_id] = packet
        compact_packet = _compact_packet(packet)
        item_identity = {
            "group_id": group.group_id,
            "packet_id": representative_id,
            "packet_sha256": _sha256(compact_packet),
            "prompt_sha256": prompt_sha256,
            "policy_version": policy_version,
        }
        items.append({
            "schema_version": "session-analysis-work-item/v1",
            "work_item_id": _work_item_id("classification", item_identity),
            "stage": "classification",
            "group_id": group.group_id,
            "packet_id": representative_id,
            "harness": group.harness,
            "session_kind": group.session_kind,
            "prompt_sha256": prompt_sha256,
            "policy_version": policy_version,
            "approved_fields": list(approved_packet_fields("classification")),
            "analysis_packet": compact_packet,
            "analysis_packet_sha256": item_identity["packet_sha256"],
            "analysis_packet_bytes": len(canonical_json(compact_packet).encode("utf-8")),
        })
    classification_items = tuple(sorted(items, key=lambda item: str(item["work_item_id"])))
    batches = _batch_items(classification_items, stage="classification")
    estimate = _estimate_batches(
        batches,
        prompt_tokens=CLASSIFICATION_PROMPT_TOKENS,
        output_tokens_per_call=CLASSIFICATION_OUTPUT_TOKENS,
        concurrency=CLASSIFICATION_CONCURRENCY,
        per_call_minutes=CLASSIFICATION_PER_CALL_MINUTES,
    )
    # This happens before a work item is persisted, and U3 has no dispatcher.
    enforce_r25(estimate, limits)
    source_manifest_sha256 = _sha256(manifest_document)
    packet_manifest_sha256 = _sha256(packet_manifest_document)
    preflight_id = "preflight-" + _sha256({
        "source_manifest_sha256": source_manifest_sha256,
        "packet_manifest_sha256": packet_manifest_sha256,
        "prompt_sha256": prompt_sha256,
        "policy_version": policy_version,
        "classification_work_item_ids": [item["work_item_id"] for item in classification_items],
    })[:24]
    prepared_rows = _eligible_record_packet_rows(manifest_document, packet_manifest_document)
    coverage = {
        "packet_manifest_packet_count": len(_packet_rows(packet_manifest_document)),
        "eligible_packet_count": len(prepared_rows),
        "eligible_group_count": len(groups),
        "classification_work_item_count": len(classification_items),
        "classification_call_count": len(batches),
        "unaccounted_group_count": len(groups) - len({str(item["group_id"]) for item in classification_items}),
    }
    # Validate every packet only after the compact route has accounted for it.
    for _record, row in prepared_rows:
        packet_id = str(row["packet_id"])
        safe_packets[packet_id] = _validated_packet_document(packet_id, row, packet_documents)
    if coverage["unaccounted_group_count"] != 0:
        raise ValueError("preflight_unaccounted_dependence_groups")
    return SessionPreflight(
        preflight_id=preflight_id,
        groups=groups,
        classification_work_items=classification_items,
        classification_call_batches=batches,
        coverage=coverage,
        resource_estimate=estimate,
        prompt_sha256=prompt_sha256,
        policy_version=policy_version,
        source_manifest_sha256=source_manifest_sha256,
        packet_manifest_sha256=packet_manifest_sha256,
        packet_documents=safe_packets,
    )


def _classification_label(value: object) -> str:
    if isinstance(value, str):
        label = value
    elif isinstance(value, Mapping):
        label = value.get("classification", value.get("result"))
    else:
        label = None
    if label not in {"marketing_bearing", "not_marketing", "mixed_work"}:
        raise ValueError("classification_result_invalid")
    return str(label)


def _split_full_packet(packet: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
    """Split only over U2 event boundaries so every selected packet is covered."""

    raw_events = packet.get("events")
    if not isinstance(raw_events, list):
        raise ValueError("full_extraction_packet_shape_invalid")
    chunks: list[dict[str, Any]] = []
    current_events: list[Mapping[str, Any]] = []
    current_ids: list[str] = []
    for raw_event in raw_events:
        if not isinstance(raw_event, Mapping) or not isinstance(raw_event.get("event_id"), str):
            raise ValueError("full_extraction_event_invalid")
        event_id = str(raw_event["event_id"])
        candidate = _project_packet(packet, [*current_events, raw_event], [*current_ids, event_id])
        if len(canonical_json(candidate).encode("utf-8")) <= MAX_PROVIDER_INPUT_BYTES:
            current_events.append(raw_event)
            current_ids.append(event_id)
            continue
        if not current_events:
            raise ValueError("full_extraction_event_exceeds_ktd15_cap")
        chunks.append(_project_packet(packet, current_events, current_ids))
        current_events = [raw_event]
        current_ids = [event_id]
        one_event = _project_packet(packet, current_events, current_ids)
        if len(canonical_json(one_event).encode("utf-8")) > MAX_PROVIDER_INPUT_BYTES:
            raise ValueError("full_extraction_event_exceeds_ktd15_cap")
    if current_events:
        chunks.append(_project_packet(packet, current_events, current_ids))
    if not chunks:
        chunks.append(_project_packet(packet, (), ()))
    return tuple(chunks)


def route_full_extraction_work(
    preflight: SessionPreflight,
    classifications: Mapping[str, object],
    *,
    mixed_sample_fraction: float = 0.05,
    representative_only: bool = False,
    limits: ResourceLimits = FULL_POC_LIMITS,
) -> FullExtractionRoute:
    """Route only positive groups plus a deterministic negative mixed sample."""

    if not 0 <= mixed_sample_fraction <= 1:
        raise ValueError("mixed_sample_fraction_invalid")
    known_group_ids = {group.group_id for group in preflight.groups}
    if set(classifications) != known_group_ids:
        raise ValueError("classification_coverage_incomplete")
    labels = {group_id: _classification_label(value) for group_id, value in classifications.items()}
    positives = {
        group_id
        for group_id, label in labels.items()
        if label in {"marketing_bearing", "mixed_work"}
    }
    negative_mixed = [
        group.group_id
        for group in preflight.groups
        if group.group_id not in positives and group.session_kind in {"mixed_work", "mixed"}
    ]
    sample_count = ceil(len(negative_mixed) * mixed_sample_fraction) if negative_mixed else 0
    sampled = set(
        sorted(
            negative_mixed,
            key=lambda group_id: _sha256({"preflight_id": preflight.preflight_id, "group_id": group_id}),
        )[:sample_count]
    )
    selected = positives | sampled
    items: list[dict[str, Any]] = []
    terminal_statuses: dict[str, str] = {}
    for group in preflight.groups:
        if group.group_id not in selected:
            terminal_statuses[group.group_id] = "group_rolled_up"
            continue
        terminal_statuses[group.group_id] = "extraction_pending"
        reason = "marketing_bearing" if group.group_id in positives else "mixed_negative_sample"
        packet_ids = (group.representative_packet_id,) if representative_only else group.packet_ids
        for packet_id in packet_ids:
            packet = preflight.packet_documents.get(packet_id)
            if not isinstance(packet, Mapping):
                raise ValueError("preflight_packet_document_missing")
            chunks = _split_full_packet(packet)
            for index, chunk in enumerate(chunks, start=1):
                identity = {
                    "group_id": group.group_id,
                    "packet_id": packet_id,
                    "packet_part": index,
                    "packet_part_count": len(chunks),
                    "packet_sha256": _sha256(chunk),
                    "prompt_sha256": preflight.prompt_sha256,
                    "policy_version": preflight.policy_version,
                    "selection_reason": reason,
                }
                items.append({
                    "schema_version": "session-analysis-work-item/v1",
                    "work_item_id": _work_item_id("full_extraction", identity),
                    "stage": "full_extraction",
                    "group_id": group.group_id,
                    "packet_id": packet_id,
                    "packet_part": index,
                    "packet_part_count": len(chunks),
                    "harness": group.harness,
                    "session_kind": group.session_kind,
                    "selection_reason": reason,
                    "prompt_sha256": preflight.prompt_sha256,
                    "policy_version": preflight.policy_version,
                    "approved_fields": list(approved_packet_fields("full_extraction")),
                    "analysis_packet": chunk,
                    "analysis_packet_sha256": identity["packet_sha256"],
                    "analysis_packet_bytes": len(canonical_json(chunk).encode("utf-8")),
                })
    full_items = tuple(sorted(items, key=lambda item: str(item["work_item_id"])))
    batches = _batch_items(full_items, stage="full_extraction")
    full_estimate = _estimate_batches(
        batches,
        prompt_tokens=FULL_EXTRACTION_PROMPT_TOKENS,
        output_tokens_per_call=FULL_EXTRACTION_OUTPUT_TOKENS,
        concurrency=FULL_EXTRACTION_CONCURRENCY,
        per_call_minutes=FULL_EXTRACTION_PER_CALL_MINUTES,
    )
    estimate = _combined_estimate(preflight.resource_estimate, full_estimate)
    enforce_r25(estimate, limits)
    return FullExtractionRoute(
        extraction_work_items=full_items,
        extraction_call_batches=batches,
        group_terminal_statuses=dict(sorted(terminal_statuses.items())),
        resource_estimate=estimate,
    )


def _immutable_private_json(path: Path, value: Mapping[str, Any], mismatch_error: str) -> None:
    """Write a non-ledger metadata file once, or prove an identical resume."""

    expected = canonical_json(dict(value)) + "\n"
    if path.exists() or path.is_symlink():
        details = os.lstat(path)
        if stat.S_ISLNK(details.st_mode) or not stat.S_ISREG(details.st_mode):
            raise ValueError("private_output_not_directory")
        if path.read_text(encoding="utf-8") != expected:
            raise ValueError(mismatch_error)
        return
    secure_write_text(path, expected)


def write_preflight_private(
    preflight: SessionPreflight,
    output_root: Path,
    *,
    repository_root: Path = _REPOSITORY_ROOT,
    require_ignored: bool = True,
) -> PreflightOutput:
    """Persist a resumable private plan without packet or candidate bodies."""

    root = _strict_private_root(Path(output_root), Path(repository_root), require_ignored)
    preflight_root = root / "preflight"
    CheckpointStore._ensure_private_directory(preflight_root)
    run_directory = preflight_root / preflight.preflight_id
    store = CheckpointStore(run_directory)
    created = sum(store.write_immutable_work_item(item) for item in preflight.classification_work_items)
    plan = {
        "schema_version": "session-analysis-preflight-plan/v1",
        "preflight_id": preflight.preflight_id,
        "classification_work_items": [
            {
                "work_item_id": item["work_item_id"],
                "group_id": item["group_id"],
                "packet_id": item["packet_id"],
                "analysis_packet_sha256": item["analysis_packet_sha256"],
            }
            for item in preflight.classification_work_items
        ],
        "classification_call_batches": [
            {
                "batch_id": batch["batch_id"],
                "work_item_ids": list(batch["work_item_ids"]),
                "analysis_packet_bytes": batch["analysis_packet_bytes"],
            }
            for batch in preflight.classification_call_batches
        ],
    }
    _immutable_private_json(run_directory / "work-plan.json", plan, "preflight_work_plan_immutable_mismatch")
    pending = store.pending_work_item_ids(preflight.classification_work_items)
    release_plan = {
        "schema_version": "session-analysis-release-plan/v1",
        "preflight_id": preflight.preflight_id,
        "mode": "blocked_pending_u7_quality",
        "provider_affinity": {
            "claude": {
                "provider": "anthropic",
                "account": "authenticated-first-party-claude",
                "cross_provider_fallback": "blocked",
            },
            "codex": {
                "provider": "openai",
                "account": "authenticated-first-party-codex",
                "cross_provider_fallback": "blocked",
            },
        },
        "release_requirements": [
            "account_verified",
            "model_verified",
            "prompt_sha256_match",
            "policy_version_match",
            "approved_field_contract_match",
            "raw_tools_empty",
            "encrypted_transport_verified",
        ],
        "classification_work_item_count": len(preflight.classification_work_items),
    }
    release_plan_sha256 = _sha256(release_plan)
    _immutable_private_json(
        run_directory / "release-plan.json",
        release_plan,
        "preflight_release_plan_immutable_mismatch",
    )
    receipt = {
        "schema_version": "session-analysis-preflight-receipt/v1",
        "preflight_id": preflight.preflight_id,
        "mode": "private_no_provider_egress",
        "provider_dispatch": "blocked_u7_quality_gate",
        "source_manifest_sha256": preflight.source_manifest_sha256,
        "packet_manifest_sha256": preflight.packet_manifest_sha256,
        "prompt_sha256": preflight.prompt_sha256,
        "policy_version": preflight.policy_version,
        "coverage": dict(sorted(preflight.coverage.items())),
        "resource_estimate": asdict(preflight.resource_estimate),
        "classification_work_item_count": len(preflight.classification_work_items),
        "pending_work_item_count": len(pending),
        "terminal_work_item_count": len(store.terminal_results()),
        "release_plan_sha256": release_plan_sha256,
    }
    receipt_sha256 = _sha256(receipt)
    _immutable_private_json(
        run_directory / "receipt.json",
        {"receipt_sha256": receipt_sha256, "receipt": receipt},
        "preflight_receipt_immutable_mismatch",
    )
    return PreflightOutput(
        root=root,
        run_directory=run_directory,
        receipt_path=run_directory / "receipt.json",
        receipt_sha256=receipt_sha256,
        release_plan_sha256=release_plan_sha256,
        created_work_items=created,
        pending_work_items=len(pending),
    )
