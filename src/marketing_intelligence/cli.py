"""Command-line entry point for local, private census operations."""

from __future__ import annotations

import argparse
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Mapping, Sequence

from .census import (
    _REPOSITORY_ROOT,
    UNKNOWN,
    canonical_json,
    load_census_config,
    parse_timestamp,
    scan_corpus,
    validate_schema_document,
    write_census_private,
)
from .estimate import ResourceBudgetExceeded
from .full_corpus import (
    FullCorpusError,
    finalize_full_corpus,
    load_full_corpus_input,
    prepare_full_corpus,
    route_extraction,
    run_batch,
)
from .normalize import normalize_census, write_normalization_private
from .quality import PilotArtifactStore, QualityPilotError, select_reference_packets
from .quality_execution import (
    QualityPilotExecutionError,
    build_quality_pilot_preflight,
    combine_and_score_quality_pilot,
    execute_claude_packet,
    ingest_provider_result,
    load_private_json_input,
    parse_quality_pilot_pricing,
    read_stdin_private_json,
    write_quality_pilot_preflight,
)
from .review import (
    HumanReviewError,
    build_publication,
    build_review_queue,
    write_publication_artifacts,
    write_review_artifacts,
)
from .routing import build_session_preflight, write_preflight_private


def _safe_reason(error: BaseException) -> str:
    """Do not surface source paths or transcript content through the CLI."""

    known = {
        "census_config_not_object",
        "census_config_source_roots_missing",
        "census_config_source_root_missing",
        "census_config_invalid_window",
        "census_config_invalid_estimator",
        "census_config_output_root_missing",
        "invalid_census_window",
        "private_output_outside_repository",
        "private_output_not_gitignored",
        "private_output_not_directory",
        "private_output_unsafe_owner",
        "normalization_manifest_invalid",
        "normalization_manifest_window_mismatch",
        "normalization_invalid_artifact",
        "normalization_invalid_harness",
        "normalization_invalid_source_version",
        "normalization_invalid_event_count",
        "normalization_invalid_packet_limit",
        "private_output_permissions_unsafe",
        "private_output_symlink",
        "normalization_run_exists",
        "preflight_manifest_records_invalid",
        "preflight_manifest_record_invalid",
        "preflight_manifest_artifact_invalid",
        "preflight_manifest_duplicate_artifact",
        "preflight_packet_manifest_invalid",
        "preflight_packet_manifest_row_invalid",
        "preflight_packet_manifest_identity_invalid",
        "preflight_packet_manifest_duplicate_packet",
        "preflight_packet_artifact_not_in_manifest",
        "preflight_packet_not_eligible",
        "preflight_packet_harness_mismatch",
        "preflight_packet_document_missing",
        "preflight_packet_document_identity_mismatch",
        "preflight_packet_document_manifest_mismatch",
        "preflight_packet_document_event_coverage_mismatch",
        "preflight_packet_document_shape_invalid",
        "preflight_prompt_sha256_invalid",
        "preflight_policy_version_invalid",
        "preflight_unaccounted_dependence_groups",
        "preflight_representative_not_in_packet_manifest",
        "preflight_work_plan_immutable_mismatch",
        "preflight_receipt_immutable_mismatch",
        "classification_compact_packet_exceeds_cap",
        "classification_packet_bytes_exceeds_ktd15_cap",
        "private_packet_root_invalid",
        "private_packet_file_invalid",
        "private_packet_file_missing",
        "private_packet_file_shape_invalid",
        "private_packet_file_unsafe",
    }
    message = str(error)
    safe_prefixes = (
        "quality_", "codex_packets_", "claude_packets_", "review_", "publication_",
        "full_corpus_",
    )
    return message if message in known or message.startswith(safe_prefixes) or message == "reviewer_required" else "census_command_failed"


def _private_safe_source_delta(first: object, second: object) -> dict[str, int]:
    """Describe cross-scan byte drift only as aggregate artifact counts."""

    first_hashes = getattr(first, "source_byte_sha256")
    second_hashes = getattr(second, "source_byte_sha256")
    first_ids = set(first_hashes)
    second_ids = set(second_hashes)
    common_ids = first_ids & second_ids
    changed_source_ids = {artifact_id for artifact_id in common_ids if first_hashes[artifact_id] != second_hashes[artifact_id]}

    def record_fingerprints(run: object) -> dict[str, str]:
        document = getattr(run, "manifest_document")
        records = document["records"]
        return {str(record["artifact_id"]): canonical_json(record) for record in records}

    first_records = record_fingerprints(first)
    second_records = record_fingerprints(second)
    first_record_ids = set(first_records)
    second_record_ids = set(second_records)
    common_record_ids = first_record_ids & second_record_ids
    changed_record_ids = {
        artifact_id
        for artifact_id in common_record_ids
        if first_records[artifact_id] != second_records[artifact_id]
    }
    return {
        "hashed_source_artifacts_first": len(first_ids),
        "hashed_source_artifacts_second": len(second_ids),
        "source_artifacts_added": len(second_ids - first_ids),
        "source_artifacts_removed": len(first_ids - second_ids),
        "source_artifacts_changed": len(changed_source_ids),
        "canonical_records_added": len(second_record_ids - first_record_ids),
        "canonical_records_removed": len(first_record_ids - second_record_ids),
        "canonical_records_changed": len(changed_record_ids),
        "source_changed_without_canonical_record_change": len(changed_source_ids - changed_record_ids),
    }


def _census_command(arguments: argparse.Namespace) -> int:
    try:
        config, output_root = load_census_config(arguments.config)
        if arguments.start or arguments.cutoff:
            start = parse_timestamp(arguments.start) if arguments.start else config.window_start
            cutoff = parse_timestamp(arguments.cutoff) if arguments.cutoff else config.cutoff
            if start is None or cutoff is None:
                raise ValueError("census_config_invalid_window")
            config = replace(config, window_start=start, cutoff=cutoff)
        if arguments.output_root:
            output_root = Path(arguments.output_root)
        result = scan_corpus(config)
        determinism = None
        if arguments.verify_determinism:
            repeated = scan_corpus(config)
            first_source_digest = hashlib.sha256(canonical_json(result.source_byte_sha256).encode("utf-8")).hexdigest()
            second_source_digest = hashlib.sha256(canonical_json(repeated.source_byte_sha256).encode("utf-8")).hexdigest()
            inputs_preserved = bool(result.source_integrity["read_only_input_preserved"]) and bool(repeated.source_integrity["read_only_input_preserved"])
            determinism = {
                "manifest_sha256_stable": result.manifest_sha256 == repeated.manifest_sha256,
                "coverage_sha256_stable": result.coverage_sha256 == repeated.coverage_sha256,
                # This proves the census did not alter either scan's opened
                # descriptors. It deliberately does not require an active
                # harness corpus to remain globally quiescent between scans.
                "input_bytes_unchanged_during_each_scan": inputs_preserved,
                "source_bytes_unchanged": inputs_preserved,
                "cross_scan_source_bytes_equal": result.source_byte_sha256 == repeated.source_byte_sha256,
                "first_source_changes_observed_during_scan": result.source_integrity["source_changes_observed_during_scan"],
                "second_source_changes_observed_during_scan": repeated.source_integrity["source_changes_observed_during_scan"],
                "source_delta": _private_safe_source_delta(result, repeated),
                "first_manifest_sha256": result.manifest_sha256,
                "second_manifest_sha256": repeated.manifest_sha256,
                "first_coverage_sha256": result.coverage_sha256,
                "second_coverage_sha256": repeated.coverage_sha256,
                "first_source_bytes_sha256": first_source_digest,
                "second_source_bytes_sha256": second_source_digest,
            }
            result = replace(
                repeated,
                receipt_document={**repeated.receipt_document, "determinism": determinism},
            )
        manifest_errors = validate_schema_document(
            result.manifest_document,
            _REPOSITORY_ROOT / "schemas" / "session-manifest.schema.json",
        )
        coverage_errors = validate_schema_document(
            result.coverage_document,
            _REPOSITORY_ROOT / "schemas" / "coverage-record.schema.json",
        )
        if manifest_errors or coverage_errors:
            print(canonical_json({
                "status": "schema_validation_failed",
                "manifest_errors": len(manifest_errors),
                "coverage_errors": len(coverage_errors),
            }))
            return 2
        output = write_census_private(result, output_root)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(canonical_json({"status": "failed", "reason": _safe_reason(error)}))
        return 2

    summary = result.summary
    print(canonical_json({
        "status": "accounted" if summary["zero_unaccounted"] else "coverage_incomplete",
        "scanned_artifacts": summary["scanned_artifacts"],
        "included": summary["included"],
        "excluded": summary["excluded"],
        "quarantined": summary["quarantined"],
        "failed": summary["failed"],
        "unaccounted_artifacts": summary["unaccounted_artifacts"],
        "by_harness": summary["by_harness"],
        "record_counters": result.observation_counters,
        "manifest_sha256": result.manifest_sha256,
        "coverage_sha256": result.coverage_sha256,
        "receipt_sha256": output.receipt_sha256,
        "resource_estimate": result.receipt_document["resource_estimate"],
        "source_integrity": result.source_integrity,
        "determinism": determinism or {
            "manifest_sha256_stable": UNKNOWN,
            "coverage_sha256_stable": UNKNOWN,
            "input_bytes_unchanged_during_each_scan": UNKNOWN,
            "source_bytes_unchanged": UNKNOWN,
        },
        "private_output": "written",
    }))
    deterministic = determinism is None or all(
        determinism[key]
        for key in ("manifest_sha256_stable", "coverage_sha256_stable", "source_bytes_unchanged")
    )
    return 0 if summary["zero_unaccounted"] and deterministic else 2


def _normalization_hashes(run: object) -> dict[str, str]:
    packets = list(getattr(run, "packets"))
    packet_manifest = getattr(run, "packet_manifest_document")
    coverage = getattr(run, "coverage_document")
    canonical_event_packet = {
        "packet_manifest": packet_manifest,
        "coverage": coverage,
        "packets": packets,
    }
    return {
        "packet_manifest_sha256": hashlib.sha256(canonical_json(packet_manifest).encode("utf-8")).hexdigest(),
        "coverage_sha256": hashlib.sha256(canonical_json(coverage).encode("utf-8")).hexdigest(),
        "packet_payloads_sha256": hashlib.sha256(canonical_json(packets).encode("utf-8")).hexdigest(),
        "canonical_event_packet_sha256": hashlib.sha256(canonical_json(canonical_event_packet).encode("utf-8")).hexdigest(),
        "receipt_sha256": hashlib.sha256(canonical_json(getattr(run, "receipt_document")).encode("utf-8")).hexdigest(),
    }


def _source_byte_delta(first: Mapping[str, str], second: Mapping[str, str]) -> dict[str, int]:
    """Summarize cross-pass raw-byte drift without exposing source identities."""

    first_ids = set(first)
    second_ids = set(second)
    shared_ids = first_ids & second_ids
    return {
        "first_opened_descriptors": len(first_ids),
        "second_opened_descriptors": len(second_ids),
        "changed_descriptor_count": sum(first[item] != second[item] for item in shared_ids),
        "first_only_descriptor_count": len(first_ids - second_ids),
        "second_only_descriptor_count": len(second_ids - first_ids),
    }


def _normalize_command(arguments: argparse.Namespace) -> int:
    """Build private U2 packets without exposing source text or paths."""

    try:
        config, _configured_output = load_census_config(arguments.config)
        with arguments.manifest.open("r", encoding="utf-8") as stream:
            manifest = json.load(stream)
        if not isinstance(manifest, dict):
            raise ValueError("normalization_manifest_invalid")
        result = normalize_census(manifest, config)
        determinism = {
            "packet_manifest_sha256_stable": UNKNOWN,
            "coverage_sha256_stable": UNKNOWN,
            "packet_payloads_sha256_stable": UNKNOWN,
            "canonical_event_packet_sha256_stable": UNKNOWN,
            "receipt_sha256_stable": UNKNOWN,
            "opened_descriptor_bytes_unchanged_during_each_run": bool(result.source_integrity["opened_descriptor_bytes_unchanged_during_read"]),
        }
        if arguments.verify_determinism:
            repeated = normalize_census(manifest, config)
            first_hashes = _normalization_hashes(result)
            second_hashes = _normalization_hashes(repeated)
            inputs_preserved = bool(result.source_integrity["opened_descriptor_bytes_unchanged_during_read"]) and bool(
                repeated.source_integrity["opened_descriptor_bytes_unchanged_during_read"]
            )
            determinism = {
                "packet_manifest_sha256_stable": first_hashes["packet_manifest_sha256"] == second_hashes["packet_manifest_sha256"],
                "coverage_sha256_stable": first_hashes["coverage_sha256"] == second_hashes["coverage_sha256"],
                "packet_payloads_sha256_stable": first_hashes["packet_payloads_sha256"] == second_hashes["packet_payloads_sha256"],
                "canonical_event_packet_sha256_stable": first_hashes["canonical_event_packet_sha256"] == second_hashes["canonical_event_packet_sha256"],
                # The receipt contains an observational raw-byte digest. It can
                # differ when an active harness appends post-cutoff data, even
                # though the fixed-window canonical evidence is deterministic.
                "receipt_sha256_stable": first_hashes["receipt_sha256"] == second_hashes["receipt_sha256"],
                "opened_descriptor_bytes_unchanged_during_each_run": inputs_preserved,
                "cross_pass_raw_source_bytes_equal": result.source_byte_sha256 == repeated.source_byte_sha256,
                "cross_pass_raw_source_byte_delta": _source_byte_delta(result.source_byte_sha256, repeated.source_byte_sha256),
                "first_packet_manifest_sha256": first_hashes["packet_manifest_sha256"],
                "second_packet_manifest_sha256": second_hashes["packet_manifest_sha256"],
                "first_coverage_sha256": first_hashes["coverage_sha256"],
                "second_coverage_sha256": second_hashes["coverage_sha256"],
                "first_packet_payloads_sha256": first_hashes["packet_payloads_sha256"],
                "second_packet_payloads_sha256": second_hashes["packet_payloads_sha256"],
                "first_canonical_event_packet_sha256": first_hashes["canonical_event_packet_sha256"],
                "second_canonical_event_packet_sha256": second_hashes["canonical_event_packet_sha256"],
                "first_opened_source_bytes_sha256": result.source_integrity["opened_source_bytes_sha256"],
                "second_opened_source_bytes_sha256": repeated.source_integrity["opened_source_bytes_sha256"],
            }
            result = replace(repeated, receipt_document={**repeated.receipt_document, "determinism": determinism})
        output = write_normalization_private(result, arguments.output_root)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(canonical_json({"status": "failed", "reason": _safe_reason(error)}))
        return 2

    summary = result.receipt_document["summary"]
    source_integrity = result.source_integrity
    deterministic = all(
        determinism[key] is True
        for key in (
            "packet_manifest_sha256_stable",
            "coverage_sha256_stable",
            "packet_payloads_sha256_stable",
            "canonical_event_packet_sha256_stable",
            "opened_descriptor_bytes_unchanged_during_each_run",
        )
    ) if arguments.verify_determinism else bool(source_integrity["opened_descriptor_bytes_unchanged_during_read"])
    status = "normalized" if summary["terminal_statuses"]["quarantined"] == 0 and summary["terminal_statuses"]["failed"] == 0 else "normalized_with_quarantines"
    print(canonical_json({
        "status": status,
        "artifact_count": summary["artifact_count"],
        "event_count": summary["event_count"],
        "packet_count": summary["packet_count"],
        "packet_bytes": summary["packet_bytes"],
        "reason_aggregates": summary["reason_aggregates"],
        "source_integrity": source_integrity,
        "coverage_complete": result.coverage_complete,
        "determinism": determinism,
        "resource_estimate": result.receipt_document["resource_estimate"],
        "receipt_sha256": output.receipt_sha256,
        "private_output": "written",
        "mode": "local_private_no_provider_egress",
    }))
    return 0 if result.coverage_complete and bool(source_integrity["opened_descriptor_bytes_unchanged_during_read"]) and deterministic else 2


def _load_json_mapping(path: Path, *, reason: str) -> dict[str, object]:
    """Read a local JSON metadata object without exposing its path in errors."""

    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(reason) from error
    if not isinstance(value, dict):
        raise ValueError(reason)
    return value


def _read_private_packet(path: Path) -> dict[str, object]:
    """Read one U2 packet through a no-follow regular-file boundary."""

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ValueError("private_packet_file_missing") from error
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode) or details.st_uid != os.getuid():
            raise ValueError("private_packet_file_unsafe")
        with os.fdopen(descriptor, "r", encoding="utf-8", closefd=False) as stream:
            value = json.load(stream)
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("private_packet_file_invalid") from error
    finally:
        os.close(descriptor)
    if not isinstance(value, dict):
        raise ValueError("private_packet_file_shape_invalid")
    return value


def _load_private_packet_documents(packet_manifest: Mapping[str, object], packet_root: Path) -> dict[str, dict[str, object]]:
    """Load only U2 prepared packets, never raw source transcripts."""

    candidate_root = Path(packet_root)
    try:
        details = os.lstat(candidate_root)
    except OSError as error:
        raise ValueError("private_packet_root_invalid") from error
    if stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode) or details.st_uid != os.getuid():
        raise ValueError("private_packet_root_invalid")
    rows = packet_manifest.get("packets")
    if not isinstance(rows, list):
        raise ValueError("preflight_packet_manifest_invalid")
    packets: dict[str, dict[str, object]] = {}
    for row in rows:
        if not isinstance(row, Mapping) or row.get("terminal_outcome") != "prepared_no_egress":
            continue
        packet_id = row.get("packet_id")
        if not isinstance(packet_id, str) or re.fullmatch(r"packet-[a-f0-9]{24}", packet_id) is None:
            raise ValueError("preflight_packet_manifest_identity_invalid")
        if packet_id in packets:
            raise ValueError("preflight_packet_manifest_duplicate_packet")
        packets[packet_id] = _read_private_packet(candidate_root / f"{packet_id}.json")
    return packets


def _sessions_policy_version(packet_manifest: Mapping[str, object]) -> str:
    """Bind a plan to both U2 redaction and injected-context policy versions."""

    policy = {
        "redaction_policy_version": packet_manifest.get("redaction_policy_version", "?"),
        "fingerprint_policy_version": packet_manifest.get("fingerprint_policy_version", "?"),
    }
    return hashlib.sha256(canonical_json(policy).encode("utf-8")).hexdigest()


def _sessions_command(arguments: argparse.Namespace) -> int:
    """Plan and checkpoint U3 classification work without provider egress."""

    try:
        manifest = _load_json_mapping(arguments.manifest, reason="preflight_manifest_records_invalid")
        packet_manifest = _load_json_mapping(arguments.packet_manifest, reason="preflight_packet_manifest_invalid")
        packet_documents = _load_private_packet_documents(packet_manifest, arguments.packet_root)
        prompt_text = (_REPOSITORY_ROOT / "prompts" / "session-analysis.md").read_text(encoding="utf-8")
        prompt_sha256 = hashlib.sha256(prompt_text.encode("utf-8")).hexdigest()
        preflight = build_session_preflight(
            manifest,
            packet_manifest,
            packet_documents,
            prompt_sha256=prompt_sha256,
            policy_version=_sessions_policy_version(packet_manifest),
        )
        output = write_preflight_private(preflight, arguments.output_root)
    except ResourceBudgetExceeded as error:
        print(canonical_json({
            "status": "reduced_scope_resource_envelope",
            "reason": "r25_pre_dispatch_cap",
            "dimension": error.dimension,
            "actual": error.actual,
            "limit": error.limit,
            "provider_dispatch": "not_started",
        }))
        return 2
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(canonical_json({"status": "failed", "reason": _safe_reason(error), "provider_dispatch": "not_started"}))
        return 2

    estimate = preflight.resource_estimate
    print(canonical_json({
        "status": "preflight_planned_no_provider_egress",
        "eligible_groups": preflight.coverage["eligible_group_count"],
        "classification_work_items": preflight.coverage["classification_work_item_count"],
        "classification_calls": preflight.coverage["classification_call_count"],
        "unaccounted_groups": preflight.coverage["unaccounted_group_count"],
        "estimated_input_tokens": estimate.input_tokens,
        "estimated_output_tokens": estimate.output_tokens,
        "estimated_calls": estimate.calls,
        "estimated_wall_minutes": estimate.wall_minutes,
        "estimated_monetary_cost_usd": estimate.monetary_cost_usd,
        "concurrency": estimate.concurrency,
        "per_call_minutes": estimate.per_call_minutes,
        "created_work_items": output.created_work_items,
        "pending_work_items": output.pending_work_items,
        "receipt_sha256": output.receipt_sha256,
        "release_plan_sha256": output.release_plan_sha256,
        "provider_dispatch": "blocked_u7_quality_gate",
        "mode": "private_no_provider_egress",
    }))
    return 0


def _quality_pilot_prepare_command(arguments: argparse.Namespace) -> int:
    """Freeze a U1-bound, unlabeled U7 reviewer packet, or receipt a hard sample block."""

    try:
        packet_manifest = _load_json_mapping(arguments.packet_manifest, reason="quality_packet_manifest_invalid")
        source_manifest = _load_json_mapping(arguments.source_manifest, reason="quality_source_manifest_invalid")
        packet_documents = _load_private_packet_documents(packet_manifest, arguments.packet_root)
        selection = select_reference_packets(packet_manifest, source_manifest, packet_documents)
        store = PilotArtifactStore(arguments.output_root, fresh=True)
        if selection.hard_blockers:
            receipt = store.write_reduced_scope_selection_receipt(selection)
            print(canonical_json({
                "status": "reduced_scope",
                "reasons": list(selection.hard_blockers),
                "blocked_units": ["U4", "U5", "U6"],
                "selection_sha256": selection.selection_sha256,
                "proposed_packet_count": len(selection.selected_packet_ids),
                "selected_stratum_counts": selection.document["selected_stratum_counts"],
                "absent_optional_strata": list(selection.absent_optional_strata),
                "absent_required_strata": list(selection.absent_required_strata),
                "metadata_absences": selection.document["metadata_absences"],
                "receipt_sha256": receipt.sha256,
                "reviewer_packet": "not_frozen",
                "provider_dispatch": "not_started",
            }))
            return 2
        packets = {
            packet_id: packet_documents[packet_id]
            for packet_id in selection.selected_packet_ids
        }
        frozen = store.freeze_reference_set(
            selection,
            packets,
            _REPOSITORY_ROOT / "schemas" / "quality-reviewer-label.schema.json",
        )
    except (OSError, ValueError, json.JSONDecodeError, QualityPilotError) as error:
        print(canonical_json({
            "status": "failed",
            "reason": _safe_reason(error),
            "provider_dispatch": "not_started",
        }))
        return 2

    print(canonical_json({
        "status": "reviewer_packet_frozen",
        "selection_sha256": selection.selection_sha256,
        "reference_set_sha256": frozen.reference_set_sha256,
        "selected_packet_count": frozen.packet_count,
        "selected_stratum_counts": selection.document["selected_stratum_counts"],
        "substitution_count": len(selection.substitutions),
        "absent_optional_strata": list(selection.absent_optional_strata),
        "absent_required_strata": list(selection.absent_required_strata),
        "metadata_absences": selection.document["metadata_absences"],
        "provider_dispatch": "not_started",
        "mode": "private_no_provider_egress",
    }))
    return 0


def _quality_private_input(arguments: argparse.Namespace) -> dict[str, object]:
    """Read a private stdin or mode-0600 input without printing its contents."""

    if getattr(arguments, "input_from_stdin", False):
        return read_stdin_private_json()
    return load_private_json_input(input_file=arguments.input_file)


def _quality_pilot_labels_command(arguments: argparse.Namespace) -> int:
    """Validate blind reviewer labels before their one immutable write."""

    try:
        labels = _quality_private_input(arguments)
        store = PilotArtifactStore(arguments.output_root)
        receipt = store.write_reviewer_labels(labels)
        label_rows = labels.get("labels")
        if not isinstance(label_rows, list):
            raise QualityPilotExecutionError("quality_reviewer_labels_invalid")
    except (OSError, ValueError, json.JSONDecodeError, QualityPilotError, QualityPilotExecutionError) as error:
        print(canonical_json({
            "status": "failed",
            "reason": _safe_reason(error),
            "provider_dispatch": "not_started",
        }))
        return 2

    print(canonical_json({
        "status": "reviewer_labels_written",
        "selection_sha256": receipt.selection_sha256,
        "reviewer_labels_sha256": receipt.sha256,
        "label_count": len(label_rows),
        "artifact_status": receipt.status,
        "provider_dispatch": "not_started",
        "mode": "private_no_provider_egress",
    }))
    return 0


def _quality_pilot_preflight_command(arguments: argparse.Namespace) -> int:
    """Project R25 usage for all frozen U7 packets before provider egress."""

    try:
        pricing = parse_quality_pilot_pricing(
            arguments.input_usd_per_million,
            arguments.output_usd_per_million,
        )
        store = PilotArtifactStore(arguments.output_root)
        preflight = build_quality_pilot_preflight(store, pricing=pricing)
        receipt = write_quality_pilot_preflight(store, preflight)
    except (OSError, ValueError, json.JSONDecodeError, QualityPilotError, QualityPilotExecutionError) as error:
        print(canonical_json({
            "status": "failed",
            "reason": _safe_reason(error),
            "provider_dispatch": "not_started",
        }))
        return 2

    estimate = preflight.resource_estimate
    result = {
        "status": "preflight_ready" if preflight.status == "ready" else "reduced_scope",
        "selection_sha256": preflight.selection.selection_sha256,
        "reviewer_labels_sha256": preflight.reviewer_labels_sha256,
        "packet_count": len(preflight.work_items),
        "projected_input_tokens": estimate.input_tokens,
        "projected_output_tokens": estimate.output_tokens,
        "projected_call_count": estimate.calls,
        "projected_concurrency": estimate.concurrency,
        "projected_wall_minutes": estimate.wall_minutes,
        "projected_monetary_cost_usd": estimate.monetary_cost_usd,
        "r25_failure": preflight.budget_failure,
        "blocked_units": ["U4", "U5", "U6"] if preflight.status != "ready" else [],
        "preflight_sha256": receipt.sha256,
        "provider_dispatch": "not_started",
        "mode": "private_no_provider_egress",
    }
    print(canonical_json(result))
    return 0 if preflight.status == "ready" else 2


def _quality_pilot_ingest_command(arguments: argparse.Namespace, *, harness: str) -> int:
    """Ingest one verified provider result without exposing its candidate body."""

    try:
        envelope = _quality_private_input(arguments)
        store = PilotArtifactStore(arguments.output_root)
        result = ingest_provider_result(store, envelope, expected_harness=harness)
    except (OSError, ValueError, json.JSONDecodeError, QualityPilotError, QualityPilotExecutionError) as error:
        print(canonical_json({
            "status": "failed",
            "reason": _safe_reason(error),
            "provider_dispatch": "not_started",
        }))
        return 2

    print(canonical_json({
        "status": "packet_result_staged",
        "packet_id": result.packet_id,
        "harness": result.harness,
        "terminal_status": result.terminal_status,
        "validation_error_count": len(result.validation_errors),
        "document_sha256": result.document_sha256,
        "artifact_status": result.receipt.status,
        "provider_dispatch": "not_started",
        "mode": "private_result_ingestion",
    }))
    return 0


def _quality_pilot_claude_extract_command(arguments: argparse.Namespace) -> int:
    """Use only the constrained first-party Claude CLI execution path."""

    try:
        release = load_private_json_input(input_file=arguments.release_file)
        store = PilotArtifactStore(arguments.output_root)
        result = execute_claude_packet(
            store,
            packet_id=arguments.packet_id,
            release=release,
        )
    except (OSError, ValueError, json.JSONDecodeError, QualityPilotError, QualityPilotExecutionError) as error:
        print(canonical_json({
            "status": "failed",
            "reason": _safe_reason(error),
            "provider_dispatch": "not_started_or_failed",
        }))
        return 2

    print(canonical_json({
        "status": "packet_result_staged",
        "packet_id": result.packet_id,
        "harness": result.harness,
        "terminal_status": result.terminal_status,
        "validation_error_count": len(result.validation_errors),
        "document_sha256": result.document_sha256,
        "artifact_status": result.receipt.status,
        "provider_dispatch": "completed_first_party_claude_cli",
        "mode": "private_result_ingestion",
    }))
    return 0


def _quality_pilot_combine_command(arguments: argparse.Namespace) -> int:
    """Write the one complete extractor artifact and its terminal U7 receipt."""

    try:
        store = PilotArtifactStore(arguments.output_root)
        combination = combine_and_score_quality_pilot(store)
    except (OSError, ValueError, json.JSONDecodeError, QualityPilotError, QualityPilotExecutionError) as error:
        print(canonical_json({
            "status": "failed",
            "reason": _safe_reason(error),
            "provider_dispatch": "not_started",
        }))
        return 2

    print(canonical_json({
        "status": combination.status,
        "extractor_results_sha256": combination.extractor_results_sha256,
        "pilot_gate_receipt_sha256": combination.gate_receipt_sha256,
        "failing_metrics": list(combination.failing_metrics),
        "blocked_units": list(combination.blocked_units),
        "provider_dispatch": "not_started",
        "mode": "private_immutable_quality_gate",
    }))
    return 0 if combination.status == "passed" else 2


def _review_prepare_command(arguments: argparse.Namespace) -> int:
    """Create a pending human-review workbench from a private value probe."""

    try:
        value_probe = load_private_json_input(input_file=arguments.value_probe_receipt)
        queue = build_review_queue(value_probe)
        paths = write_review_artifacts(queue, arguments.output_root)
    except (OSError, ValueError, json.JSONDecodeError, HumanReviewError, QualityPilotExecutionError) as error:
        print(canonical_json({"status": "failed", "reason": _safe_reason(error)}))
        return 2

    print(canonical_json({
        "status": "blocked_pending_human_review",
        "candidate_count": len(queue["candidates"]),
        "queue_sha256": queue["queue_sha256"],
        "review_page": str(paths["review.html"].relative_to(_REPOSITORY_ROOT)),
        "publication": "not_created",
        "mode": "private_offline_review",
    }))
    return 0


def _review_publish_command(arguments: argparse.Namespace) -> int:
    """Publish accepted intelligence from one complete human decision file."""

    try:
        queue = load_private_json_input(input_file=arguments.queue)
        decisions = load_private_json_input(input_file=arguments.decisions)
        publication = build_publication(queue, decisions)
        paths = write_publication_artifacts(publication, arguments.output_root)
    except (OSError, ValueError, json.JSONDecodeError, HumanReviewError, QualityPilotExecutionError) as error:
        print(canonical_json({"status": "failed", "reason": _safe_reason(error)}))
        return 2

    print(canonical_json({
        "status": "published_human_reviewed_intelligence",
        "accepted_learning_count": len(publication["learnings"]),
        "decision_counts": publication["decision_counts"],
        "publication_sha256": publication["publication_sha256"],
        "index_page": str(paths["index.html"].relative_to(_REPOSITORY_ROOT)),
        "mode": "private_offline_publication",
    }))
    return 0


def _full_corpus_prepare_command(arguments: argparse.Namespace) -> int:
    try:
        queue = load_private_json_input(input_file=arguments.queue)
        decisions = load_private_json_input(input_file=arguments.decisions)
        publication = load_private_json_input(input_file=arguments.publication)
        receipt = prepare_full_corpus(
            arguments.preflight_run,
            queue,
            decisions,
            publication,
            arguments.output_root,
        )
    except (OSError, ValueError, json.JSONDecodeError, HumanReviewError, FullCorpusError) as error:
        print(canonical_json({"status": "failed", "reason": _safe_reason(error), "provider_dispatch": "not_started"}))
        return 2
    print(canonical_json({**receipt, "provider_dispatch": "ready_human_calibrated"}))
    return 0


def _full_corpus_run_batch_command(arguments: argparse.Namespace) -> int:
    try:
        result = run_batch(
            arguments.output_root,
            arguments.batch_id,
            claude_model=arguments.claude_model,
            codex_model=arguments.codex_model,
            effort=arguments.effort,
            max_budget_usd=arguments.max_budget_usd,
            timeout_seconds=arguments.timeout_seconds,
        )
    except (OSError, ValueError, json.JSONDecodeError, FullCorpusError) as error:
        print(canonical_json({"status": "failed", "reason": _safe_reason(error), "provider_dispatch": "not_started_or_failed"}))
        return 2
    print(canonical_json({**result, "provider_dispatch": "completed_first_party_provider"}))
    return 0


def _full_corpus_route_command(arguments: argparse.Namespace) -> int:
    try:
        source_manifest = load_full_corpus_input(arguments.source_manifest)
        packet_manifest = load_full_corpus_input(arguments.packet_manifest)
        result = route_extraction(
            arguments.output_root,
            source_manifest,
            packet_manifest,
            arguments.packet_root,
            mixed_sample_fraction=arguments.mixed_sample_fraction,
        )
    except (OSError, ValueError, json.JSONDecodeError, FullCorpusError, ResourceBudgetExceeded) as error:
        print(canonical_json({"status": "failed", "reason": _safe_reason(error), "provider_dispatch": "not_started"}))
        return 2
    print(canonical_json({**result, "provider_dispatch": "ready_human_calibrated"}))
    return 0


def _full_corpus_finalize_command(arguments: argparse.Namespace) -> int:
    try:
        result = finalize_full_corpus(arguments.output_root, arguments.review_output_root)
    except (OSError, ValueError, json.JSONDecodeError, HumanReviewError, FullCorpusError) as error:
        print(canonical_json({"status": "failed", "reason": _safe_reason(error), "publication": "not_created"}))
        return 2
    print(canonical_json({**result, "publication": "not_created"}))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Run a no-egress census with explicitly configured local roots."""

    parser = argparse.ArgumentParser(description="Build a private cross-harness session census.")
    subcommands = parser.add_subparsers(dest="command", required=True)
    census = subcommands.add_parser("census", help="stream configured Codex and Claude JSONL roots")
    census.add_argument("--config", type=Path, required=True, help="local census configuration JSON")
    census.add_argument("--start", help="optional ISO 8601 window start, including an AMT offset")
    census.add_argument("--cutoff", help="optional ISO 8601 half-open cutoff, including an AMT offset")
    census.add_argument("--output-root", help="ignored private output root relative to this repository")
    census.add_argument("--verify-determinism", action="store_true", help="run the same fixed census twice before writing the receipt")
    normalize = subcommands.add_parser("normalize", help="normalize a U1 manifest into private redacted packets")
    normalize.add_argument("--config", type=Path, required=True, help="local census configuration JSON")
    normalize.add_argument("--manifest", type=Path, required=True, help="private U1 manifest JSON")
    normalize.add_argument("--output-root", type=Path, required=True, help="new ignored private output root")
    normalize.add_argument("--verify-determinism", action="store_true", help="run normalization twice before private packet write")
    sessions = subcommands.add_parser("sessions", help="plan U3 session classification from private U1 and U2 outputs")
    sessions.add_argument("--manifest", type=Path, required=True, help="private U1 manifest JSON")
    sessions.add_argument("--packet-manifest", type=Path, required=True, help="private U2 packet manifest JSON")
    sessions.add_argument("--packet-root", type=Path, required=True, help="private U2 redacted packet directory")
    sessions.add_argument("--output-root", type=Path, required=True, help="ignored private U3 preflight root")
    quality_pilot = subcommands.add_parser("quality-pilot", help="prepare or score the private U7 blind quality pilot")
    quality_commands = quality_pilot.add_subparsers(dest="quality_command", required=True)
    quality_prepare = quality_commands.add_parser("prepare", help="join U1/U2 metadata and freeze an unlabeled private reviewer packet")
    quality_prepare.add_argument("--source-manifest", type=Path, required=True, help="private U1 source manifest JSON")
    quality_prepare.add_argument("--packet-manifest", type=Path, required=True, help="private U2 packet manifest JSON")
    quality_prepare.add_argument("--packet-root", type=Path, required=True, help="private U2 redacted packet directory")
    quality_prepare.add_argument("--output-root", type=Path, required=True, help="fresh ignored private U7 output root")

    quality_labels = quality_commands.add_parser("labels", help="validate and immutably ingest blind reviewer labels")
    quality_labels.add_argument("--output-root", type=Path, required=True, help="existing ignored private U7 output root")
    quality_labels_input = quality_labels.add_mutually_exclusive_group(required=True)
    quality_labels_input.add_argument("--input-file", type=Path, help="mode-0600 private reviewer-label JSON file")
    quality_labels_input.add_argument("--stdin", dest="input_from_stdin", action="store_true", help="read the reviewer-label JSON document from stdin")

    quality_preflight = quality_commands.add_parser("preflight", help="estimate the frozen U7 extraction before provider egress")
    quality_preflight.add_argument("--output-root", type=Path, required=True, help="existing ignored private U7 output root")
    quality_preflight.add_argument("--input-usd-per-million", help="optional current provider input price in USD per million tokens")
    quality_preflight.add_argument("--output-usd-per-million", help="optional current provider output price in USD per million tokens")

    quality_ingest_codex = quality_commands.add_parser("ingest-codex-result", help="ingest one result from a verified first-party Codex seat")
    quality_ingest_codex.add_argument("--output-root", type=Path, required=True, help="existing ignored private U7 output root")
    quality_ingest_codex_input = quality_ingest_codex.add_mutually_exclusive_group(required=True)
    quality_ingest_codex_input.add_argument("--input-file", type=Path, help="mode-0600 private provider-result JSON file")
    quality_ingest_codex_input.add_argument("--stdin", dest="input_from_stdin", action="store_true", help="read the provider-result JSON document from stdin")

    quality_ingest_claude = quality_commands.add_parser("ingest-claude-result", help="ingest one result from the constrained first-party Claude CLI")
    quality_ingest_claude.add_argument("--output-root", type=Path, required=True, help="existing ignored private U7 output root")
    quality_ingest_claude_input = quality_ingest_claude.add_mutually_exclusive_group(required=True)
    quality_ingest_claude_input.add_argument("--input-file", type=Path, help="mode-0600 private provider-result JSON file")
    quality_ingest_claude_input.add_argument("--stdin", dest="input_from_stdin", action="store_true", help="read the provider-result JSON document from stdin")

    quality_claude_extract = quality_commands.add_parser("claude-extract", help="run one packet through the no-tools, no-persistence Claude CLI path")
    quality_claude_extract.add_argument("--output-root", type=Path, required=True, help="existing ignored private U7 output root")
    quality_claude_extract.add_argument("--packet-id", required=True, help="selected Claude packet identifier")
    quality_claude_extract.add_argument("--release-file", type=Path, required=True, help="mode-0600 private verified Claude release JSON file")

    quality_combine = quality_commands.add_parser("combine", help="combine all terminal U7 results and write the final immutable gate")
    quality_combine.add_argument("--output-root", type=Path, required=True, help="existing ignored private U7 output root")
    review = subcommands.add_parser("review", help="prepare human review or publish accepted intelligence")
    review_commands = review.add_subparsers(dest="review_command", required=True)
    review_prepare = review_commands.add_parser("prepare", help="create a private offline review page from a value-probe receipt")
    review_prepare.add_argument("--value-probe-receipt", type=Path, required=True, help="mode-0600 private value-probe receipt JSON")
    review_prepare.add_argument("--output-root", type=Path, required=True, help="ignored private human-review output root")
    review_publish = review_commands.add_parser("publish", help="publish only candidates with complete human decisions")
    review_publish.add_argument("--queue", type=Path, required=True, help="mode-0600 private review-queue JSON")
    review_publish.add_argument("--decisions", type=Path, required=True, help="mode-0600 exported human decisions JSON")
    review_publish.add_argument("--output-root", type=Path, required=True, help="ignored private accepted-intelligence output root")
    full_corpus = subcommands.add_parser("full-corpus", help="run human-calibrated full-corpus extraction")
    full_corpus_commands = full_corpus.add_subparsers(dest="full_corpus_command", required=True)
    full_corpus_prepare = full_corpus_commands.add_parser("prepare", help="bind human calibration and create classification batches")
    full_corpus_prepare.add_argument("--preflight-run", type=Path, required=True, help="existing private U3 preflight run directory")
    full_corpus_prepare.add_argument("--queue", type=Path, required=True, help="private reviewed value-probe queue")
    full_corpus_prepare.add_argument("--decisions", type=Path, required=True, help="private complete human decision ledger")
    full_corpus_prepare.add_argument("--publication", type=Path, required=True, help="private accepted value-probe intelligence")
    full_corpus_prepare.add_argument("--output-root", type=Path, required=True, help="fresh ignored private full-corpus root")
    full_corpus_run = full_corpus_commands.add_parser("run-batch", help="run one provider-affine classification or extraction batch")
    full_corpus_run.add_argument("--output-root", type=Path, required=True, help="existing ignored private full-corpus root")
    full_corpus_run.add_argument("--batch-id", required=True, help="immutable batch identifier")
    full_corpus_run.add_argument("--claude-model", default="claude-sonnet-5")
    full_corpus_run.add_argument("--codex-model", default="gpt-5.6-luna")
    full_corpus_run.add_argument("--effort", choices=("low", "medium", "high", "xhigh", "max"), default="high")
    full_corpus_run.add_argument("--max-budget-usd", type=float, default=8.0)
    full_corpus_run.add_argument("--timeout-seconds", type=int, default=1200)
    full_corpus_route = full_corpus_commands.add_parser("route", help="route classified groups into extraction batches")
    full_corpus_route.add_argument("--output-root", type=Path, required=True)
    full_corpus_route.add_argument("--source-manifest", type=Path, required=True)
    full_corpus_route.add_argument("--packet-manifest", type=Path, required=True)
    full_corpus_route.add_argument("--packet-root", type=Path, required=True)
    full_corpus_route.add_argument("--mixed-sample-fraction", type=float, default=0.05)
    full_corpus_finalize = full_corpus_commands.add_parser("finalize", help="create a pending review queue after complete extraction")
    full_corpus_finalize.add_argument("--output-root", type=Path, required=True)
    full_corpus_finalize.add_argument("--review-output-root", type=Path, required=True)
    arguments = parser.parse_args(argv)
    if arguments.command == "census":
        return _census_command(arguments)
    if arguments.command == "normalize":
        return _normalize_command(arguments)
    if arguments.command == "sessions":
        return _sessions_command(arguments)
    if arguments.command == "quality-pilot" and arguments.quality_command == "prepare":
        return _quality_pilot_prepare_command(arguments)
    if arguments.command == "quality-pilot" and arguments.quality_command == "labels":
        return _quality_pilot_labels_command(arguments)
    if arguments.command == "quality-pilot" and arguments.quality_command == "preflight":
        return _quality_pilot_preflight_command(arguments)
    if arguments.command == "quality-pilot" and arguments.quality_command == "ingest-codex-result":
        return _quality_pilot_ingest_command(arguments, harness="codex")
    if arguments.command == "quality-pilot" and arguments.quality_command == "ingest-claude-result":
        return _quality_pilot_ingest_command(arguments, harness="claude")
    if arguments.command == "quality-pilot" and arguments.quality_command == "claude-extract":
        return _quality_pilot_claude_extract_command(arguments)
    if arguments.command == "quality-pilot" and arguments.quality_command == "combine":
        return _quality_pilot_combine_command(arguments)
    if arguments.command == "review" and arguments.review_command == "prepare":
        return _review_prepare_command(arguments)
    if arguments.command == "review" and arguments.review_command == "publish":
        return _review_publish_command(arguments)
    if arguments.command == "full-corpus" and arguments.full_corpus_command == "prepare":
        return _full_corpus_prepare_command(arguments)
    if arguments.command == "full-corpus" and arguments.full_corpus_command == "run-batch":
        return _full_corpus_run_batch_command(arguments)
    if arguments.command == "full-corpus" and arguments.full_corpus_command == "route":
        return _full_corpus_route_command(arguments)
    if arguments.command == "full-corpus" and arguments.full_corpus_command == "finalize":
        return _full_corpus_finalize_command(arguments)
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
