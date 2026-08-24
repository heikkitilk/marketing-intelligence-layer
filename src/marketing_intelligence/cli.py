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
from .normalize import normalize_census, write_normalization_private
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
    return message if message in known else "census_command_failed"


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
    arguments = parser.parse_args(argv)
    if arguments.command == "census":
        return _census_command(arguments)
    if arguments.command == "normalize":
        return _normalize_command(arguments)
    if arguments.command == "sessions":
        return _sessions_command(arguments)
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
