"""Command-line entry point for local, private census operations."""

from __future__ import annotations

import argparse
from dataclasses import replace
import hashlib
import json
from pathlib import Path
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
from .normalize import normalize_census, write_normalization_private


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
    arguments = parser.parse_args(argv)
    if arguments.command == "census":
        return _census_command(arguments)
    if arguments.command == "normalize":
        return _normalize_command(arguments)
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
