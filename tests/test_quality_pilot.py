"""Contract tests for the U7 blind extraction-quality pilot."""

from __future__ import annotations

import itertools
import json
import contextlib
import io
import hashlib
from pathlib import Path
import tempfile
import unittest

from marketing_intelligence.census import canonical_json
from marketing_intelligence.cli import main
from marketing_intelligence.extraction import stable_candidate_id
from marketing_intelligence.quality import (
    PilotArtifactStore,
    QualityPilotError,
    QualityPilotOrderError,
    evaluate_quality_pilot,
    select_reference_packets,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "quality"


def packet_row(
    ordinal: int,
    *,
    harness: str,
    execution_kind: str,
    artifact_role: str,
    learning_expectation: str,
    workload_class: str = "mixed_work",
) -> dict[str, object]:
    token = f"{ordinal:024x}"
    return {
        "packet_id": f"packet-{token}",
        "artifact_id": f"artifact-{token}",
        "harness": harness,
        "source_version": "a" * 64,
        "event_ids": [f"event-{token[:-2]}01"],
        "terminal_outcome": "prepared_no_egress",
        "execution_kind": execution_kind,
        "artifact_role": artifact_role,
        "learning_expectation": learning_expectation,
        "workload_class": workload_class,
    }


def packet_document(row: dict[str, object], *, event_count: int = 1) -> dict[str, object]:
    packet_id = str(row["packet_id"])
    artifact_id = str(row["artifact_id"])
    harness = str(row["harness"])
    source_version = str(row["source_version"])
    event_ids = [f"event-{packet_id.removeprefix('packet-')[:-2]}{index:02x}" for index in range(1, event_count + 1)]
    prelabel_text = (
        "Marketing campaign audience paid conversion revenue budget decision action."
        if row.get("learning_expectation") == "likely_learning"
        else "Agent harness SDK fixture token and tool details."
    )
    return {
        "schema_version": "session-packet/v1",
        "packet_id": packet_id,
        "artifact_id": artifact_id,
        "harness": harness,
        "source_version": source_version,
        "event_ids": event_ids,
        "events": [
            {
                "event_id": event_id,
                "evidence_uri": f"session://{harness}/{artifact_id}@{source_version}#event={event_id}",
                "evidence_strength": "observed",
                "role": "tool_result",
                "timestamp": "2026-08-24T14:00:00Z",
                "text": prelabel_text,
            }
            for index, event_id in enumerate(event_ids, start=1)
        ],
    }


def rich_rows() -> list[dict[str, object]]:
    rows = []
    for ordinal, values in enumerate(
        itertools.product(
            ("claude", "codex"),
            ("interactive", "sdk"),
            ("root", "child"),
            ("likely_learning", "no_learning"),
        ),
        start=1,
    ):
        rows.append(packet_row(ordinal, harness=values[0], execution_kind=values[1], artifact_role=values[2], learning_expectation=values[3]))
        rows.append(packet_row(ordinal + 100, harness=values[0], execution_kind=values[1], artifact_role=values[2], learning_expectation=values[3]))
    return rows


def packet_documents(rows: list[dict[str, object]]) -> dict[str, dict[str, object]]:
    return {str(row["packet_id"]): packet_document(row) for row in rows}


def u1_source_manifest(rows: list[dict[str, object]]) -> dict[str, object]:
    """Build only the safe U1 fields that U7 may use for selector metadata."""

    records = []
    for index, row in enumerate(rows):
        artifact_id = str(row["artifact_id"])
        artifact_role = str(row["artifact_role"])
        execution_kind = str(row["execution_kind"])
        workload_class = "documents" if index % 2 else "other"
        records.append({
            "artifact_id": artifact_id,
            "harness": row["harness"],
            "logical_session_id": f"session-{index}",
            "session_container_id": f"container-{index}",
            "parent_logical_session_id": "?" if artifact_role == "root" else "root-session",
            "parent_artifact_id": "?" if artifact_role == "root" else "artifact-000000000000000000000001",
            "sidechain": False,
            "source_kind": "root_conversation" if artifact_role == "root" else "child_agent",
            "entry_point": "fixture",
            "session_kind": execution_kind,
            "classification": {
                "execution_shape": {
                    "value": execution_kind,
                    "provenance": "observed",
                    "rule": "fixture_execution_shape",
                },
                "working_directory": {
                    "value": workload_class,
                    "provenance": "inferred",
                    "rule": "fixture_working_directory",
                },
            },
            "dependence_group_id": f"dependence-{index:024x}",
            "dependence_fields": {
                "harness": row["harness"],
                "group_anchor": f"group-{index}",
                "session_container_id": f"container-{index}",
                "parent_reference": "?",
                "entry_point": "fixture",
                "session_kind": execution_kind,
                "working_directory_category": workload_class,
                "prompt_hash": "?",
                "input_hash": "?",
                "code_version": "?",
                "configuration_version": "?",
                "source_dataset": "?",
                "injected_context_fingerprint": "?",
            },
            "in_window_canonical_bytes": 10,
            "in_window_event_count": 1,
            "first_in_window_timestamp": "2026-08-24T14:00:00Z",
            "last_in_window_timestamp": "2026-08-24T14:00:00Z",
            "content_sha256": row["source_version"],
            "terminal_status": "complete",
            "reason": "included",
            "in_window": True,
        })
    return {
        "schema_version": "session-manifest/v1",
        "window": {"start": "2026-08-17T00:00:00Z", "cutoff": "2026-08-25T00:00:00Z"},
        "records": records,
        "summary": {"fixture": True},
    }


def u2_packet_manifest(rows: list[dict[str, object]], source_manifest: dict[str, object]) -> dict[str, object]:
    """Make a U2-shaped manifest that intentionally lacks U7 selector metadata."""

    source_manifest_sha256 = hashlib.sha256(canonical_json(source_manifest).encode("utf-8")).hexdigest()
    return {
        "schema_version": "normalization-packet-manifest/v1",
        "source_manifest_sha256": source_manifest_sha256,
        "packets": [
            {
                key: row[key]
                for key in ("packet_id", "artifact_id", "harness", "source_version", "event_ids", "terminal_outcome")
            }
            for row in rows
        ],
    }


def fixture_selection(rows: list[dict[str, object]]) -> object:
    source_manifest = u1_source_manifest(rows)
    return select_reference_packets(
        u2_packet_manifest(rows, source_manifest),
        source_manifest,
        packet_documents(rows),
    )


def label_document(selection: object, packets: dict[str, dict[str, object]]) -> dict[str, object]:
    selected_ids = getattr(selection, "selected_packet_ids")
    labels = []
    for packet_id in selected_ids:
        packet = packets[packet_id]
        labels.append({
            "packet_id": packet_id,
            "expected_outcome": "learning",
            "approved_data_evidence_uris": [packet["events"][0]["evidence_uri"]],
            "approved_topics": ["paid_advertising"],
            "requires_relevance": True,
            "requires_transferability": True,
            "baseline_novel": True,
            "non_harness_useful": True,
        })
    return {
        "schema_version": "quality-reviewer-labels/v1",
        "selection_sha256": getattr(selection, "selection_sha256"),
        "labels": labels,
    }


def candidate_document(
    packet: dict[str, object],
    *,
    summary: str = "Observed paid campaign conversion evidence supports reallocating budget to the winning audience.",
    rationale: str = "When a paid campaign exposes the same conversion pattern, marketing teams can reallocate spend and preserve the observed decision rule.",
    evidence_uri: str | None = None,
) -> dict[str, object]:
    candidate = {
        "candidate_id": "candidate-" + "0" * 24,
        "topic": "paid_advertising",
        "learning_type": "finding",
        "claim_label": "[DATA]",
        "summary": summary,
        "transferability_rationale": rationale,
        "confidence": "medium",
        "session_kind": "interactive",
        "evidence_uris": [evidence_uri or packet["events"][0]["evidence_uri"]],
    }
    candidate["candidate_id"] = stable_candidate_id(str(packet["packet_id"]), candidate)
    return {
        "schema_version": "candidate-learning/v1",
        "result_type": "candidates",
        "packet_id": packet["packet_id"],
        "candidates": [candidate],
    }


def extractor_results(
    selection: object,
    packets: dict[str, dict[str, object]],
    *,
    documents: list[dict[str, object]] | None = None,
    exact_deduplications: list[dict[str, str]] | None = None,
    reviewer_labels_sha256: str = "labels-sha",
) -> dict[str, object]:
    return {
        "schema_version": "quality-extractor-results/v1",
        "selection_sha256": getattr(selection, "selection_sha256"),
        "reviewer_labels_sha256": reviewer_labels_sha256,
        "documents": documents or [candidate_document(packets[packet_id]) for packet_id in getattr(selection, "selected_packet_ids")],
        "exact_deduplications": exact_deduplications or [],
    }


class PilotSelectionTests(unittest.TestCase):
    def test_selector_joins_u1_metadata_and_prelabels_redacted_packet_text(self) -> None:
        rows = rich_rows()
        source_manifest = u1_source_manifest(rows)
        packet_manifest = u2_packet_manifest(rows, source_manifest)
        packets = packet_documents(rows)
        for index, packet_id in enumerate(sorted(packets)):
            packets[packet_id]["events"][0]["text"] = (
                "Marketing campaign audience paid conversion revenue budget decision action."
                if index % 2
                else "Agent harness SDK fixture token and tool details."
            )

        selection = select_reference_packets(packet_manifest, source_manifest, packets)

        self.assertEqual(len(selection.selected_packet_ids), 24)
        self.assertEqual(len(set(selection.selected_packet_ids)), 24)
        self.assertEqual(selection.hard_blockers, ())
        self.assertEqual({row["harness"] for row in selection.selected_rows}, {"claude", "codex"})
        self.assertEqual({row["execution_kind"] for row in selection.selected_rows}, {"interactive", "sdk"})
        self.assertEqual({row["artifact_role"] for row in selection.selected_rows}, {"root", "child"})
        self.assertEqual(
            {row["learning_expectation"] for row in selection.selected_rows},
            {"likely_learning", "no_learning"},
        )
        self.assertTrue(all(row["execution_kind_provenance"] == "observed" for row in selection.selected_rows))
        self.assertTrue(all(row["artifact_role_provenance"] == "u1_source_kind" for row in selection.selected_rows))
        self.assertTrue(all(row["learning_expectation_provenance"] == "redacted_packet_heuristic_v1" for row in selection.selected_rows))
        self.assertEqual(selection.document["source_manifest_sha256"], packet_manifest["source_manifest_sha256"])

    def test_selector_is_deterministic_and_covers_observed_strata(self) -> None:
        rows = rich_rows()
        source_manifest = u1_source_manifest(rows)
        packets = packet_documents(rows)

        first = select_reference_packets(u2_packet_manifest(rows, source_manifest), source_manifest, packets)
        second = select_reference_packets(u2_packet_manifest(list(reversed(rows)), source_manifest), source_manifest, packets)

        self.assertEqual(len(first.selected_packet_ids), 24)
        self.assertEqual(first.selected_packet_ids, second.selected_packet_ids)
        self.assertEqual(first.selection_sha256, second.selection_sha256)
        self.assertIn("mixed_work", first.absent_optional_strata)
        self.assertTrue(first.substitutions)
        self.assertTrue(all(set(row["mismatched_dimensions"]) <= {"workload_class"} for row in first.substitutions))
        self.assertEqual(
            {row["harness"] for row in first.selected_rows},
            {"claude", "codex"},
        )
        self.assertEqual(
            {row["execution_kind"] for row in first.selected_rows},
            {"interactive", "sdk"},
        )
        self.assertEqual(
            {row["artifact_role"] for row in first.selected_rows},
            {"root", "child"},
        )

    def test_selector_fails_closed_on_a_u1_harness_mismatch(self) -> None:
        rows = rich_rows()
        source_manifest = u1_source_manifest(rows)
        source_manifest["records"][0]["harness"] = "codex"

        with self.assertRaisesRegex(QualityPilotError, "quality_source_manifest_harness_mismatch"):
            select_reference_packets(
                u2_packet_manifest(rows, source_manifest),
                source_manifest,
                packet_documents(rows),
            )

    def test_selector_records_absent_mixed_work_and_harness_without_inventing_coverage(self) -> None:
        rows = [
            packet_row(
                ordinal,
                harness="claude",
                execution_kind="interactive",
                artifact_role="root",
                learning_expectation="likely_learning",
                workload_class="other_work",
            )
            for ordinal in range(1, 30)
        ]

        selection = fixture_selection(rows)

        self.assertIn("codex_packets_absent", selection.hard_blockers)
        self.assertIn("mixed_work", selection.absent_optional_strata)
        self.assertTrue(selection.substitutions)
        self.assertEqual({row["harness"] for row in selection.selected_rows}, {"claude"})


class PilotArtifactOrderTests(unittest.TestCase):
    def test_prepare_cli_exercises_the_frozen_reviewer_packet_path(self) -> None:
        rows = rich_rows()
        packets = packet_documents(rows)
        source_manifest = u1_source_manifest(rows)
        packet_manifest = u2_packet_manifest(rows, source_manifest)
        private_parent = ROOT / ".u8-private"
        with tempfile.TemporaryDirectory(dir=private_parent) as temporary:
            temporary_path = Path(temporary)
            manifest_path = temporary_path / "packet-manifest.json"
            source_manifest_path = temporary_path / "source-manifest.json"
            packet_root = temporary_path / "packets"
            packet_root.mkdir()
            manifest_path.write_text(json.dumps(packet_manifest), encoding="utf-8")
            source_manifest_path.write_text(json.dumps(source_manifest), encoding="utf-8")
            for packet_id, packet in packets.items():
                (packet_root / f"{packet_id}.json").write_text(json.dumps(packet), encoding="utf-8")
            output_root = temporary_path / "quality-pilot"
            stream = io.StringIO()
            with contextlib.redirect_stdout(stream):
                status = main([
                    "quality-pilot",
                    "prepare",
                    "--source-manifest", str(source_manifest_path),
                    "--packet-manifest", str(manifest_path),
                    "--packet-root", str(packet_root),
                    "--output-root", str(output_root),
                ])
            result = json.loads(stream.getvalue())

            self.assertEqual(status, 0)
            self.assertEqual(result["status"], "reviewer_packet_frozen")
            self.assertEqual(result["selected_packet_count"], 24)
            self.assertEqual(result["mode"], "private_no_provider_egress")
            self.assertEqual(output_root.stat().st_mode & 0o777, 0o700)
            self.assertEqual((output_root / "reviewer-index.json").stat().st_mode & 0o777, 0o600)

    def test_labels_must_precede_separate_extractor_results(self) -> None:
        rows = rich_rows()
        selection = fixture_selection(rows)
        packets = packet_documents(rows)
        labels = label_document(selection, packets)
        results = extractor_results(selection, packets)

        with tempfile.TemporaryDirectory() as temporary:
            store = PilotArtifactStore(Path(temporary) / "pilot", require_ignored=False)
            frozen = store.freeze_reference_set(selection, packets, FIXTURES / "reviewer-label.schema.json")
            with self.assertRaisesRegex(QualityPilotOrderError, "reviewer_labels_required"):
                store.write_extractor_results(results)

            label_receipt = store.write_reviewer_labels(labels)
            stored_results = store.write_extractor_results({
                **results,
                "reviewer_labels_sha256": label_receipt.sha256,
            })
            ledger = [json.loads(line) for line in (store.root / "artifact-order.jsonl").read_text(encoding="utf-8").splitlines()]

        kinds = [entry["artifact_kind"] for entry in ledger]
        self.assertLess(kinds.index("reviewer_labels"), kinds.index("extractor_results"))
        self.assertEqual(label_receipt.selection_sha256, selection.selection_sha256)
        self.assertEqual(stored_results.selection_sha256, selection.selection_sha256)
        self.assertTrue(frozen.reference_set_sha256)


class PilotEvaluationTests(unittest.TestCase):
    def test_generic_candidate_fails_relevance_transferability_and_novelty(self) -> None:
        rows = rich_rows()
        selection = fixture_selection(rows)
        packets = packet_documents(rows)
        labels = label_document(selection, packets)
        template = json.loads((FIXTURES / "generic-candidate.json").read_text(encoding="utf-8"))
        documents = []
        for packet_id in selection.selected_packet_ids:
            packet = packets[packet_id]
            documents.append(candidate_document(
                packet,
                summary=template["summary"],
                rationale=template["transferability_rationale"],
            ))

        evaluation = evaluate_quality_pilot(selection, packets, labels, extractor_results(selection, packets, documents=documents))

        self.assertEqual(evaluation.status, "reduced_scope")
        self.assertFalse(evaluation.metrics["relevance"]["passed"])
        self.assertFalse(evaluation.metrics["transferability"]["passed"])
        self.assertFalse(evaluation.metrics["novelty_non_harness_usefulness"]["passed"])
        self.assertEqual(evaluation.blocked_units, ("U4", "U5", "U6"))

    def test_unsupported_data_claim_fails_faithfulness(self) -> None:
        rows = rich_rows()
        selection = fixture_selection(rows)
        packets = packet_documents(rows)
        first_id = selection.selected_packet_ids[0]
        packets[first_id] = packet_document(next(row for row in rows if row["packet_id"] == first_id), event_count=2)
        labels = label_document(selection, packets)
        template = json.loads((FIXTURES / "unsupported-data-candidate.json").read_text(encoding="utf-8"))
        documents = [candidate_document(packets[packet_id]) for packet_id in selection.selected_packet_ids]
        documents[0] = candidate_document(
            packets[first_id],
            summary=template["summary"],
            rationale=template["transferability_rationale"],
            evidence_uri=packets[first_id]["events"][1]["evidence_uri"],
        )

        evaluation = evaluate_quality_pilot(selection, packets, labels, extractor_results(selection, packets, documents=documents))

        self.assertEqual(evaluation.status, "reduced_scope")
        self.assertEqual(evaluation.metrics["data_faithfulness"]["numerator"], 23)
        self.assertEqual(evaluation.metrics["data_faithfulness"]["denominator"], 24)
        self.assertFalse(evaluation.metrics["data_faithfulness"]["passed"])

    def test_failed_threshold_writes_reduced_scope_receipt_that_blocks_u4_to_u6(self) -> None:
        rows = rich_rows()
        selection = fixture_selection(rows)
        packets = packet_documents(rows)
        labels = label_document(selection, packets)
        documents = [
            {
                "schema_version": "candidate-learning/v1",
                "result_type": "no_learning",
                "packet_id": packet_id,
                "candidates": [],
                "no_learning_reason": "No marketing outcome is supported.",
            }
            if index < 5 else candidate_document(packets[packet_id])
            for index, packet_id in enumerate(selection.selected_packet_ids)
        ]
        evaluation = evaluate_quality_pilot(selection, packets, labels, extractor_results(selection, packets, documents=documents))

        with tempfile.TemporaryDirectory() as temporary:
            store = PilotArtifactStore(Path(temporary) / "pilot", require_ignored=False)
            store.freeze_reference_set(selection, packets, FIXTURES / "reviewer-label.schema.json")
            label_receipt = store.write_reviewer_labels(labels)
            store.write_extractor_results({
                **extractor_results(selection, packets, documents=documents),
                "reviewer_labels_sha256": label_receipt.sha256,
            })
            receipt = store.write_gate_receipt(evaluation)
            stored = json.loads((store.root / "pilot-gate-receipt.json").read_text(encoding="utf-8"))

        self.assertEqual(receipt.status, "reduced_scope")
        self.assertEqual(stored["blocked_units"], ["U4", "U5", "U6"])
        self.assertIn("no_learning_accuracy", stored["failing_metrics"])

    def test_false_exact_deduplication_collapse_is_a_hard_failure(self) -> None:
        rows = rich_rows()
        selection = fixture_selection(rows)
        packets = packet_documents(rows)
        labels = label_document(selection, packets)
        documents = [candidate_document(packets[packet_id]) for packet_id in selection.selected_packet_ids]
        second_candidate = documents[1]["candidates"][0]
        second_candidate["summary"] = "A different paid campaign outcome requires a different marketing decision."
        second_candidate["candidate_id"] = stable_candidate_id(str(documents[1]["packet_id"]), second_candidate)
        deduplication = [{
            "retained_candidate_id": documents[0]["candidates"][0]["candidate_id"],
            "collapsed_candidate_id": second_candidate["candidate_id"],
        }]

        evaluation = evaluate_quality_pilot(
            selection,
            packets,
            labels,
            extractor_results(selection, packets, documents=documents, exact_deduplications=deduplication),
        )

        self.assertEqual(evaluation.metrics["false_exact_deduplication_collapses"]["count"], 1)
        self.assertFalse(evaluation.metrics["false_exact_deduplication_collapses"]["passed"])
        self.assertEqual(evaluation.status, "reduced_scope")


if __name__ == "__main__":
    unittest.main()
