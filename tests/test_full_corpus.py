from __future__ import annotations

import json
from pathlib import Path
import shutil
import tempfile
import unittest

from marketing_intelligence.census import canonical_json
from marketing_intelligence.full_corpus import (
    _claude_failure_reason,
    build_calibration,
    finalize_full_corpus,
    prepare_full_corpus,
    route_extraction,
    run_batch,
)
from marketing_intelligence.redact import secure_write_text
from marketing_intelligence.review import build_publication, build_review_queue
from marketing_intelligence.routing import build_session_preflight, write_preflight_private


ROOT = Path(__file__).resolve().parents[1]
PRIVATE_TEST_ROOT = ROOT / ".u8-private"
SOURCE_VERSION = "a" * 64


def artifact_record(value: str, harness: str) -> dict[str, object]:
    return {
        "artifact_id": f"artifact-{value * 24}",
        "harness": harness,
        "terminal_status": "complete",
        "in_window": True,
        "session_kind": "interactive",
        "parent_artifact_id": "?",
        "dependence_fields": {
            "harness": harness,
            "parent_reference": f"parent-{value}",
            "prompt_hash": f"prompt-{value}",
            "input_hash": f"input-{value}",
            "code_version": "code-a",
            "configuration_version": "config-a",
            "source_dataset": "dataset-a",
            "injected_context_fingerprint": f"fingerprint-{value}",
        },
    }


def packet_for(record: dict[str, object], value: str) -> dict[str, object]:
    artifact_id = str(record["artifact_id"])
    harness = str(record["harness"])
    packet_id = f"packet-{value * 24}"
    event_id = f"event-{value * 24}"
    return {
        "schema_version": "session-packet/v1",
        "packet_id": packet_id,
        "artifact_id": artifact_id,
        "harness": harness,
        "source_version": SOURCE_VERSION,
        "event_ids": [event_id],
        "events": [{
            "event_id": event_id,
            "evidence_uri": f"session://{harness}/{artifact_id}@{SOURCE_VERSION}#event={event_id}",
            "evidence_strength": "observed",
            "role": "assistant",
            "timestamp": "2026-08-20T12:00:00Z",
            "text": "A paid campaign produced a measured marketing result.",
        }],
    }


def packet_manifest(packets: list[dict[str, object]]) -> dict[str, object]:
    return {
        "schema_version": "normalization-packet-manifest/v1",
        "source_manifest_sha256": "manifest-a",
        "packets": [{
            "packet_id": packet["packet_id"],
            "artifact_id": packet["artifact_id"],
            "harness": packet["harness"],
            "source_version": packet["source_version"],
            "event_ids": packet["event_ids"],
            "serialized_bytes": len(canonical_json(packet).encode("utf-8")),
            "estimated_tokens": 100,
            "terminal_outcome": "prepared_no_egress",
        } for packet in packets],
    }


def probe_candidate(candidate_id: str, title: str, accepted: bool) -> dict[str, object]:
    return {
        "candidate_id": candidate_id,
        "accepted": accepted,
        "reason": "accepted" if accepted else "not_novel",
        "candidate": {
            "id": candidate_id,
            "title": title,
            "content": "A measured marketing result with a concrete consequence.",
            "decision": "Use the result to change the next campaign decision.",
            "evidence": [
                "session://claude/artifact-cccccccccccccccccccccccc@"
                + SOURCE_VERSION
                + "#event=event-cccccccccccccccccccccccc"
            ],
            "label": "[DATA]",
            "topic": "paid advertising",
            "type": "measurement",
        },
    }


def reviewed_probe() -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    envelope = {
        "receipt_sha256": "b" * 64,
        "receipt": {
            "status": "passed",
            "candidate_decisions": [
                probe_candidate("source-accepted", "Accepted calibration", True),
                probe_candidate("source-rejected", "Rejected calibration", True),
            ],
        },
    }
    queue = build_review_queue(envelope)
    ids = {row["title"]: row["candidate_id"] for row in queue["candidates"]}
    decisions = {
        "schema_version": "human-review-decisions/v1",
        "queue_sha256": queue["queue_sha256"],
        "reviewer": "Heikki",
        "decisions": [
            {"candidate_id": ids["Accepted calibration"], "decision": "accept"},
            {"candidate_id": ids["Rejected calibration"], "decision": "reject"},
        ],
    }
    return queue, decisions, build_publication(queue, decisions)


def fake_provider(
    harness: str,
    prompt: str,
    _schema_path: Path,
    _cwd: Path,
    _model: str,
    _effort: str,
    _budget: float,
    _timeout: int,
) -> dict[str, object]:
    batch = json.loads(prompt.split("Approved redacted batch:\n", 1)[1])
    if batch["stage"] == "classification":
        return {
            "schema_version": "full-corpus-classification-result/v1",
            "results": [{
                "work_item_id": item["work_item_id"],
                "group_id": item["group_id"],
                "classification": "marketing_bearing",
                "rationale": "The packet contains a measured marketing result.",
            } for item in batch["work_items"]],
        }
    results = []
    for item in batch["work_items"]:
        packet = item["analysis_packet"]
        results.append({
            "work_item_id": item["work_item_id"],
            "document": {
                "schema_version": "candidate-learning/v1",
                "result_type": "candidates",
                "packet_id": item["packet_id"],
                "no_learning_reason": "not_applicable",
                "candidates": [{
                    "candidate_id": "placeholder",
                    "title": f"Measured result from {harness}",
                    "summary": "A paid campaign produced a measured result.",
                    "recommended_action": "Use the observed result in the next campaign decision.",
                    "topic": "paid_advertising",
                    "learning_type": "finding",
                    "claim_label": "[DATA]",
                    "transferability_rationale": "The decision pattern applies to another campaign.",
                    "confidence": "high",
                    "session_kind": item["session_kind"],
                    "evidence_uris": [packet["events"][0]["evidence_uri"]],
                }],
            },
        })
    return {"schema_version": "full-corpus-extraction-result/v1", "results": results}


class FullCorpusPipelineTest(unittest.TestCase):

    def test_claude_rate_limit_is_classified_without_echoing_provider_content(self):
        envelope = json.dumps({
            "api_error_status": 429,
            "result": "sensitive provider message",
        })

        self.assertEqual(
            _claude_failure_reason(envelope),
            "full_corpus_provider_rate_limited",
        )

    def setUp(self) -> None:
        PRIVATE_TEST_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.temporary = Path(tempfile.mkdtemp(prefix="full-corpus-test-", dir=PRIVATE_TEST_ROOT))

    def tearDown(self) -> None:
        shutil.rmtree(self.temporary)

    def test_calibration_binds_positive_and_negative_human_decisions(self) -> None:
        queue, decisions, publication = reviewed_probe()

        calibration = build_calibration(queue, decisions, publication)

        self.assertEqual(calibration["decision_counts"], {"accept": 1, "edit": 0, "reject": 1})
        self.assertEqual(len(calibration["positive_examples"]), 1)
        self.assertEqual(len(calibration["negative_examples"]), 1)
        self.assertEqual(calibration["publication_sha256"], publication["publication_sha256"])

    def test_full_pipeline_accounts_for_both_harnesses_and_stops_at_review(self) -> None:
        records = [artifact_record("a", "claude"), artifact_record("b", "codex")]
        packets = [packet_for(records[0], "a"), packet_for(records[1], "b")]
        source_manifest = {"records": records}
        packets_manifest = packet_manifest(packets)
        preflight = build_session_preflight(
            source_manifest,
            packets_manifest,
            {str(packet["packet_id"]): packet for packet in packets},
            prompt_sha256="prompt-a",
            policy_version="policy-a",
        )
        preflight_output = write_preflight_private(preflight, self.temporary / "source-preflight")
        packet_root = self.temporary / "packets"
        packet_root.mkdir(mode=0o700)
        for packet in packets:
            secure_write_text(packet_root / f"{packet['packet_id']}.json", canonical_json(packet) + "\n")
        queue, decisions, publication = reviewed_probe()
        run_root = self.temporary / "full-run"

        prepared = prepare_full_corpus(
            preflight_output.run_directory,
            queue,
            decisions,
            publication,
            run_root,
        )

        self.assertEqual(prepared["classification_work_item_count"], 2)
        self.assertEqual(prepared["classification_batch_count"], 2)
        self.assertEqual(prepared["harness_counts"], {"claude": 1, "codex": 1})
        self.assertEqual((run_root / "decision-ledger.json").stat().st_mode & 0o777, 0o600)
        for batch_path in sorted((run_root / "classification" / "batches").glob("*.json")):
            run_batch(run_root, batch_path.stem, provider_runner=fake_provider)

        routed = route_extraction(
            run_root,
            source_manifest,
            packets_manifest,
            packet_root,
            mixed_sample_fraction=0,
        )

        self.assertEqual(routed["classified_group_count"], 2)
        self.assertEqual(routed["selected_group_count"], 2)
        self.assertEqual(routed["rolled_up_group_count"], 0)
        self.assertEqual(routed["extraction_batch_count"], 2)
        for batch_path in sorted((run_root / "extraction" / "batches").glob("*.json")):
            batch = json.loads(batch_path.read_text(encoding="utf-8"))
            if batch["harness"] == "claude":
                result = run_batch(
                    run_root,
                    batch_path.stem,
                    provider_override="codex",
                    provider_override_reason="active_user_override_claude_unavailable",
                    provider_runner=fake_provider,
                )
                self.assertEqual(result["source_harness"], "claude")
                self.assertEqual(result["provider"], "codex")
                terminal = json.loads(
                    (run_root / "extraction" / "results" / batch_path.name).read_text(encoding="utf-8")
                )
                self.assertEqual(terminal["harness"], "claude")
                self.assertEqual(terminal["provider"], "codex")
                self.assertEqual(
                    terminal["provider_override_reason"],
                    "active_user_override_claude_unavailable",
                )
            else:
                run_batch(run_root, batch_path.stem, provider_runner=fake_provider)

        review_root = self.temporary / "review"
        finalized = finalize_full_corpus(run_root, review_root.relative_to(ROOT))

        self.assertEqual(finalized["status"], "blocked_pending_human_review")
        self.assertEqual(finalized["classified_group_count"], 2)
        self.assertEqual(finalized["terminal_status_counts"], {"extracted": 2})
        self.assertEqual(finalized["provider_batch_counts"], {"codex": 2})
        self.assertEqual(finalized["review_candidate_count"], 1)
        self.assertTrue((review_root / "review.html").is_file())
        self.assertFalse((review_root / "index.html").exists())


if __name__ == "__main__":
    unittest.main()
