import contextlib
import copy
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from marketing_intelligence.checkpoint import CheckpointStore
from marketing_intelligence.cli import main
from marketing_intelligence.estimate import FULL_POC_LIMITS, ResourceBudgetExceeded, ResourceLimits
from marketing_intelligence.extraction import (
    approved_packet_fields,
    stable_candidate_id,
    validate_candidate_document,
    validate_provider_release,
)
from marketing_intelligence.routing import (
    build_dependence_groups,
    build_session_preflight,
    route_full_extraction_work,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "candidates"
SOURCE_VERSION = "a" * 64


def fixture(name: str) -> dict[str, object]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def artifact_record(
    value: str,
    *,
    harness: str = "claude",
    prompt_hash: str = "prompt-a",
    input_hash: str = "input-a",
    injected_fingerprint: str = "fingerprint-a",
    session_kind: str = "interactive",
) -> dict[str, object]:
    artifact_id = f"artifact-{value * 24}"
    return {
        "artifact_id": artifact_id,
        "harness": harness,
        "terminal_status": "complete",
        "in_window": True,
        "session_kind": session_kind,
        "parent_artifact_id": "?",
        "dependence_group_id": f"dependence-{value * 24}",
        "dependence_fields": {
            "harness": harness,
            "parent_reference": "parent-a",
            "prompt_hash": prompt_hash,
            "input_hash": input_hash,
            "code_version": "code-a",
            "configuration_version": "config-a",
            "source_dataset": "dataset-a",
            "injected_context_fingerprint": injected_fingerprint,
        },
    }


def packet_for(record: dict[str, object], *, value: str, text: str = "A paid campaign result was observed.") -> dict[str, object]:
    artifact_id = str(record["artifact_id"])
    packet_id = f"packet-{value * 24}"
    event_id = f"event-{value * 24}"
    harness = str(record["harness"])
    return {
        "schema_version": "session-packet/v1",
        "packet_id": packet_id,
        "artifact_id": artifact_id,
        "harness": harness,
        "source_version": SOURCE_VERSION,
        "event_ids": [event_id],
        "events": [
            {
                "event_id": event_id,
                "evidence_uri": f"session://{harness}/{artifact_id}@{SOURCE_VERSION}#event={event_id}",
                "evidence_strength": "observed",
                "text": text,
            }
        ],
    }


def packet_manifest(packets: list[dict[str, object]]) -> dict[str, object]:
    return {
        "schema_version": "normalization-packet-manifest/v1",
        "source_manifest_sha256": "manifest-a",
        "packets": [
            {
                "packet_id": packet["packet_id"],
                "artifact_id": packet["artifact_id"],
                "harness": packet["harness"],
                "source_version": packet["source_version"],
                "event_ids": packet["event_ids"],
                "serialized_bytes": len(json.dumps(packet, sort_keys=True).encode("utf-8")),
                "estimated_tokens": 100,
                "terminal_outcome": "prepared_no_egress",
            }
            for packet in packets
        ],
    }


class CandidateValidationTests(unittest.TestCase):
    def test_data_candidate_requires_observed_evidence_inside_packet_coverage(self):
        document = fixture("valid-data.json")
        packet = fixture("prompt-injection-packet.json")
        document["candidates"][0]["candidate_id"] = stable_candidate_id(
            str(document["packet_id"]), document["candidates"][0]
        )

        result = validate_candidate_document(document, packet)

        self.assertTrue(result.accepted)
        self.assertEqual(result.errors, ())
        self.assertEqual(result.candidates[0]["claim_label"], "[DATA]")

    def test_data_candidate_without_evidence_and_outside_coverage_fail(self):
        packet = fixture("prompt-injection-packet.json")
        missing = fixture("invalid-data-no-evidence.json")
        missing["candidates"][0]["candidate_id"] = stable_candidate_id(
            str(missing["packet_id"]), missing["candidates"][0]
        )
        outside = fixture("valid-data.json")
        outside["candidates"][0]["candidate_id"] = stable_candidate_id(
            str(outside["packet_id"]), outside["candidates"][0]
        )
        outside["candidates"][0]["evidence_uris"] = [
            "session://claude/artifact-aaaaaaaaaaaaaaaaaaaaaaaa@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa#event=event-bbbbbbbbbbbbbbbbbbbbbbbb"
        ]

        missing_result = validate_candidate_document(missing, packet)
        outside_result = validate_candidate_document(outside, packet)

        self.assertFalse(missing_result.accepted)
        self.assertIn("$.candidates[0].evidence_uris:minItems", missing_result.errors)
        self.assertFalse(outside_result.accepted)
        self.assertIn("candidate.evidence_uris[0]:not_in_packet", outside_result.errors)

    def test_no_learning_is_terminal_without_published_candidate(self):
        result = validate_candidate_document(fixture("no-learning.json"), fixture("prompt-injection-packet.json"))

        self.assertTrue(result.accepted)
        self.assertEqual(result.terminal_status, "no_learning")
        self.assertEqual(result.candidates, ())

    def test_packet_content_is_untrusted_and_cannot_add_mutation_fields(self):
        document = fixture("valid-data.json")
        document["candidates"][0]["candidate_id"] = stable_candidate_id(
            str(document["packet_id"]), document["candidates"][0]
        )
        document["candidates"][0]["source_mutation"] = "delete source"

        result = validate_candidate_document(document, fixture("prompt-injection-packet.json"))

        self.assertFalse(result.accepted)
        self.assertIn("$.candidates[0].source_mutation:unexpected", result.errors)

    def test_unsupported_topic_type_and_claim_label_report_field_errors(self):
        document = fixture("valid-data.json")
        candidate = document["candidates"][0]
        candidate["topic"] = "unsupported"
        candidate["learning_type"] = "unsupported"
        candidate["claim_label"] = "unsupported"
        candidate["candidate_id"] = stable_candidate_id(str(document["packet_id"]), candidate)

        result = validate_candidate_document(document, fixture("prompt-injection-packet.json"))

        self.assertFalse(result.accepted)
        self.assertIn("$.candidates[0].topic:enum", result.errors)
        self.assertIn("$.candidates[0].learning_type:enum", result.errors)
        self.assertIn("$.candidates[0].claim_label:enum", result.errors)


class RoutingTests(unittest.TestCase):
    def test_dependence_groups_use_provenance_and_injected_fingerprints(self):
        first = artifact_record("a")
        second = artifact_record("b")
        third = artifact_record("c", injected_fingerprint="fingerprint-b")
        packets = [packet_for(first, value="a"), packet_for(second, value="b"), packet_for(third, value="c")]

        groups = build_dependence_groups(
            {"records": [first, second, third]},
            packet_manifest(packets),
        )

        self.assertEqual(len(groups), 2)
        grouped_members = sorted(len(group.member_artifact_ids) for group in groups)
        self.assertEqual(grouped_members, [1, 2])
        self.assertNotEqual(groups[0].group_id, str(first["dependence_group_id"]))

    def test_observed_execution_shape_supplies_unknown_session_kind_without_overwriting_provenance(self):
        record = artifact_record("a", session_kind="?")
        record["classification"] = {
            "execution_shape": {"value": "mixed_work", "provenance": "observed", "rule": "fixture"}
        }
        packet = packet_for(record, value="a")

        group = build_dependence_groups({"records": [record]}, packet_manifest([packet]))[0]

        self.assertEqual(group.session_kind, "mixed_work")

    def test_preflight_accounts_every_eligible_group_with_compact_classification(self):
        records = [artifact_record("a"), artifact_record("b"), artifact_record("c", injected_fingerprint="fingerprint-b")]
        packets = [packet_for(record, value=value) for record, value in zip(records, ("a", "b", "c"), strict=True)]

        preflight = build_session_preflight(
            {"records": records},
            packet_manifest(packets),
            {str(packet["packet_id"]): packet for packet in packets},
            prompt_sha256="prompt-a",
            policy_version="policy-a",
        )

        self.assertEqual(preflight.coverage["eligible_group_count"], 2)
        self.assertEqual(preflight.coverage["classification_work_item_count"], 2)
        self.assertEqual(preflight.coverage["unaccounted_group_count"], 0)
        self.assertLessEqual(preflight.resource_estimate.input_tokens, FULL_POC_LIMITS.max_input_tokens)
        self.assertLessEqual(preflight.resource_estimate.calls, FULL_POC_LIMITS.max_calls)
        self.assertLessEqual(preflight.resource_estimate.wall_minutes, FULL_POC_LIMITS.max_wall_minutes)

    def test_only_positive_groups_and_deterministic_mixed_negative_sample_get_full_work(self):
        records = [
            artifact_record("a", session_kind="mixed_work"),
            artifact_record("b", session_kind="interactive"),
            artifact_record("c", session_kind="mixed_work", injected_fingerprint="fingerprint-b"),
        ]
        packets = [packet_for(record, value=value) for record, value in zip(records, ("a", "b", "c"), strict=True)]
        preflight = build_session_preflight(
            {"records": records}, packet_manifest(packets), {str(packet["packet_id"]): packet for packet in packets},
            prompt_sha256="prompt-a", policy_version="policy-a",
        )
        mixed_group_ids = [group.group_id for group in preflight.groups if group.session_kind == "mixed_work"]
        positive_group_id = next(group.group_id for group in preflight.groups if group.session_kind == "interactive")
        classifications = {group.group_id: "not_marketing" for group in preflight.groups}
        classifications[positive_group_id] = "marketing_bearing"

        routed_once = route_full_extraction_work(preflight, classifications, mixed_sample_fraction=0.50)
        routed_twice = route_full_extraction_work(preflight, classifications, mixed_sample_fraction=0.50)

        self.assertEqual(routed_once, routed_twice)
        self.assertEqual(len(routed_once.extraction_work_items), 2)
        self.assertEqual(
            {item["selection_reason"] for item in routed_once.extraction_work_items},
            {"marketing_bearing", "mixed_negative_sample"},
        )
        rolled_up_mixed_ids = [
            group_id for group_id in mixed_group_ids
            if routed_once.group_terminal_statuses[group_id] == "group_rolled_up"
        ]
        self.assertEqual(len(rolled_up_mixed_ids), 1)

    def test_resource_cap_blocks_preflight_before_any_dispatch(self):
        record = artifact_record("a")
        packet = packet_for(record, value="a", text="x" * 10_000)

        with self.assertRaises(ResourceBudgetExceeded):
            build_session_preflight(
                {"records": [record]}, packet_manifest([packet]), {str(packet["packet_id"]): packet},
                prompt_sha256="prompt-a", policy_version="policy-a",
                limits=ResourceLimits(max_input_tokens=1, max_calls=1, max_wall_minutes=1),
            )


class CheckpointAndReleaseTests(unittest.TestCase):
    def test_immutable_work_items_and_repeated_failure_terminal_checkpoint(self):
        work_item = {
            "schema_version": "session-analysis-work-item/v1",
            "work_item_id": "work-aaaaaaaaaaaaaaaaaaaaaaaa",
            "stage": "full_extraction",
            "packet_id": "packet-aaaaaaaaaaaaaaaaaaaaaaaa",
            "harness": "claude",
        }
        with tempfile.TemporaryDirectory() as temporary:
            store = CheckpointStore(Path(temporary))
            self.assertTrue(store.write_immutable_work_item(work_item))
            self.assertFalse(store.write_immutable_work_item(work_item))
            changed = {**work_item, "stage": "classification"}
            with self.assertRaisesRegex(ValueError, "work_item_immutable_mismatch"):
                store.write_immutable_work_item(changed)
            self.assertEqual(store.pending_work_item_ids([work_item]), (work_item["work_item_id"],))
            self.assertEqual(store.record_failure(work_item["work_item_id"], "fixture_timeout"), "retrying")
            self.assertEqual(store.pending_work_item_ids([work_item]), (work_item["work_item_id"],))
            self.assertEqual(store.record_failure(work_item["work_item_id"], "fixture_timeout"), "failed")
            self.assertEqual(store.pending_work_item_ids([work_item]), ())
            terminal = store.terminal_results()[0]
            self.assertEqual(terminal["terminal_status"], "failed")
            self.assertEqual(terminal["failure_fingerprint"], terminal["repeated_failure_fingerprint"])

    def test_terminal_no_learning_result_is_append_only_and_resume_skips_only_it(self):
        first = {
            "schema_version": "session-analysis-work-item/v1",
            "work_item_id": "work-aaaaaaaaaaaaaaaaaaaaaaaa",
            "stage": "full_extraction",
            "packet_id": "packet-aaaaaaaaaaaaaaaaaaaaaaaa",
            "harness": "claude",
        }
        second = {**first, "work_item_id": "work-bbbbbbbbbbbbbbbbbbbbbbbb", "packet_id": "packet-bbbbbbbbbbbbbbbbbbbbbbbb"}
        with tempfile.TemporaryDirectory() as temporary:
            store = CheckpointStore(Path(temporary))
            store.write_immutable_work_item(first)
            store.write_immutable_work_item(second)
            result = {"work_item_id": first["work_item_id"], "terminal_status": "no_learning", "result_sha256": "fixture"}
            self.assertTrue(store.append_terminal_result(result))
            self.assertFalse(store.append_terminal_result(result))
            self.assertEqual(store.pending_work_item_ids([first, second]), (second["work_item_id"],))
            with self.assertRaisesRegex(ValueError, "checkpoint_terminal_work_item_missing"):
                store.append_terminal_result({"work_item_id": "work-cccccccccccccccccccccccc", "terminal_status": "no_learning"})

    def test_provider_release_is_affine_and_requires_verified_approved_fields_without_tools(self):
        work_item = {
            "schema_version": "session-analysis-work-item/v1",
            "work_item_id": "work-aaaaaaaaaaaaaaaaaaaaaaaa",
            "stage": "classification",
            "packet_id": "packet-aaaaaaaaaaaaaaaaaaaaaaaa",
            "harness": "claude",
            "prompt_sha256": "prompt-a",
            "policy_version": "policy-a",
            "approved_fields": list(approved_packet_fields("classification")),
        }
        release = {
            "provider": "anthropic",
            "account": "authenticated-first-party-claude",
            "account_verified": True,
            "model": "claude-sonnet-5",
            "model_verified": True,
            "prompt_sha256": "prompt-a",
            "policy_version": "policy-a",
            "approved_fields": list(approved_packet_fields("classification")),
            "raw_tools": [],
            "encrypted_transport_verified": True,
        }

        accepted = validate_provider_release(release, work_item)
        mismatched = validate_provider_release({**release, "provider": "openai"}, work_item)

        self.assertTrue(accepted.approved)
        self.assertFalse(mismatched.approved)
        self.assertIn("provider_affinity_mismatch", mismatched.errors)
        self.assertNotIn("fallback_provider", mismatched.errors)


class CliTests(unittest.TestCase):
    def test_sessions_cli_writes_private_preflight_without_packet_or_candidate_bodies(self):
        record = artifact_record("a")
        packet = packet_for(record, value="a")
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            manifest_path = temporary_path / "manifest.json"
            packet_manifest_path = temporary_path / "packet-manifest.json"
            packet_root = temporary_path / "packets"
            packet_root.mkdir()
            manifest_path.write_text(json.dumps({"records": [record]}), encoding="utf-8")
            packet_manifest_path.write_text(json.dumps(packet_manifest([packet])), encoding="utf-8")
            (packet_root / f"{packet['packet_id']}.json").write_text(json.dumps(packet), encoding="utf-8")
            output_root = ROOT / ".u8-private" / "u3-cli-test"
            stream = io.StringIO()
            try:
                with contextlib.redirect_stdout(stream):
                    status = main([
                        "sessions",
                        "--manifest", str(manifest_path),
                        "--packet-manifest", str(packet_manifest_path),
                        "--packet-root", str(packet_root),
                        "--output-root", str(output_root),
                    ])
                result = json.loads(stream.getvalue())
                receipt = json.loads(next((output_root / "preflight").glob("*/receipt.json")).read_text(encoding="utf-8"))
                self.assertEqual(status, 0)
                self.assertEqual(result["status"], "preflight_planned_no_provider_egress")
                self.assertEqual(result["unaccounted_groups"], 0)
                self.assertNotIn("events", json.dumps(receipt))
                self.assertNotIn("candidates", json.dumps(receipt))
            finally:
                if output_root.exists():
                    shutil.rmtree(output_root)


if __name__ == "__main__":
    unittest.main()
