import json
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from marketing_intelligence.value_probe import (
    ArtifactMetadata,
    _build_claude_artifact,
    _claude_total_input_tokens,
    ProbeStatus,
    build_evidence_pointer,
    freeze_novelty_baseline,
    is_novel_against_baseline,
    run_value_probe,
    select_root_artifacts,
    validate_candidate,
)


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config"


def metadata(number, *, density=None, root=True):
    return ArtifactMetadata(
        artifact_id=f"artifact-{number:02d}",
        harness="claude",
        source_kind="root" if root else "child",
        source_path=f"/outside/source/{number}.jsonl",
        stratum="general-documents",
        in_window_events=number + 1,
        marketing_events=number if density is None else density,
        byte_size=1000 + number,
        event_ids=(f"event-{number:02d}",),
        content_sha256=(f"{number:064x}"),
        parent_artifact_id=None if root else "artifact-01",
    )


def candidate(number, content=None, *, label="[DATA]", evidence=None):
    return {
        "id": f"candidate-{number:02d}",
        "title": f"Marketing learning {number}",
        "content": content or f"Marketing decision {number} increases qualified demand by changing paid search budget allocation.",
        "label": label,
        "topic": "Paid Advertising",
        "type": "finding",
        "decision": "change budget allocation",
        "evidence": evidence or [f"session://claude/artifact-{number:02d}@abc#event=event-{number:02d}"],
    }


def packet(number, *, byte_size=1000, evidence_strength="observed"):
    pointer = f"session://claude/artifact-{number:02d}@abc#event=event-{number:02d}"
    return {
        "artifact_id": f"artifact-{number:02d}",
        "bytes": byte_size,
        "events": [{"evidence": pointer, "evidence_strength": evidence_strength}],
    }


class ValueProbeTests(unittest.TestCase):
    def test_claude_input_usage_is_cache_inclusive_or_unknown(self):
        self.assertEqual(
            _claude_total_input_tokens(
                {
                    "input_tokens": 2,
                    "cache_creation_input_tokens": 1_000,
                    "cache_read_input_tokens": 4_000,
                }
            ),
            5_002,
        )
        self.assertEqual(_claude_total_input_tokens({"input_tokens": 2}), "?")

    def test_selection_is_deterministic_eight_to_twelve_without_coverage_claim(self):
        artifacts = [metadata(i, density=100 - i) for i in range(1, 14)]
        artifacts.append(metadata(99, density=1000, root=False))

        first = select_root_artifacts(artifacts)
        second = select_root_artifacts(list(reversed(artifacts)))

        self.assertEqual(first, second)
        self.assertEqual(len(first.artifacts), 8)
        self.assertFalse(first.claims_corpus_coverage)
        self.assertEqual(first.selection_reason, "verified_high_density_root_strata")

    def test_evidence_pointer_is_safe_and_contains_no_local_path(self):
        pointer = build_evidence_pointer(metadata(1), "event-1", "v1")

        self.assertEqual(pointer, "session://claude/artifact-01@v1#event=event-1")
        self.assertNotIn("/outside", pointer)
        self.assertNotIn(".jsonl", pointer)

    def test_baseline_freeze_is_stable_and_happens_before_candidate_evaluation(self):
        baseline = freeze_novelty_baseline(
            {
                "policy": "Cross-reference active campaign keywords before adding negatives.",
                "prior": "Baseline prior intelligence.",
            }
        )
        self.assertEqual(baseline, freeze_novelty_baseline({"prior": "Baseline prior intelligence.", "policy": "Cross-reference active campaign keywords before adding negatives."}))
        self.assertFalse(is_novel_against_baseline("Cross-reference active campaign keywords before adding negatives.", baseline)[0])
        self.assertFalse(is_novel_against_baseline("Check the campaign's active keyword targets before you add a negative keyword.", baseline)[0])
        self.assertTrue(is_novel_against_baseline("Use weekday-only CPM to separate volume from competition.", baseline)[0])

    def test_harness_only_learning_is_rejected(self):
        decision = validate_candidate(
            {
                **candidate(1, "The harness should checkpoint packets and retry only new failures."),
                "topic": "AI and marketing operations",
                "decision": "checkpoint packets",
            },
            freeze_novelty_baseline({"prior": "unrelated baseline"}),
        )

        self.assertFalse(decision.accepted)
        self.assertEqual(decision.reason, "harness_only")

    def test_data_candidate_rejects_assertion_only_evidence(self):
        proposed = candidate(1)
        pointer = proposed["evidence"][0]

        decision = validate_candidate(
            proposed,
            freeze_novelty_baseline({"prior": "unrelated baseline"}),
            evidence_strength_by_pointer={pointer: "asserted"},
        )

        self.assertFalse(decision.accepted)
        self.assertEqual(decision.reason, "data_evidence_not_observed")

    def test_data_candidate_accepts_observed_evidence(self):
        proposed = candidate(1)
        pointer = proposed["evidence"][0]

        decision = validate_candidate(
            proposed,
            freeze_novelty_baseline({"prior": "unrelated baseline"}),
            evidence_strength_by_pointer={pointer: "observed"},
        )

        self.assertTrue(decision.accepted)
        self.assertEqual(decision.reason, "accepted")

    def test_logic_and_hypothesis_do_not_require_observed_evidence(self):
        baseline = freeze_novelty_baseline({"prior": "unrelated baseline"})
        for number, label, strength in (
            (1, "[LOGIC]", "asserted"),
            (2, "[HYPOTHESIS]", "reasoned"),
        ):
            with self.subTest(label=label):
                proposed = candidate(number, label=label)
                decision = validate_candidate(
                    proposed,
                    baseline,
                    evidence_strength_by_pointer={proposed["evidence"][0]: strength},
                )
                self.assertTrue(decision.accepted)
                self.assertEqual(decision.reason, "accepted")

    def test_normalized_packet_marks_verified_tool_results_observed(self):
        records = (
            {
                "timestamp": "2026-08-20T12:00:00Z",
                "type": "user",
                "message": {
                    "role": "user",
                    "content": "Assertion: increase the paid search campaign budget.",
                },
            },
            {
                "timestamp": "2026-08-20T12:01:00Z",
                "type": "assistant",
                "message": {
                    "role": "assistant",
                    "content": [{"type": "text", "text": "Reasoned: campaign CTR supports a budget test."}],
                },
            },
            {
                "timestamp": "2026-08-20T12:02:00Z",
                "type": "user",
                "toolUseResult": {"commandName": "Read", "success": True},
                "message": {
                    "role": "user",
                    "content": [{
                        "type": "tool_result",
                        "tool_use_id": "tool-1",
                        "content": "File read-back: Google Ads conversion data supports increasing paid search budget.",
                    }],
                },
            },
            {
                "timestamp": "2026-08-20T12:03:00Z",
                "type": "user",
                "message": {
                    "role": "user",
                    "content": [{
                        "type": "tool_result",
                        "tool_use_id": "unpaired-tool",
                        "content": "Unpaired tool-shaped text says to increase paid search campaign budget.",
                    }],
                },
            },
        )
        with tempfile.TemporaryDirectory() as temp:
            source_root = Path(temp)
            source_path = source_root / "artifact.jsonl"
            source_path.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")
            _artifact, packet, _manifest = _build_claude_artifact(
                source_path,
                source_root,
                "artifact",
                "google-ads",
                datetime.fromisoformat("2026-08-16T20:00:00+00:00"),
                datetime.fromisoformat("2026-08-24T14:57:36+00:00"),
            )

        self.assertCountEqual(
            (event["evidence_strength"] for event in packet["events"]),
            ("asserted", "asserted", "reasoned", "observed"),
        )

    def test_seven_qualifying_learnings_end_reduced_scope(self):
        calls = []

        def dispatch(_packets):
            calls.append(True)
            return [candidate(i) for i in range(1, 8)]

        receipt = run_value_probe(
            [metadata(i) for i in range(1, 9)],
            baseline=freeze_novelty_baseline({"prior": "unrelated baseline"}),
            redacted_packets=[packet(i) for i in range(1, 9)],
            dispatch=dispatch,
            provider_release={"provider": "openai", "account": "authenticated-codex", "harness": "codex", "model": "gpt-5", "prompt_id": "value-probe-v1", "policy_id": "u8"},
        )

        self.assertEqual(receipt.status, ProbeStatus.REDUCED_SCOPE)
        self.assertEqual(receipt.qualifying_learnings, 7)
        self.assertEqual(receipt.reason, "r23_threshold_not_met")
        self.assertEqual(len(calls), 1)

    def test_eight_qualifying_learnings_pass_inside_resource_envelope(self):
        def dispatch(_packets):
            return [candidate(i) for i in range(1, 9)]

        receipt = run_value_probe(
            [metadata(i) for i in range(1, 9)],
            baseline=freeze_novelty_baseline({"prior": "unrelated baseline"}),
            redacted_packets=[packet(i) for i in range(1, 9)],
            dispatch=dispatch,
            provider_release={"provider": "openai", "account": "authenticated-codex", "harness": "codex", "model": "gpt-5", "prompt_id": "value-probe-v1", "policy_id": "u8"},
        )

        self.assertEqual(receipt.status, ProbeStatus.PASSED)
        self.assertEqual(receipt.qualifying_learnings, 8)
        self.assertEqual(len(receipt.sample_ids), 8)
        self.assertEqual(receipt.baseline_sha256, freeze_novelty_baseline({"prior": "unrelated baseline"}).sha256)

    def test_probe_rejects_data_candidates_backed_only_by_asserted_events(self):
        receipt = run_value_probe(
            [metadata(i) for i in range(1, 9)],
            baseline=freeze_novelty_baseline({"prior": "unrelated baseline"}),
            redacted_packets=[packet(i, evidence_strength="asserted") for i in range(1, 9)],
            dispatch=lambda _packets: [candidate(i) for i in range(1, 9)],
            provider_release={"provider": "openai", "account": "authenticated-codex", "harness": "codex", "model": "gpt-5", "prompt_id": "value-probe-v1", "policy_id": "u8"},
        )

        self.assertEqual(receipt.status, ProbeStatus.REDUCED_SCOPE)
        self.assertEqual(receipt.qualifying_learnings, 0)
        self.assertEqual(receipt.validation_summary["rejection_reasons"], {"data_evidence_not_observed": 8})
        self.assertEqual(receipt.validation_summary["evidence_strength_distribution"], {"asserted": 8, "observed": 0, "reasoned": 0, "unknown": 0})

    def test_resource_rejection_happens_before_dispatch(self):
        calls = []

        def dispatch(_packets):
            calls.append(True)
            return [candidate(i) for i in range(1, 9)]

        receipt = run_value_probe(
            [metadata(i) for i in range(1, 9)],
            baseline=freeze_novelty_baseline({"prior": "unrelated baseline"}),
            redacted_packets=[packet(i, byte_size=300_000) for i in range(1, 9)],
            dispatch=dispatch,
            provider_release={"provider": "openai", "account": "authenticated-codex", "harness": "codex", "model": "gpt-5", "prompt_id": "value-probe-v1", "policy_id": "u8"},
        )

        self.assertEqual(receipt.status, ProbeStatus.REDUCED_SCOPE)
        self.assertEqual(receipt.reason, "resource_envelope_exceeded")
        self.assertEqual(calls, [])
        self.assertEqual(receipt.resource_dimension, "input_tokens")

    def test_quarantine_blocks_dispatch_and_receipt_contains_safe_reason(self):
        calls = []

        def dispatch(_packets):
            calls.append(True)
            return []

        receipt = run_value_probe(
            [metadata(i) for i in range(1, 9)],
            baseline=freeze_novelty_baseline({"prior": "unrelated baseline"}),
            redacted_packets=[{"artifact_id": "artifact-01", "status": "quarantined", "reason": "credential_detected"}],
            dispatch=dispatch,
            provider_release={"provider": "openai", "account": "authenticated-codex", "harness": "codex", "model": "gpt-5", "prompt_id": "value-probe-v1", "policy_id": "u8"},
        )

        self.assertEqual(receipt.status, ProbeStatus.REDUCED_SCOPE)
        self.assertEqual(receipt.reason, "redaction_quarantine")
        self.assertEqual(calls, [])
        self.assertEqual(receipt.quarantined_artifacts, ("artifact-01",))

    def test_provider_affinity_mismatch_blocks_before_dispatch(self):
        calls = []

        def dispatch(_packets):
            calls.append(True)
            return [candidate(i) for i in range(1, 9)]

        receipt = run_value_probe(
            [metadata(i) for i in range(1, 9)],
            baseline=freeze_novelty_baseline({"prior": "unrelated baseline"}),
            redacted_packets=[packet(i) for i in range(1, 9)],
            dispatch=dispatch,
            provider_release={"provider": "anthropic", "account": "authenticated-claude", "harness": "codex", "model": "claude", "prompt_id": "value-probe-v1", "policy_id": "u8"},
        )

        self.assertEqual(receipt.status, ProbeStatus.BLOCKED)
        self.assertEqual(receipt.reason, "provider_affinity_mismatch")
        self.assertEqual(calls, [])

    def test_private_receipt_hash_is_deterministic_and_mode_is_private(self):
        from marketing_intelligence.value_probe import write_probe_receipt

        receipt = run_value_probe(
            [metadata(i) for i in range(1, 9)],
            baseline=freeze_novelty_baseline({"prior": "unrelated baseline"}),
            redacted_packets=[packet(i) for i in range(1, 9)],
            dispatch=lambda _packets: [candidate(i) for i in range(1, 9)],
            provider_release={"provider": "openai", "account": "authenticated-codex", "harness": "codex", "model": "gpt-5", "prompt_id": "value-probe-v1", "policy_id": "u8"},
        )

        with tempfile.TemporaryDirectory() as temp:
            first = write_probe_receipt(Path(temp) / "one" / "receipt.json", receipt)
            second = write_probe_receipt(Path(temp) / "two" / "receipt.json", receipt)
            self.assertEqual(first["receipt_sha256"], second["receipt_sha256"])
            self.assertEqual((Path(temp) / "one" / "receipt.json").stat().st_mode & 0o777, 0o600)
            self.assertEqual((Path(temp) / "one").stat().st_mode & 0o777, 0o700)


if __name__ == "__main__":
    unittest.main()
