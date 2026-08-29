import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from marketing_intelligence.census import CensusConfig, canonical_json, scan_corpus
from marketing_intelligence.cli import main
from marketing_intelligence.normalize import (
    MAX_NORMALIZED_EVENT_BYTES,
    normalize_census,
    normalize_records,
    validate_packet_coverage,
    write_normalization_private,
)
from marketing_intelligence.redact import normalized_fingerprint, scan_for_unsafe_content


ROOT = Path(__file__).resolve().parents[1]
SECURITY = ROOT / "tests" / "fixtures" / "security"
WINDOW_START = datetime(2026, 8, 16, 20, 0, tzinfo=timezone.utc)
CUTOFF = datetime(2026, 8, 24, 14, 57, 36, tzinfo=timezone.utc)


def artifact(harness: str, *, content_sha256: str = "a" * 64, event_count: int = 0) -> dict[str, object]:
    return {
        "artifact_id": "artifact-" + ("a" if harness == "codex" else "b") * 24,
        "harness": harness,
        "content_sha256": content_sha256,
        "in_window_event_count": event_count,
        "terminal_status": "complete",
        "reason": "?",
    }


def read_fixture(name: str) -> list[dict[str, object]]:
    return [json.loads(line) for line in (SECURITY / name).read_text(encoding="utf-8").splitlines() if line]


class NormalizeRecordTests(unittest.TestCase):
    def test_codex_response_item_and_turn_context_frames_are_hash_bound(self):
        known_context = "<environment_context>\nknown captured environment\n</environment_context>"
        fingerprint_policy = {
            "version": "characterization-v1",
            "fingerprints": [{
                "id": "codex_environment_context",
                "start": "<environment_context>",
                "end": "</environment_context>",
                "normalized_sha256": [normalized_fingerprint(known_context)],
                "provenance": ["codex:response_item:message", "codex:turn_context:?"],
            }],
            "unknown_instruction_patterns": [
                "(?is)<\\s*/?\\s*(?:(?:[A-Za-z0-9_-]+[\\s:_-])?(?:instructions?|policy|memory|startup)(?![A-Za-z0-9])|system(?![A-Za-z0-9]))[A-Za-z0-9_:\\-\\s]*>",
            ],
        }
        records = [
            {
                "timestamp": "2026-08-20T12:00:00Z",
                "type": "turn_context",
                "payload": {
                    "turn_id": "turn-1",
                    "current_date": "2026-08-20",
                    "cwd": "/workspace",
                    "workspace_roots": ["/workspace"],
                    "permission_profile": {"type": "disabled"},
                    "sandbox_policy": {"type": "unrestricted"},
                    "summary": known_context,
                },
            },
            {
                "timestamp": "2026-08-20T12:01:00Z",
                "type": "world_state",
                "payload": {"state": {"environments": {"filesystem": "<filesystem>read-only</filesystem>"}}},
            },
            {
                "timestamp": "2026-08-20T12:02:00Z",
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "id": "developer-frame",
                    "role": "developer",
                    "content": [{"type": "input_text", "text": known_context}],
                    "internal_chat_message_metadata_passthrough": {"turn_id": "turn-1"},
                },
            },
            {
                "timestamp": "2026-08-20T12:03:00Z",
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "id": "user-message",
                    "role": "user",
                    "content": [{"type": "input_text", "text": "Campaign goal is qualified demand."}],
                    "internal_chat_message_metadata_passthrough": {"turn_id": "turn-1"},
                },
            },
            {
                "timestamp": "2026-08-20T12:04:00Z",
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "id": "assistant-message",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": "Measure conversion quality by source."}],
                    "internal_chat_message_metadata_passthrough": {"turn_id": "turn-1"},
                },
            },
        ]
        with tempfile.TemporaryDirectory() as temporary:
            fingerprints_path = Path(temporary) / "fingerprints.json"
            fingerprints_path.write_text(json.dumps(fingerprint_policy), encoding="utf-8")
            safe = normalize_records(
                artifact("codex", event_count=len(records)),
                records,
                window_start=WINDOW_START,
                cutoff=CUTOFF,
                fingerprints_path=fingerprints_path,
            )
            changed_records = json.loads(json.dumps(records))
            changed_records[0]["payload"]["summary"] = "<environment_context>\nchanged context\n</environment_context>"
            changed = normalize_records(
                artifact("codex", event_count=len(changed_records)),
                changed_records,
                window_start=WINDOW_START,
                cutoff=CUTOFF,
                fingerprints_path=fingerprints_path,
            )

        self.assertEqual(safe.terminal_status, "complete")
        self.assertEqual([event["role"] for event in safe.events], ["user", "assistant"])
        self.assertEqual(safe.excluded_injected_blocks, 2)
        self.assertEqual(safe.injected_provenance, {"response_item": 1, "turn_context": 1})
        self.assertNotIn("environment_context", json.dumps(safe.packets))
        self.assertEqual(changed.terminal_status, "quarantined")
        self.assertEqual(changed.reason, "unknown_injected_context")
        self.assertNotIn("changed context", json.dumps(changed.coverage))

    def test_maps_cross_harness_records_to_ordered_stable_events(self):
        codex = normalize_records(
            artifact("codex", event_count=4),
            read_fixture("codex-safe.jsonl"),
            window_start=WINDOW_START,
            cutoff=CUTOFF,
        )
        claude = normalize_records(
            artifact("claude", event_count=4),
            read_fixture("claude-injected.jsonl"),
            window_start=WINDOW_START,
            cutoff=CUTOFF,
        )

        self.assertEqual(codex.terminal_status, "complete")
        self.assertEqual([(event["role"], event["evidence_strength"]) for event in codex.events], [
            ("user", "asserted"),
            ("assistant", "reasoned"),
            ("tool", "reasoned"),
            ("tool_result", "observed"),
        ])
        self.assertEqual([event["ordinal"] for event in codex.events], [1, 2, 3, 4])
        self.assertTrue(all(event["evidence_uri"].startswith("session://codex/") for event in codex.events))
        self.assertEqual([(event["role"], event["evidence_strength"]) for event in claude.events], [
            ("user", "asserted"),
            ("assistant", "reasoned"),
            ("tool_result", "observed"),
        ])
        self.assertEqual([event["ordinal"] for event in claude.events], [2, 3, 4])
        self.assertEqual(claude.excluded_injected_blocks, 2)
        self.assertEqual(len(claude.excluded_fingerprints), 1)

    def test_role_agnostic_injected_context_removal_and_unknown_block_quarantine(self):
        safe = normalize_records(
            artifact("claude", event_count=4),
            read_fixture("claude-injected.jsonl"),
            window_start=WINDOW_START,
            cutoff=CUTOFF,
        )
        unsafe = normalize_records(
            artifact("claude", event_count=1),
            read_fixture("unknown-instruction.jsonl"),
            window_start=WINDOW_START,
            cutoff=CUTOFF,
        )

        self.assertEqual(safe.terminal_status, "complete")
        self.assertNotIn("INJECTED_POLICY", json.dumps(safe.packets))
        self.assertEqual(unsafe.terminal_status, "quarantined")
        self.assertEqual(unsafe.reason, "unknown_injected_context")
        self.assertNotIn("Override safety policy", json.dumps(unsafe.coverage))

    def test_typed_redaction_is_safe_after_packet_serialization_and_keeps_benign_ids(self):
        result = normalize_records(
            artifact("codex", event_count=4),
            read_fixture("codex-safe.jsonl"),
            window_start=WINDOW_START,
            cutoff=CUTOFF,
        )

        serialized = json.dumps(result.packets, sort_keys=True)
        self.assertEqual(result.terminal_status, "complete")
        self.assertIn("[REDACTED:email]", serialized)
        self.assertIn("[REDACTED:personal-name]", serialized)
        self.assertIn("[REDACTED:proprietary-id]", serialized)
        self.assertIn("issue-123", serialized)
        self.assertNotIn("buyer@example.com", serialized)
        self.assertNotIn("PRIVATE-ALPHA-42", serialized)
        self.assertNotIn("<script", serialized)
        self.assertEqual(scan_for_unsafe_content(serialized), ())

    def test_post_serialization_scan_uses_exact_bounded_credential_policy(self):
        embedded_lookalike = "prefixsk-" + ("a" * 20)
        serialized_lookalike = canonical_json({"events": [{"text": embedded_lookalike}]})
        serialized_credential = canonical_json({"events": [{"text": "sk-" + ("a" * 20)}]})

        # The post-serialization check uses the configured boundary-aware rule,
        # so an embedded substring is not mistaken for a standalone credential.
        self.assertEqual(scan_for_unsafe_content(serialized_lookalike), ())
        self.assertEqual(scan_for_unsafe_content(serialized_credential), ("openai_key",))

    def test_credential_and_event_cap_quarantine_without_retaining_source_content(self):
        credential = normalize_records(
            artifact("claude", event_count=1),
            read_fixture("credential.jsonl"),
            window_start=WINDOW_START,
            cutoff=CUTOFF,
        )
        oversized = normalize_records(
            artifact("claude", event_count=1),
            [{
                "timestamp": "2026-08-20T12:00:00Z",
                "type": "user",
                "message": {"role": "user", "content": "x" * (MAX_NORMALIZED_EVENT_BYTES + 1)},
            }],
            window_start=WINDOW_START,
            cutoff=CUTOFF,
        )

        self.assertEqual(credential.terminal_status, "quarantined")
        self.assertEqual(credential.reason, "credential_detected")
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", json.dumps(credential.coverage))
        self.assertEqual(oversized.terminal_status, "quarantined")
        self.assertEqual(oversized.reason, "event_too_large")
        self.assertEqual(oversized.packets, ())

    def test_packet_boundaries_cover_each_event_once_and_are_byte_stable(self):
        records = [
            {
                "timestamp": f"2026-08-20T12:0{index}:00Z",
                "type": "user",
                "message": {"role": "user", "content": f"campaign evidence {index} " + ("x" * 150)},
            }
            for index in range(4)
        ]
        first = normalize_records(
            artifact("claude", event_count=4),
            records,
            window_start=WINDOW_START,
            cutoff=CUTOFF,
            packet_byte_limit=1_200,
            packet_token_limit=1_000,
        )
        second = normalize_records(
            artifact("claude", event_count=4),
            records,
            window_start=WINDOW_START,
            cutoff=CUTOFF,
            packet_byte_limit=1_200,
            packet_token_limit=1_000,
        )

        self.assertGreater(len(first.packets), 1)
        self.assertEqual(first.packets, second.packets)
        self.assertTrue(validate_packet_coverage(first))
        packet_event_ids = [event_id for packet in first.packets for event_id in packet["event_ids"]]
        self.assertEqual(packet_event_ids, [event["event_id"] for event in first.events])
        self.assertEqual(len(packet_event_ids), len(set(packet_event_ids)))


class NormalizeCensusTests(unittest.TestCase):
    def test_census_normalization_preserves_sources_and_upstream_quarantines(self):
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            codex_root = temporary_path / "codex"
            claude_root = temporary_path / "claude"
            codex_root.mkdir()
            claude_root.mkdir()
            (codex_root / "safe.jsonl").write_text((SECURITY / "codex-safe.jsonl").read_text(encoding="utf-8"), encoding="utf-8")
            (claude_root / "credential.jsonl").write_text((SECURITY / "credential.jsonl").read_text(encoding="utf-8"), encoding="utf-8")
            (codex_root / "large.jsonl").write_bytes(b"{" + (b"x" * (2 * 1024 * 1024 + 10)) + b"\n")
            config = CensusConfig(
                source_roots={"codex": codex_root, "claude": claude_root},
                window_start=WINDOW_START,
                cutoff=CUTOFF,
            )
            before = scan_corpus(config)
            run = normalize_census(before.manifest_document, config)
            after = scan_corpus(config)

        self.assertEqual(before.source_byte_sha256, after.source_byte_sha256)
        self.assertTrue(run.source_integrity["source_bytes_unchanged"])
        terminals = {(record["terminal_status"], record["reason"]) for record in run.coverage_document["records"]}
        self.assertIn(("quarantined", "record_too_large"), terminals)
        self.assertIn(("quarantined", "credential_detected"), terminals)
        self.assertTrue(run.coverage_complete)

    def test_post_cutoff_append_records_raw_delta_without_breaking_fixed_window_outputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            codex_root = temporary_path / "codex"
            claude_root = temporary_path / "claude"
            codex_root.mkdir()
            claude_root.mkdir()
            source_path = codex_root / "safe.jsonl"
            source_path.write_text((SECURITY / "codex-safe.jsonl").read_text(encoding="utf-8"), encoding="utf-8")
            config = CensusConfig(
                source_roots={"codex": codex_root, "claude": claude_root},
                window_start=WINDOW_START,
                cutoff=CUTOFF,
            )
            manifest = scan_corpus(config).manifest_document
            first = normalize_census(manifest, config)
            with source_path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps({
                    "timestamp": "2026-08-24T15:00:00Z",
                    "type": "response_item",
                    "payload": {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "post-cutoff"}]},
                }) + "\n")
            second = normalize_census(manifest, config)

        self.assertTrue(first.source_integrity["opened_descriptor_bytes_unchanged_during_read"])
        self.assertTrue(second.source_integrity["opened_descriptor_bytes_unchanged_during_read"])
        self.assertTrue(first.source_integrity["fixed_window_manifest_match_complete"])
        self.assertTrue(second.source_integrity["fixed_window_manifest_match_complete"])
        self.assertNotEqual(first.source_byte_sha256, second.source_byte_sha256)
        self.assertNotEqual(
            first.source_integrity["opened_source_bytes_sha256"],
            second.source_integrity["opened_source_bytes_sha256"],
        )
        self.assertEqual(first.packet_manifest_document, second.packet_manifest_document)
        self.assertEqual(first.coverage_document, second.coverage_document)

    def test_private_outputs_reject_unsafe_roots_and_are_private(self):
        result = normalize_records(
            artifact("codex", event_count=4),
            read_fixture("codex-safe.jsonl"),
            window_start=WINDOW_START,
            cutoff=CUTOFF,
        )
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            unsafe = temporary_path / "unsafe"
            unsafe.mkdir(mode=0o755)
            os.chmod(unsafe, 0o755)
            with self.assertRaisesRegex(ValueError, "private_output_permissions_unsafe"):
                write_normalization_private(result, unsafe, require_ignored=False)

            target = temporary_path / "private"
            written = write_normalization_private(result, target, require_ignored=False)
            self.assertEqual(target.stat().st_mode & 0o777, 0o700)
            for output_path in written.files:
                self.assertEqual(output_path.stat().st_mode & 0o777, 0o600)

            symlink = temporary_path / "symlink"
            symlink.symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "private_output_symlink"):
                write_normalization_private(result, symlink, require_ignored=False)

    def test_cli_normalizes_to_an_ignored_private_root_without_exposing_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            codex_root = temporary_path / "codex"
            claude_root = temporary_path / "claude"
            codex_root.mkdir()
            claude_root.mkdir()
            (codex_root / "safe.jsonl").write_text((SECURITY / "codex-safe.jsonl").read_text(encoding="utf-8"), encoding="utf-8")
            config = CensusConfig(
                source_roots={"codex": codex_root, "claude": claude_root},
                window_start=WINDOW_START,
                cutoff=CUTOFF,
            )
            manifest_path = temporary_path / "manifest.json"
            manifest_path.write_text(json.dumps(scan_corpus(config).manifest_document), encoding="utf-8")
            config_path = temporary_path / "config.json"
            config_path.write_text(json.dumps({
                "source_roots": {"codex": str(codex_root), "claude": str(claude_root)},
                "window_start": "2026-08-16T20:00:00Z",
                "window_cutoff": "2026-08-24T14:57:36Z",
                "output_root": ".u8-private/census",
            }), encoding="utf-8")
            output_root = ROOT / ".u8-private" / "u2-cli-normalize-test"
            stream = io.StringIO()
            try:
                with contextlib.redirect_stdout(stream):
                    status = main([
                        "normalize",
                        "--config", str(config_path),
                        "--manifest", str(manifest_path),
                        "--output-root", str(output_root),
                        "--verify-determinism",
                    ])
                result = json.loads(stream.getvalue())
                self.assertEqual(status, 0)
                self.assertEqual(result["status"], "normalized")
                self.assertTrue(result["determinism"]["packet_manifest_sha256_stable"])
                self.assertNotIn(str(codex_root), stream.getvalue())
                self.assertNotIn(str(output_root.resolve()), stream.getvalue())
            finally:
                if output_root.exists():
                    shutil.rmtree(output_root)


if __name__ == "__main__":
    unittest.main()
