import contextlib
import io
import json
import os
import shutil
import stat
import tempfile
import unittest
from pathlib import Path

from marketing_intelligence.census import (
    CENSUS_CUTOFF,
    CENSUS_START,
    CensusConfig,
    scan_corpus,
    validate_schema_document,
    write_census_private,
)
from marketing_intelligence.cli import main


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"


def fixture_config(*, codex_root: Path | None = None, claude_root: Path | None = None) -> CensusConfig:
    return CensusConfig(
        source_roots={
            "codex": codex_root or FIXTURES / "codex",
            "claude": claude_root or FIXTURES / "claude",
        },
        window_start=CENSUS_START,
        cutoff=CENSUS_CUTOFF,
    )


class CensusTests(unittest.TestCase):
    def test_characterized_cross_harness_fixture_census_preserves_relationships(self):
        result = scan_corpus(fixture_config())

        self.assertEqual(result.summary["scanned_artifacts"], 11)
        self.assertEqual(result.summary["by_harness"]["codex"]["scanned_artifacts"], 6)
        self.assertEqual(result.summary["by_harness"]["claude"]["scanned_artifacts"], 5)
        self.assertEqual(result.summary["terminal_statuses"], {"complete": 8, "excluded": 2, "quarantined": 1, "failed": 0})
        self.assertTrue(result.summary["zero_unaccounted"])
        self.assertEqual(result.source_integrity["source_changes_observed_during_scan"], 0)
        self.assertTrue(result.source_integrity["read_only_input_preserved"])

        records = {record["artifact_id"]: record for record in result.manifest_document["records"]}
        codex_children = [record for record in records.values() if record["logical_session_id"] in {"codex-child-one", "codex-child-two"}]
        self.assertEqual(len(codex_children), 2)
        self.assertEqual({record["parent_logical_session_id"] for record in codex_children}, {"codex-root"})
        self.assertTrue(all(record["artifact_id"] != record["logical_session_id"] for record in records.values()))
        codex_root = next(record for record in records.values() if record["logical_session_id"] == "codex-root")
        self.assertEqual(codex_root["session_container_id"], "codex-container-root")

        claude_records = [record for record in records.values() if record["logical_session_id"] == "claude-shared"]
        self.assertEqual(len(claude_records), 3)
        self.assertEqual(len({record["artifact_id"] for record in claude_records}), 3)
        child = next(record for record in claude_records if record["sidechain"] is True)
        self.assertEqual(child["classification"]["execution_shape"]["provenance"], "observed")
        self.assertEqual(child["classification"]["execution_shape"]["value"], "sdk")

    def test_event_window_is_half_open_and_post_cutoff_bytes_do_not_change_hash(self):
        with tempfile.TemporaryDirectory() as temporary:
            corpus = Path(temporary) / "corpus"
            shutil.copytree(FIXTURES, corpus)
            root_source = corpus / "codex" / "root.jsonl"
            first = scan_corpus(fixture_config(codex_root=corpus / "codex", claude_root=corpus / "claude"))
            first_root = next(record for record in first.manifest_document["records"] if record["logical_session_id"] == "codex-root")
            self.assertEqual(first_root["in_window_event_count"], 2)
            self.assertEqual(first_root["last_in_window_timestamp"], "2026-08-18T10:00:00Z")

            root_source.write_text(
                root_source.read_text(encoding="utf-8")
                + '{"timestamp":"2026-08-24T15:01:00Z","type":"session_meta","payload":{"id":"post-cutoff-metadata","session_id":"post-cutoff-container","parent_thread_id":"post-cutoff-parent","source":"sdk"}}\n',
                encoding="utf-8",
            )
            second = scan_corpus(fixture_config(codex_root=corpus / "codex", claude_root=corpus / "claude"))
            second_root = next(record for record in second.manifest_document["records"] if record["logical_session_id"] == "codex-root")
            self.assertEqual(first_root["content_sha256"], second_root["content_sha256"])
            self.assertEqual(first_root["in_window_event_count"], second_root["in_window_event_count"])
            self.assertEqual(first.manifest_sha256, second.manifest_sha256)
            self.assertEqual(first.coverage_sha256, second.coverage_sha256)
            self.assertEqual(second.observation_counters["post_cutoff_identity_conflicts"], 1)

    def test_authoritative_harness_identity_fields_preserve_primary_ids_without_false_conflicts(self):
        with tempfile.TemporaryDirectory() as temporary:
            corpus = Path(temporary) / "corpus"
            shutil.copytree(FIXTURES, corpus)
            codex_source = corpus / "codex" / "root.jsonl"
            claude_source = corpus / "claude" / "root.jsonl"
            codex_source.write_text(
                codex_source.read_text(encoding="utf-8")
                + '{"timestamp":"2026-08-19T10:00:00Z","type":"session_meta","payload":{"id":"codex-retained-history","session_id":"codex-retained-container","source":"sdk"}}\n',
                encoding="utf-8",
            )
            claude_source.write_text(
                claude_source.read_text(encoding="utf-8")
                + '{"timestamp":"2026-08-19T10:00:00Z","type":"assistant","sessionId":"claude-shared","session_id":"claude-retained-lineage","message":{"role":"assistant","content":[]}}\n',
                encoding="utf-8",
            )
            result = scan_corpus(fixture_config(codex_root=corpus / "codex", claude_root=corpus / "claude"))

        codex_root = next(record for record in result.manifest_document["records"] if record["logical_session_id"] == "codex-root")
        claude_root = next(
            record
            for record in result.manifest_document["records"]
            if record["harness"] == "claude" and record["logical_session_id"] == "claude-shared" and record["sidechain"] is False
        )
        self.assertEqual(codex_root["session_container_id"], "codex-container-root")
        self.assertEqual(claude_root["logical_session_id"], "claude-shared")
        self.assertEqual(result.observation_counters["conflicting_logical_session_ids"], 0)
        self.assertGreaterEqual(result.observation_counters["supplemental_session_ids"], 3)

    def test_old_mtime_does_not_exclude_in_window_event_and_invalid_records_are_accounted(self):
        with tempfile.TemporaryDirectory() as temporary:
            corpus = Path(temporary) / "corpus"
            shutil.copytree(FIXTURES, corpus)
            old_file = corpus / "codex" / "old-mtime.jsonl"
            os.utime(old_file, (1, 1))
            result = scan_corpus(fixture_config(codex_root=corpus / "codex", claude_root=corpus / "claude"))

        old_record = next(record for record in result.manifest_document["records"] if record["logical_session_id"] == "codex-old-mtime")
        malformed = next(record for record in result.manifest_document["records"] if record["logical_session_id"] == "codex-malformed")
        self.assertEqual(old_record["terminal_status"], "complete")
        self.assertEqual(malformed["terminal_status"], "quarantined")
        self.assertGreaterEqual(result.observation_counters["malformed_lines"], 1)
        self.assertGreaterEqual(result.observation_counters["missing_timestamp_records"], 1)
        self.assertGreaterEqual(result.observation_counters["unknown_record_types"], 1)

    def test_symlinks_and_special_files_are_quarantined_without_opening_content(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            codex = root / "codex"
            claude = root / "claude"
            codex.mkdir()
            claude.mkdir()
            (codex / "regular.jsonl").write_text(
                '{"timestamp":"2026-08-18T10:00:00Z","type":"session_meta","payload":{"id":"safe"}}\n',
                encoding="utf-8",
            )
            outside = root / "outside.jsonl"
            outside.write_text('{"timestamp":"2026-08-18T10:00:00Z","type":"session_meta"}\n', encoding="utf-8")
            (codex / "outside-link.jsonl").symlink_to(outside)
            fifo = codex / "unsafe.fifo.jsonl"
            os.mkfifo(fifo)
            try:
                result = scan_corpus(fixture_config(codex_root=codex, claude_root=claude))
            finally:
                fifo.unlink()

        unsafe = [record for record in result.coverage_document["records"] if record["terminal_status"] == "quarantined"]
        self.assertEqual(len(unsafe), 2)
        self.assertEqual({record["reason"] for record in unsafe}, {"symlink_rejected", "special_file_rejected"})
        self.assertNotIn(str(outside), json.dumps(result.manifest_document))
        self.assertEqual(validate_schema_document(result.manifest_document, ROOT / "schemas" / "session-manifest.schema.json"), ())

    def test_documents_validate_are_deterministic_and_private_writes_are_private(self):
        result = scan_corpus(fixture_config())
        self.assertEqual(validate_schema_document(result.manifest_document, ROOT / "schemas" / "session-manifest.schema.json"), ())
        self.assertEqual(validate_schema_document(result.coverage_document, ROOT / "schemas" / "coverage-record.schema.json"), ())
        self.assertEqual(result.manifest_sha256, scan_corpus(fixture_config()).manifest_sha256)
        self.assertEqual(result.coverage_sha256, scan_corpus(fixture_config()).coverage_sha256)

        with tempfile.TemporaryDirectory() as temporary:
            output = write_census_private(result, Path(temporary) / "private", require_ignored=False)
            self.assertEqual(output.root.stat().st_mode & 0o777, 0o700)
            self.assertEqual(output.run_directory.stat().st_mode & 0o777, 0o700)
            for path in output.files:
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            receipt = json.loads(output.receipt_path.read_text(encoding="utf-8"))
            self.assertNotIn(str(FIXTURES), json.dumps(receipt))

    def test_cli_uses_ignored_private_output_and_never_prints_source_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            config_path = temporary_path / "config.json"
            output_root = ROOT / ".u8-private" / "u1-cli-test"
            config_path.write_text(
                json.dumps(
                    {
                        "source_roots": {"codex": str(FIXTURES / "codex"), "claude": str(FIXTURES / "claude")},
                        "window_start": "2026-08-16T20:00:00Z",
                        "window_cutoff": "2026-08-24T14:57:36Z",
                        "output_root": str(output_root),
                    }
                ),
                encoding="utf-8",
            )
            stream = io.StringIO()
            try:
                with contextlib.redirect_stdout(stream):
                    status = main(["census", "--config", str(config_path), "--verify-determinism"])
                self.assertEqual(status, 0)
                self.assertNotIn(str(FIXTURES), stream.getvalue())
                self.assertNotIn(str(output_root.resolve()), stream.getvalue())
                determinism = json.loads(stream.getvalue())["determinism"]
                self.assertTrue(determinism["manifest_sha256_stable"])
                self.assertTrue(determinism["coverage_sha256_stable"])
                self.assertTrue(determinism["source_bytes_unchanged"])
                self.assertTrue(determinism["input_bytes_unchanged_during_each_scan"])
                self.assertEqual(determinism["source_delta"]["source_artifacts_changed"], 0)
                self.assertEqual(determinism["source_delta"]["canonical_records_changed"], 0)
            finally:
                if output_root.exists():
                    shutil.rmtree(output_root)


if __name__ == "__main__":
    unittest.main()
