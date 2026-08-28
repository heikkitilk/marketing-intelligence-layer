from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import stat
import tempfile
import unittest

from marketing_intelligence.census import canonical_json, validate_schema_document
from marketing_intelligence.cli import _safe_reason
from marketing_intelligence.review import (
    HumanReviewError,
    build_publication,
    build_review_queue,
    render_published_html,
    render_review_html,
    write_publication_artifacts,
    write_review_artifacts,
)


def probe_candidate(
    candidate_id: str,
    *,
    title: str,
    content: str,
    evidence: str,
    accepted: bool = True,
    reason: str = "accepted",
) -> dict[str, object]:
    return {
        "candidate_id": candidate_id,
        "accepted": accepted,
        "reason": reason,
        "candidate": {
            "id": candidate_id,
            "title": title,
            "content": content,
            "decision": "Use the observed result when planning the next marketing action.",
            "evidence": [evidence],
            "label": "[DATA]",
            "topic": "paid advertising",
            "type": "measurement",
        },
    }


def probe_receipt(*decisions: dict[str, object]) -> dict[str, object]:
    return {
        "receipt_sha256": "a" * 64,
        "receipt": {
            "status": "passed",
            "candidate_decisions": list(decisions),
            "qualifying_learnings": sum(bool(row["accepted"]) for row in decisions),
        },
    }


class HumanReviewTest(unittest.TestCase):
    def test_queue_is_deterministic_and_exact_duplicates_retain_all_support(self) -> None:
        first = probe_candidate(
            "c1",
            title="Paid campaign lesson",
            content="A paid campaign produced a measured result.",
            evidence="session://claude/session-one@" + "1" * 64 + "#event=e-one",
        )
        duplicate = probe_candidate(
            "c2",
            title="Paid campaign lesson",
            content="A paid campaign produced a measured result.",
            evidence="session://codex/session-two@" + "2" * 64 + "#event=e-two",
        )
        rejected = probe_candidate(
            "c3",
            title="Rejected machine candidate",
            content="This must not enter the human review queue.",
            evidence="session://claude/session-three@" + "3" * 64 + "#event=e-three",
            accepted=False,
            reason="unresolvable_evidence",
        )

        queue = build_review_queue(probe_receipt(first, duplicate, rejected))
        repeated = build_review_queue(probe_receipt(first, duplicate, rejected))

        self.assertEqual(queue, repeated)
        self.assertEqual(queue["schema_version"], "human-review-queue/v1")
        self.assertEqual(queue["machine_qualified_count"], 2)
        self.assertEqual(queue["review_candidate_count"], 1)
        self.assertEqual(queue["exact_duplicates_collapsed"], 1)
        self.assertEqual(len(queue["candidates"]), 1)
        candidate = queue["candidates"][0]
        self.assertEqual(candidate["review_status"], "pending")
        self.assertEqual(candidate["support_count"], 2)
        self.assertEqual(len(candidate["evidence_uris"]), 2)
        self.assertEqual(candidate["source_candidate_ids"], ["c1", "c2"])
        self.assertRegex(queue["queue_sha256"], r"^[a-f0-9]{64}$")

    def test_duplicate_rows_from_one_session_count_as_one_support_source(self) -> None:
        first = probe_candidate(
            "c1",
            title="Repeated lesson",
            content="One session produced the same measured result twice.",
            evidence="session://claude/same-session@" + "1" * 64 + "#event=e-one",
        )
        duplicate = probe_candidate(
            "c2",
            title="Repeated lesson",
            content="One session produced the same measured result twice.",
            evidence="session://claude/same-session@" + "1" * 64 + "#event=e-two",
        )

        candidate = build_review_queue(probe_receipt(first, duplicate))["candidates"][0]

        self.assertEqual(candidate["support_count"], 1)
        self.assertEqual(candidate["source_candidate_ids"], ["c1", "c2"])

    def test_review_html_is_offline_escaped_and_exports_hash_bound_decisions(self) -> None:
        dangerous = probe_candidate(
            "c1",
            title="<script>alert('title')</script>",
            content="Measured marketing result & follow-up.",
            evidence="session://claude/session-one@" + "1" * 64 + "#event=e-one",
        )
        queue = build_review_queue(probe_receipt(dangerous))

        html = render_review_html(queue)

        self.assertNotIn("<script>alert('title')</script>", html)
        self.assertIn("Export decisions", html)
        self.assertIn(queue["queue_sha256"], html)
        self.assertIn("session://claude/session-one", html)
        self.assertNotIn("https://cdn", html)
        self.assertIn("human-review-decisions/v1", html)
        self.assertIn("JSON.stringify(payload,null,2)+'\\n'", html)
        self.assertIn("card.dataset.search", html)
        self.assertIn("Fields changed. Select Accept edits", html)
        self.assertIn("Fix the highlighted edited proposal", html)

    def test_publication_requires_complete_hash_bound_terminal_decisions(self) -> None:
        candidates = [
            probe_candidate(
                "c1",
                title="Accept this",
                content="A measured campaign result should be retained.",
                evidence="session://claude/session-one@" + "1" * 64 + "#event=e-one",
            ),
            probe_candidate(
                "c2",
                title="Edit this",
                content="An initial summary needs a human correction.",
                evidence="session://claude/session-two@" + "2" * 64 + "#event=e-two",
            ),
            probe_candidate(
                "c3",
                title="Reject this",
                content="A candidate can be structurally valid but not worth keeping.",
                evidence="session://claude/session-three@" + "3" * 64 + "#event=e-three",
            ),
        ]
        queue = build_review_queue(probe_receipt(*candidates))
        ids = {row["title"]: row["candidate_id"] for row in queue["candidates"]}
        incomplete = {
            "schema_version": "human-review-decisions/v1",
            "queue_sha256": queue["queue_sha256"],
            "reviewer": "Heikki",
            "decisions": [{"candidate_id": ids["Accept this"], "decision": "accept"}],
        }
        with self.assertRaisesRegex(HumanReviewError, "review_decisions_incomplete"):
            build_publication(queue, incomplete)

        decisions = {
            "schema_version": "human-review-decisions/v1",
            "queue_sha256": queue["queue_sha256"],
            "reviewer": "Heikki",
            "decisions": [
                {"candidate_id": ids["Accept this"], "decision": "accept"},
                {
                    "candidate_id": ids["Edit this"],
                    "decision": "edit",
                    "edits": {
                        "title": "Human-corrected title",
                        "topic": "attribution_measurement",
                    },
                },
                {"candidate_id": ids["Reject this"], "decision": "reject", "rationale": "Not useful."},
            ],
        }
        publication = build_publication(queue, decisions)

        self.assertEqual(publication["schema_version"], "accepted-intelligence/v1")
        self.assertEqual(publication["reviewer"], "Heikki")
        self.assertEqual(publication["source_sha256"], queue["source_sha256"])
        self.assertEqual(publication["source_payload_sha256"], queue["source_payload_sha256"])
        self.assertEqual(publication["decision_counts"], {"accept": 1, "edit": 1, "reject": 1})
        self.assertEqual(len(publication["learnings"]), 2)
        edited = next(row for row in publication["learnings"] if row["title"] == "Human-corrected title")
        self.assertEqual(edited["topic"], "attribution_measurement")
        self.assertEqual(edited["review_decision"], "edit")
        self.assertTrue(all(row["title"] != "Reject this" for row in publication["learnings"]))

    def test_publication_rejects_queue_drift_duplicate_decisions_and_invalid_edits(self) -> None:
        queue = build_review_queue(probe_receipt(probe_candidate(
            "c1",
            title="One proposal",
            content="One measured marketing proposal.",
            evidence="session://claude/session-one@" + "1" * 64 + "#event=e-one",
        )))
        candidate_id = queue["candidates"][0]["candidate_id"]
        base = {
            "schema_version": "human-review-decisions/v1",
            "queue_sha256": "f" * 64,
            "reviewer": "Heikki",
            "decisions": [{"candidate_id": candidate_id, "decision": "accept"}],
        }
        with self.assertRaisesRegex(HumanReviewError, "review_queue_hash_mismatch"):
            build_publication(queue, base)

        base["queue_sha256"] = queue["queue_sha256"]
        base["decisions"] = base["decisions"] * 2
        with self.assertRaisesRegex(HumanReviewError, "review_decision_duplicate"):
            build_publication(queue, base)

        base["decisions"] = [{
            "candidate_id": candidate_id,
            "decision": "edit",
            "edits": {"topic": "not-a-topic"},
        }]
        with self.assertRaisesRegex(HumanReviewError, "review_edit_topic_invalid"):
            build_publication(queue, base)

        tampered = dict(queue)
        tampered_candidates = [dict(queue["candidates"][0])]
        tampered_candidates[0]["candidate_id"] = "candidate-" + "f" * 24
        tampered["candidates"] = tampered_candidates
        unsigned = {key: value for key, value in tampered.items() if key != "queue_sha256"}
        tampered["queue_sha256"] = hashlib.sha256(canonical_json(unsigned).encode()).hexdigest()
        with self.assertRaisesRegex(HumanReviewError, "review_queue_candidate_identity_mismatch"):
            build_publication(tampered, base)

    def test_published_html_contains_only_reviewed_learning_and_search(self) -> None:
        queue = build_review_queue(probe_receipt(
            probe_candidate(
                "c1",
                title="Accepted <learning>",
                content="A reviewed marketing result.",
                evidence="session://claude/session-one@" + "1" * 64 + "#event=e-one",
            ),
            probe_candidate(
                "c2",
                title="Rejected learning",
                content="This must not be published.",
                evidence="session://claude/session-two@" + "2" * 64 + "#event=e-two",
            ),
        ))
        ids = {row["title"]: row["candidate_id"] for row in queue["candidates"]}
        publication = build_publication(queue, {
            "schema_version": "human-review-decisions/v1",
            "queue_sha256": queue["queue_sha256"],
            "reviewer": "Heikki",
            "decisions": [
                {"candidate_id": ids["Accepted <learning>"], "decision": "accept"},
                {"candidate_id": ids["Rejected learning"], "decision": "reject"},
            ],
        })

        html = render_published_html(publication)

        self.assertIn("Search accepted intelligence", html)
        self.assertIn("Accepted &lt;learning&gt;", html)
        self.assertNotIn("Rejected learning", html)
        self.assertIn("Evidence", html)
        self.assertNotIn("<script>alert", html)

    def test_private_artifacts_use_owner_only_modes(self) -> None:
        queue = build_review_queue(probe_receipt(probe_candidate(
            "c1",
            title="Private proposal",
            content="A private reviewed marketing result.",
            evidence="session://claude/session-one@" + "1" * 64 + "#event=e-one",
        )))
        candidate_id = queue["candidates"][0]["candidate_id"]
        decisions = {
            "schema_version": "human-review-decisions/v1",
            "queue_sha256": queue["queue_sha256"],
            "reviewer": "Heikki",
            "decisions": [{"candidate_id": candidate_id, "decision": "accept"}],
        }
        publication = build_publication(queue, decisions)

        with tempfile.TemporaryDirectory() as directory:
            review_root = Path(directory) / "review"
            published_root = Path(directory) / "published"
            review_paths = write_review_artifacts(queue, review_root, require_ignored=False)
            published_paths = write_publication_artifacts(publication, published_root, require_ignored=False)

            self.assertEqual(stat.S_IMODE(review_root.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(published_root.stat().st_mode), 0o700)
            for path in (*review_paths.values(), *published_paths.values()):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

            with self.assertRaisesRegex(HumanReviewError, "review_output_exists"):
                write_review_artifacts(queue, review_root, require_ignored=False)
            with self.assertRaisesRegex(HumanReviewError, "review_output_exists"):
                write_publication_artifacts(publication, published_root, require_ignored=False)

    def test_empty_queue_is_not_reviewable(self) -> None:
        queue = build_review_queue(probe_receipt(probe_candidate(
            "c1",
            title="Rejected",
            content="No candidate reaches review.",
            evidence="session://claude/session-one@" + "1" * 64 + "#event=e-one",
            accepted=False,
            reason="not_useful",
        )))
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(HumanReviewError, "review_queue_empty"):
                write_review_artifacts(queue, Path(directory), require_ignored=False)

    def test_review_documents_conform_to_their_schemas(self) -> None:
        queue = build_review_queue(probe_receipt(probe_candidate(
            "c1",
            title="Schema-bound proposal",
            content="A reviewed result follows its published contract.",
            evidence="session://claude/session-one@" + "1" * 64 + "#event=e-one",
        )))
        candidate_id = queue["candidates"][0]["candidate_id"]
        decisions = {
            "schema_version": "human-review-decisions/v1",
            "queue_sha256": queue["queue_sha256"],
            "reviewer": "Heikki",
            "decisions": [{"candidate_id": candidate_id, "decision": "accept"}],
        }
        publication = build_publication(queue, decisions)
        schema_root = Path(__file__).resolve().parents[1] / "schemas"

        self.assertEqual(validate_schema_document(queue, schema_root / "human-review-queue.schema.json"), ())
        self.assertEqual(validate_schema_document(decisions, schema_root / "human-review-decisions.schema.json"), ())
        self.assertEqual(validate_schema_document(publication, schema_root / "accepted-intelligence.schema.json"), ())

        invalid_queue = copy.deepcopy(queue)
        invalid_queue["schema_version"] = "human-review-queue/wrong"
        invalid_queue["candidates"][0]["evidence_uris"] = [
            "session://claude/session-one@" + "1" * 64 + "#event=bad\tevent"
        ]
        errors = validate_schema_document(invalid_queue, schema_root / "human-review-queue.schema.json")
        self.assertIn("$.schema_version:const", errors)
        self.assertIn("$.candidates[0].evidence_uris[0]:pattern", errors)

    def test_review_errors_are_safe_and_specific(self) -> None:
        self.assertEqual(_safe_reason(HumanReviewError("review_decisions_incomplete")), "review_decisions_incomplete")
        self.assertEqual(_safe_reason(HumanReviewError("reviewer_required")), "reviewer_required")


if __name__ == "__main__":
    unittest.main()
