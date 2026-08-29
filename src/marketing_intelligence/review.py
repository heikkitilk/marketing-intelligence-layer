"""Human review and publication for session-derived marketing intelligence."""

from __future__ import annotations

from collections import Counter
import hashlib
import html
import json
from pathlib import Path
import re
from typing import Any, Mapping, Sequence

from .census import _REPOSITORY_ROOT, _private_root, canonical_json, validate_schema_document
from .extraction import CLAIM_LABELS, LEARNING_TYPES, TOPICS
from .redact import secure_write_text


QUEUE_SCHEMA_VERSION = "human-review-queue/v1"
DECISIONS_SCHEMA_VERSION = "human-review-decisions/v1"
PUBLICATION_SCHEMA_VERSION = "accepted-intelligence/v1"

_EDITABLE_FIELDS = frozenset({"title", "content", "action", "topic", "learning_type"})
_EVIDENCE_PATTERN = re.compile(
    r"^session://(?:codex|claude)/[^@\s]+@[a-f0-9]{64}#event=[^\s]+$"
)
_SCHEMA_ROOT = _REPOSITORY_ROOT / "schemas"


class HumanReviewError(ValueError):
    """A safe, content-free human-review contract error."""


def _sha256(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(dict(value)).encode("utf-8")).hexdigest()


def _validate_schema(document: Mapping[str, Any], filename: str, error: str) -> None:
    if validate_schema_document(document, _SCHEMA_ROOT / filename):
        raise HumanReviewError(error)


def _nonempty(value: object, error: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise HumanReviewError(error)
    return value.strip()


def _suggest_topic(candidate: Mapping[str, Any]) -> str:
    source_topic = str(candidate.get("topic", "")).casefold().replace("_", " ")
    source_rules = (
        ("ai_and_marketing_operations", ("platform api", "change control", "mutation authority", "automation workflow")),
        ("activation_onboarding", ("form routing", "landing page")),
        ("attribution_measurement", ("attribution", "measurement", "reporting", "retention", "traffic quality")),
        ("paid_advertising", ("creative", "campaign", "search term", "linkedin ads", "youtube", "placement", "targeting", "budget allocation", "media planning")),
    )
    for topic, terms in source_rules:
        if any(term in source_topic for term in terms):
            return topic

    text = " ".join(
        str(candidate.get(field, ""))
        for field in ("topic", "type", "title", "content", "decision")
    ).casefold()
    rules = (
        ("attribution_measurement", ("attribution", "measurement", "reporting", "retention", "benchmark")),
        ("seo", (" seo ", "organic search", "search engine optimization")),
        ("paid_advertising", ("paid", "campaign", "advert", "linkedin", "youtube", "reddit", "keyword", "creative", "media planning", "targeting")),
        ("activation_onboarding", ("activation", "onboarding", "form", "conversion")),
        ("product_marketing", ("positioning", "messaging", "competitive", "product marketing")),
        ("content_marketing", ("content marketing", "editorial", "thought leadership")),
        ("demand_generation", ("lead", "pipeline", "demand generation", "account fit")),
        ("ai_and_marketing_operations", (" api ", "agent", "automation", "workflow", "change control")),
        ("leadership_strategy", ("leadership", "team", "strategy")),
    )
    padded = f" {text} "
    for topic, terms in rules:
        if any(term in padded for term in terms):
            return topic
    return "leadership_strategy"


def _suggest_learning_type(candidate: Mapping[str, Any]) -> str:
    source_type = str(candidate.get("type", "")).casefold()
    if any(term in source_type for term in ("measure", "metric", "attribution")):
        return "metric"
    if any(term in source_type for term in ("framework", "formula", "process")):
        return "formula"
    if any(term in source_type for term in ("creative", "targeting", "channel", "media")):
        return "channel"
    return "finding"


def _candidate_identity(candidate: Mapping[str, Any]) -> str:
    identity = {
        key: candidate[key]
        for key in ("title", "content", "action", "topic", "learning_type", "claim_label")
    }
    return _sha256(identity)


def _normalize_probe_candidate(row: Mapping[str, Any]) -> dict[str, Any]:
    source = row.get("candidate")
    if not isinstance(source, Mapping):
        raise HumanReviewError("review_probe_candidate_invalid")
    title = _nonempty(source.get("title"), "review_probe_title_invalid")
    content = _nonempty(source.get("content"), "review_probe_content_invalid")
    action = _nonempty(source.get("decision"), "review_probe_action_invalid")
    claim_label = source.get("label")
    if claim_label not in CLAIM_LABELS:
        raise HumanReviewError("review_probe_claim_label_invalid")
    evidence = source.get("evidence")
    if (
        not isinstance(evidence, Sequence)
        or isinstance(evidence, (str, bytes))
        or not evidence
        or any(not isinstance(uri, str) or _EVIDENCE_PATTERN.fullmatch(uri) is None for uri in evidence)
    ):
        raise HumanReviewError("review_probe_evidence_invalid")
    source_candidate_id = _nonempty(row.get("candidate_id"), "review_probe_candidate_id_invalid")
    normalized: dict[str, Any] = {
        "title": title,
        "content": content,
        "action": action,
        "topic": _suggest_topic(source),
        "learning_type": _suggest_learning_type(source),
        "claim_label": claim_label,
        "source_topic": str(source.get("topic", "?")),
        "source_type": str(source.get("type", "?")),
        "evidence_uris": sorted(set(str(uri) for uri in evidence)),
        "source_candidate_ids": [source_candidate_id],
        "review_status": "pending",
    }
    identity = _candidate_identity(normalized)
    normalized["candidate_id"] = f"candidate-{identity[:24]}"
    normalized["support_count"] = 1
    return normalized


def build_review_queue(value_probe_envelope: Mapping[str, Any]) -> dict[str, Any]:
    """Turn machine-qualified value-probe results into pending human proposals."""

    receipt = value_probe_envelope.get("receipt")
    if not isinstance(receipt, Mapping):
        raise HumanReviewError("review_probe_receipt_invalid")
    decisions = receipt.get("candidate_decisions")
    if not isinstance(decisions, list):
        raise HumanReviewError("review_probe_decisions_invalid")

    by_identity: dict[str, dict[str, Any]] = {}
    evidence_by_identity: dict[str, set[str]] = {}
    source_ids_by_identity: dict[str, set[str]] = {}
    machine_rejected = 0
    machine_qualified = 0
    for row in decisions:
        if not isinstance(row, Mapping):
            raise HumanReviewError("review_probe_decision_invalid")
        if row.get("accepted") is not True or row.get("reason") != "accepted":
            machine_rejected += 1
            continue
        machine_qualified += 1
        candidate = _normalize_probe_candidate(row)
        identity = str(candidate["candidate_id"])
        existing = by_identity.get(identity)
        if existing is None:
            by_identity[identity] = candidate
            evidence_by_identity[identity] = set(candidate["evidence_uris"])
            source_ids_by_identity[identity] = set(candidate["source_candidate_ids"])
            continue
        evidence_by_identity[identity].update(candidate["evidence_uris"])
        source_ids_by_identity[identity].update(candidate["source_candidate_ids"])

    for identity, candidate in by_identity.items():
        candidate["evidence_uris"] = sorted(evidence_by_identity[identity])
        candidate["source_candidate_ids"] = sorted(source_ids_by_identity[identity])
        candidate["support_count"] = len({uri.split("@", 1)[0] for uri in candidate["evidence_uris"]})

    candidates = sorted(by_identity.values(), key=lambda row: str(row["candidate_id"]))
    source_sha256 = value_probe_envelope.get("receipt_sha256")
    if not isinstance(source_sha256, str) or re.fullmatch(r"[a-f0-9]{64}", source_sha256) is None:
        source_sha256 = _sha256(receipt)
    queue_core: dict[str, Any] = {
        "schema_version": QUEUE_SCHEMA_VERSION,
        "source_kind": "value-probe-receipt",
        "source_sha256": source_sha256,
        "source_payload_sha256": _sha256(receipt),
        "machine_qualified_count": machine_qualified,
        "machine_rejected_count": machine_rejected,
        "review_candidate_count": len(candidates),
        "exact_duplicates_collapsed": machine_qualified - len(candidates),
        "candidates": candidates,
    }
    queue = {**queue_core, "queue_sha256": _sha256(queue_core)}
    _validate_schema(queue, "human-review-queue.schema.json", "review_queue_schema_invalid")
    return queue


def build_extraction_review_queue(
    candidate_rows: Sequence[Mapping[str, Any]],
    *,
    source_sha256: str,
    source_payload_sha256: str,
    machine_rejected_count: int = 0,
    source_kind: str = "full-corpus-extraction",
) -> dict[str, Any]:
    """Turn validated full-corpus candidates into pending human proposals."""

    for value in (source_sha256, source_payload_sha256):
        if re.fullmatch(r"[a-f0-9]{64}", value) is None:
            raise HumanReviewError("review_extraction_source_hash_invalid")
    if (
        not isinstance(machine_rejected_count, int)
        or isinstance(machine_rejected_count, bool)
        or machine_rejected_count < 0
    ):
        raise HumanReviewError("review_extraction_rejected_count_invalid")
    if source_kind not in {"full-corpus-extraction", "reviewed-publication-consolidation"}:
        raise HumanReviewError("review_extraction_source_kind_invalid")

    by_identity: dict[str, dict[str, Any]] = {}
    evidence_by_identity: dict[str, set[str]] = {}
    source_ids_by_identity: dict[str, set[str]] = {}
    for source in candidate_rows:
        if not isinstance(source, Mapping):
            raise HumanReviewError("review_extraction_candidate_invalid")
        source_candidate_id = _nonempty(
            source.get("candidate_id"),
            "review_extraction_candidate_id_invalid",
        )
        evidence = source.get("evidence_uris")
        if (
            not isinstance(evidence, Sequence)
            or isinstance(evidence, (str, bytes))
            or not evidence
            or any(
                not isinstance(uri, str) or _EVIDENCE_PATTERN.fullmatch(uri) is None
                for uri in evidence
            )
        ):
            raise HumanReviewError("review_extraction_evidence_invalid")
        topic = source.get("topic")
        learning_type = source.get("learning_type")
        claim_label = source.get("claim_label")
        if topic not in TOPICS or learning_type not in LEARNING_TYPES:
            raise HumanReviewError("review_extraction_classification_invalid")
        if claim_label not in CLAIM_LABELS:
            raise HumanReviewError("review_extraction_claim_label_invalid")
        candidate: dict[str, Any] = {
            "title": _nonempty(source.get("title"), "review_extraction_title_invalid"),
            "content": _nonempty(source.get("summary"), "review_extraction_content_invalid"),
            "action": _nonempty(
                source.get("recommended_action"),
                "review_extraction_action_invalid",
            ),
            "topic": topic,
            "learning_type": learning_type,
            "claim_label": claim_label,
            "source_topic": str(topic),
            "source_type": str(learning_type),
            "evidence_uris": sorted(set(str(uri) for uri in evidence)),
            "source_candidate_ids": [source_candidate_id],
            "review_status": "pending",
        }
        identity = f"candidate-{_candidate_identity(candidate)[:24]}"
        candidate["candidate_id"] = identity
        existing = by_identity.get(identity)
        if existing is None:
            by_identity[identity] = candidate
            evidence_by_identity[identity] = set(candidate["evidence_uris"])
            source_ids_by_identity[identity] = {source_candidate_id}
        else:
            evidence_by_identity[identity].update(candidate["evidence_uris"])
            source_ids_by_identity[identity].add(source_candidate_id)

    for identity, candidate in by_identity.items():
        candidate["evidence_uris"] = sorted(evidence_by_identity[identity])
        candidate["source_candidate_ids"] = sorted(source_ids_by_identity[identity])
        candidate["support_count"] = len(
            {uri.split("@", 1)[0] for uri in candidate["evidence_uris"]}
        )

    candidates = sorted(by_identity.values(), key=lambda row: str(row["candidate_id"]))
    queue_core: dict[str, Any] = {
        "schema_version": QUEUE_SCHEMA_VERSION,
        "source_kind": source_kind,
        "source_sha256": source_sha256,
        "source_payload_sha256": source_payload_sha256,
        "machine_qualified_count": len(candidate_rows),
        "machine_rejected_count": machine_rejected_count,
        "review_candidate_count": len(candidates),
        "exact_duplicates_collapsed": len(candidate_rows) - len(candidates),
        "candidates": candidates,
    }
    queue = {**queue_core, "queue_sha256": _sha256(queue_core)}
    _validate_schema(queue, "human-review-queue.schema.json", "review_queue_schema_invalid")
    return queue


def build_consolidated_publication(
    publications: Sequence[Mapping[str, Any]],
    *,
    reviewer: str = "Consolidated previously reviewed intelligence",
) -> dict[str, Any]:
    """Combine already reviewed publications through the existing exact identity."""

    if len(publications) < 2:
        raise HumanReviewError("publication_consolidation_requires_multiple_inputs")
    hashes: list[str] = []
    candidate_rows: list[dict[str, Any]] = []
    for publication in publications:
        _validate_schema(
            publication,
            "accepted-intelligence.schema.json",
            "publication_schema_invalid",
        )
        publication_sha256 = publication.get("publication_sha256")
        unsigned = {key: value for key, value in publication.items() if key != "publication_sha256"}
        if not isinstance(publication_sha256, str) or _sha256(unsigned) != publication_sha256:
            raise HumanReviewError("publication_hash_mismatch")
        hashes.append(publication_sha256)
        for learning in publication.get("learnings", ()):
            if not isinstance(learning, Mapping):
                raise HumanReviewError("publication_learning_invalid")
            candidate_rows.append({
                "candidate_id": str(learning["learning_id"]),
                "title": learning["title"],
                "summary": learning["content"],
                "recommended_action": learning["action"],
                "topic": learning["topic"],
                "learning_type": learning["learning_type"],
                "claim_label": learning["claim_label"],
                "evidence_uris": learning["evidence_uris"],
            })
    source_sha256 = _sha256({"publication_sha256s": sorted(hashes)})
    queue = build_extraction_review_queue(
        candidate_rows,
        source_sha256=source_sha256,
        source_payload_sha256=_sha256({
            "publications": [dict(publication) for publication in publications],
        }),
        source_kind="reviewed-publication-consolidation",
    )
    decisions = {
        "schema_version": DECISIONS_SCHEMA_VERSION,
        "queue_sha256": queue["queue_sha256"],
        "reviewer": _nonempty(reviewer, "reviewer_required"),
        "decisions": [
            {"candidate_id": row["candidate_id"], "decision": "accept"}
            for row in queue["candidates"]
        ],
    }
    return build_publication(queue, decisions)


def _validated_queue(queue: Mapping[str, Any]) -> tuple[str, dict[str, Mapping[str, Any]]]:
    if queue.get("schema_version") != QUEUE_SCHEMA_VERSION:
        raise HumanReviewError("review_queue_schema_invalid")
    queue_sha256 = queue.get("queue_sha256")
    if not isinstance(queue_sha256, str) or re.fullmatch(r"[a-f0-9]{64}", queue_sha256) is None:
        raise HumanReviewError("review_queue_hash_invalid")
    unsigned = {key: value for key, value in queue.items() if key != "queue_sha256"}
    if _sha256(unsigned) != queue_sha256:
        raise HumanReviewError("review_queue_hash_mismatch")
    rows = queue.get("candidates")
    if not isinstance(rows, list):
        raise HumanReviewError("review_queue_candidates_invalid")
    if not rows:
        raise HumanReviewError("review_queue_empty")
    if queue.get("review_candidate_count") != len(rows):
        raise HumanReviewError("review_queue_candidate_count_mismatch")
    machine_qualified = queue.get("machine_qualified_count")
    collapsed = queue.get("exact_duplicates_collapsed")
    if (
        not isinstance(machine_qualified, int)
        or isinstance(machine_qualified, bool)
        or not isinstance(collapsed, int)
        or isinstance(collapsed, bool)
        or machine_qualified - collapsed != len(rows)
    ):
        raise HumanReviewError("review_queue_dedup_count_mismatch")
    by_id: dict[str, Mapping[str, Any]] = {}
    for row in rows:
        if not isinstance(row, Mapping):
            raise HumanReviewError("review_queue_candidate_invalid")
        candidate_id = row.get("candidate_id")
        if (
            not isinstance(candidate_id, str)
            or re.fullmatch(r"candidate-[a-f0-9]{24}", candidate_id) is None
            or candidate_id in by_id
        ):
            raise HumanReviewError("review_queue_candidate_duplicate")
        if candidate_id != f"candidate-{_candidate_identity(row)[:24]}":
            raise HumanReviewError("review_queue_candidate_identity_mismatch")
        for field in ("title", "content", "action", "source_topic", "source_type"):
            _nonempty(row.get(field), f"review_queue_{field}_invalid")
        if row.get("topic") not in TOPICS or row.get("learning_type") not in LEARNING_TYPES:
            raise HumanReviewError("review_queue_classification_invalid")
        if row.get("claim_label") not in CLAIM_LABELS:
            raise HumanReviewError("review_queue_claim_label_invalid")
        if row.get("review_status") != "pending":
            raise HumanReviewError("review_queue_status_invalid")
        evidence = row.get("evidence_uris")
        source_ids = row.get("source_candidate_ids")
        if (
            not isinstance(evidence, list)
            or not evidence
            or len(evidence) != len(set(evidence))
            or any(not isinstance(uri, str) or _EVIDENCE_PATTERN.fullmatch(uri) is None for uri in evidence)
        ):
            raise HumanReviewError("review_queue_evidence_invalid")
        if (
            not isinstance(source_ids, list)
            or not source_ids
            or len(source_ids) != len(set(source_ids))
            or any(not isinstance(source_id, str) or not source_id for source_id in source_ids)
            or row.get("support_count") != len({uri.split("@", 1)[0] for uri in evidence})
        ):
            raise HumanReviewError("review_queue_support_invalid")
        by_id[candidate_id] = row
    return queue_sha256, by_id


def _apply_edits(candidate: Mapping[str, Any], edits: object) -> dict[str, Any]:
    if not isinstance(edits, Mapping) or not edits:
        raise HumanReviewError("review_edits_required")
    if set(edits) - _EDITABLE_FIELDS:
        raise HumanReviewError("review_edit_field_invalid")
    updated = dict(candidate)
    for field, value in edits.items():
        updated[field] = _nonempty(value, f"review_edit_{field}_invalid")
    if updated.get("topic") not in TOPICS:
        raise HumanReviewError("review_edit_topic_invalid")
    if updated.get("learning_type") not in LEARNING_TYPES:
        raise HumanReviewError("review_edit_learning_type_invalid")
    return updated


def build_publication(queue: Mapping[str, Any], decisions_document: Mapping[str, Any]) -> dict[str, Any]:
    """Publish only after every queued proposal has one terminal human decision."""

    queue_sha256, candidates = _validated_queue(queue)
    if decisions_document.get("schema_version") != DECISIONS_SCHEMA_VERSION:
        raise HumanReviewError("review_decisions_schema_invalid")
    if decisions_document.get("queue_sha256") != queue_sha256:
        raise HumanReviewError("review_queue_hash_mismatch")
    reviewer = _nonempty(decisions_document.get("reviewer"), "reviewer_required")
    rows = decisions_document.get("decisions")
    if not isinstance(rows, list):
        raise HumanReviewError("review_decisions_invalid")

    by_id: dict[str, Mapping[str, Any]] = {}
    for row in rows:
        if not isinstance(row, Mapping):
            raise HumanReviewError("review_decision_invalid")
        if set(row) - {"candidate_id", "decision", "rationale", "edits"}:
            raise HumanReviewError("review_decision_field_invalid")
        candidate_id = row.get("candidate_id")
        if not isinstance(candidate_id, str) or candidate_id not in candidates:
            raise HumanReviewError("review_decision_candidate_unknown")
        if candidate_id in by_id:
            raise HumanReviewError("review_decision_duplicate")
        status = row.get("decision")
        if status not in {"accept", "reject", "edit"}:
            raise HumanReviewError("review_decision_status_invalid")
        if "rationale" in row and not isinstance(row["rationale"], str):
            raise HumanReviewError("review_decision_rationale_invalid")
        if status != "edit" and "edits" in row:
            raise HumanReviewError("review_edits_unexpected")
        by_id[candidate_id] = row
    if set(by_id) != set(candidates):
        raise HumanReviewError("review_decisions_incomplete")

    counts: Counter[str] = Counter()
    accepted: list[dict[str, Any]] = []
    for candidate_id in sorted(candidates):
        decision = by_id[candidate_id]
        status = str(decision["decision"])
        counts[status] += 1
        if status == "reject":
            continue
        candidate = dict(candidates[candidate_id])
        if status == "edit":
            candidate = _apply_edits(candidate, decision.get("edits"))
        learning_body = {
            key: candidate[key]
            for key in (
                "title", "content", "action", "topic", "learning_type", "claim_label",
                "evidence_uris", "source_candidate_ids", "support_count",
            )
        }
        learning_id = "learning-" + hashlib.sha256(
            (candidate_id + "\0" + canonical_json(learning_body)).encode("utf-8")
        ).hexdigest()[:24]
        accepted.append({
            "learning_id": learning_id,
            "review_candidate_id": candidate_id,
            "review_decision": status,
            **learning_body,
        })

    _validate_schema(
        decisions_document,
        "human-review-decisions.schema.json",
        "review_decisions_schema_invalid",
    )
    decision_counts = {name: counts.get(name, 0) for name in ("accept", "edit", "reject")}
    decisions_sha256 = _sha256(decisions_document)
    core: dict[str, Any] = {
        "schema_version": PUBLICATION_SCHEMA_VERSION,
        "queue_sha256": queue_sha256,
        "source_sha256": queue["source_sha256"],
        "source_payload_sha256": queue["source_payload_sha256"],
        "decisions_sha256": decisions_sha256,
        "reviewer": reviewer,
        "decision_counts": decision_counts,
        "learnings": sorted(accepted, key=lambda row: str(row["learning_id"])),
    }
    publication = {**core, "publication_sha256": _sha256(core)}
    _validate_schema(
        publication,
        "accepted-intelligence.schema.json",
        "publication_schema_invalid",
    )
    return publication


def _escape(value: object) -> str:
    return html.escape(str(value), quote=True)


def _topic_options(selected: str) -> str:
    labels = {
        "demand_generation": "Demand generation",
        "paid_advertising": "Paid advertising",
        "seo": "SEO",
        "content_marketing": "Content marketing",
        "attribution_measurement": "Attribution and measurement",
        "product_marketing": "Product marketing",
        "activation_onboarding": "Activation and onboarding",
        "leadership_strategy": "Leadership and strategy",
        "ai_and_marketing_operations": "AI and marketing operations",
    }
    return "".join(
        f'<option value="{key}"{" selected" if key == selected else ""}>{_escape(label)}</option>'
        for key, label in labels.items()
    )


def _type_options(selected: str) -> str:
    return "".join(
        f'<option value="{kind}"{" selected" if kind == selected else ""}>{_escape(kind.title())}</option>'
        for kind in sorted(LEARNING_TYPES)
    )


def render_review_html(queue: Mapping[str, Any]) -> str:
    """Render an offline decision workbench without publishing candidates."""

    queue_sha256, _ = _validated_queue(queue)
    cards: list[str] = []
    for candidate in queue["candidates"]:
        evidence = "".join(f"<li><code>{_escape(uri)}</code></li>" for uri in candidate["evidence_uris"])
        search_text = " ".join(
            str(candidate[field])
            for field in ("title", "content", "action", "topic", "learning_type", "claim_label")
        ).casefold()
        cards.append(f"""
        <article class="candidate-card" data-candidate-id="{_escape(candidate['candidate_id'])}" data-status="pending" data-search="{_escape(search_text)}">
          <div class="card-head"><span class="claim">{_escape(candidate['claim_label'])}</span><code>{_escape(candidate['candidate_id'])}</code></div>
          <label>Title<input name="title" value="{_escape(candidate['title'])}"></label>
          <label>Learning<textarea name="content" rows="5">{_escape(candidate['content'])}</textarea></label>
          <label>Recommended action<textarea name="action" rows="3">{_escape(candidate['action'])}</textarea></label>
          <div class="grid"><label>Topic<select name="topic">{_topic_options(str(candidate['topic']))}</select></label><label>Type<select name="learning_type">{_type_options(str(candidate['learning_type']))}</select></label></div>
          <details><summary>Evidence ({len(candidate['evidence_uris'])})</summary><ul>{evidence}</ul></details>
          <div class="decisions" role="group" aria-label="Review decision">
            <label><input type="radio" name="decision-{_escape(candidate['candidate_id'])}" value="accept"> Accept</label>
            <label><input type="radio" name="decision-{_escape(candidate['candidate_id'])}" value="edit"> Accept edits</label>
            <label><input type="radio" name="decision-{_escape(candidate['candidate_id'])}" value="reject"> Reject</label>
          </div>
          <label>Review note<input name="rationale" placeholder="Optional reason"></label>
          <p class="card-message" role="status"></p>
        </article>""")
    card_html = "\n".join(cards)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Marketing intelligence human review</title>
<style>
:root{{--ink:#172033;--muted:#667085;--line:#d8dee9;--blue:#215ee6;--green:#08783f;--red:#b42318;--bg:#f5f7fb}}*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:16px/1.5 system-ui,-apple-system,sans-serif}}header{{position:sticky;top:0;z-index:2;background:#fff;border-bottom:1px solid var(--line);padding:18px max(24px,calc((100% - 1040px)/2))}}h1{{margin:0 0 4px;font-size:24px}}header p{{margin:0;color:var(--muted)}}.toolbar{{display:grid;grid-template-columns:1fr 1fr auto;gap:12px;margin-top:14px}}main{{max-width:1040px;margin:24px auto;padding:0 24px 80px}}input,textarea,select,button{{font:inherit}}input,textarea,select{{width:100%;margin-top:5px;padding:10px;border:1px solid var(--line);border-radius:8px;background:#fff}}textarea{{resize:vertical}}label{{display:block;font-weight:650;color:#344054}}.candidate-card{{background:#fff;border:1px solid var(--line);border-radius:14px;padding:20px;margin:0 0 16px;box-shadow:0 2px 10px #1018280a}}.candidate-card>label{{margin-top:14px}}.card-head{{display:flex;justify-content:space-between;gap:12px;color:var(--muted)}}.claim{{color:var(--green);font-weight:800}}.grid{{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:14px}}details{{margin-top:14px}}code{{overflow-wrap:anywhere}}.decisions{{display:flex;gap:18px;flex-wrap:wrap;padding:14px;margin-top:16px;background:#f8fafc;border-radius:10px}}.decisions label{{font-weight:700}}.decisions input{{width:auto;margin:0 6px 0 0}}.card-message{{color:var(--red);font-weight:700}}button{{border:0;border-radius:9px;padding:11px 16px;background:var(--blue);color:#fff;font-weight:800;cursor:pointer}}#message{{color:var(--red);font-weight:700}}@media(max-width:720px){{.toolbar,.grid{{grid-template-columns:1fr}}header{{position:static}}}}
</style></head><body>
<header><h1>Review marketing intelligence candidates</h1><p>Nothing on this page is published until every proposal has a terminal human decision.</p><div class="toolbar"><label>Reviewer<input id="reviewer" value="Heikki"></label><label>Search<input id="search" placeholder="Search proposals"></label><button id="export" type="button">Export decisions</button></div><p><strong id="progress">0 of {len(queue['candidates'])} decided</strong> <span id="message"></span></p></header>
<main>{card_html}</main>
<script>
const QUEUE_SHA={json.dumps(queue_sha256)};const TOTAL={len(queue['candidates'])};
const cards=[...document.querySelectorAll('.candidate-card')];
const searchText=new Map(cards.map(card=>[card,card.dataset.search]));
function selected(card){{return card.querySelector('input[type=radio]:checked')?.value||null}}
function refresh(){{const count=cards.filter(selected).length;document.getElementById('progress').textContent=`${{count}} of ${{TOTAL}} decided`;}}
cards.forEach(card=>{{card.querySelectorAll('input[type=radio]').forEach(el=>el.addEventListener('change',()=>{{card.dataset.status=el.value;card.querySelector('.card-message').textContent='';refresh()}}));card.querySelectorAll('input[name=title],textarea,select').forEach(el=>el.addEventListener('input',()=>{{const decision=selected(card);if(decision==='edit')return;if(decision){{card.querySelector('.card-message').textContent='Fields changed. Select Accept edits to publish the changed values.';return}}const edit=card.querySelector('input[value=edit]');edit.checked=true;card.dataset.status='edit';refresh()}}));}});
document.getElementById('search').addEventListener('input',event=>{{const q=event.target.value.toLowerCase();cards.forEach(card=>card.hidden=!searchText.get(card).includes(q));}});
document.getElementById('export').addEventListener('click',()=>{{const reviewer=document.getElementById('reviewer').value.trim();const missing=cards.filter(card=>!selected(card));const message=document.getElementById('message');if(!reviewer){{message.textContent='Reviewer is required.';return}}if(missing.length){{document.getElementById('search').value='';document.getElementById('search').dispatchEvent(new Event('input'));missing[0].scrollIntoView({{behavior:'smooth',block:'center'}});message.textContent=`Decide all ${{TOTAL}} proposals before export; ${{missing.length}} remain.`;return}}const decisions=[];for(const card of cards){{const decision=selected(card);const row={{candidate_id:card.dataset.candidateId,decision}};const rationale=card.querySelector('[name=rationale]').value.trim();if(rationale)row.rationale=rationale;if(decision==='edit'){{const edits={{title:card.querySelector('[name=title]').value.trim(),content:card.querySelector('[name=content]').value.trim(),action:card.querySelector('[name=action]').value.trim(),topic:card.querySelector('[name=topic]').value,learning_type:card.querySelector('[name=learning_type]').value}};const empty=Object.entries(edits).find(([,value])=>!value);if(empty){{document.getElementById('search').value='';document.getElementById('search').dispatchEvent(new Event('input'));card.scrollIntoView({{behavior:'smooth',block:'center'}});card.querySelector(`[name=${{empty[0]}}]`)?.focus();card.querySelector('.card-message').textContent=`${{empty[0]}} is required for Accept edits.`;message.textContent='Fix the highlighted edited proposal before export.';return}}row.edits=edits}}decisions.push(row)}}const payload={{schema_version:'human-review-decisions/v1',queue_sha256:QUEUE_SHA,reviewer,decisions}};const blob=new Blob([JSON.stringify(payload,null,2)+'\\n'],{{type:'application/json'}});const link=document.createElement('a');link.href=URL.createObjectURL(blob);link.download='review-decisions.json';link.click();URL.revokeObjectURL(link.href);message.textContent='Decision file exported.';}});
refresh();
</script></body></html>"""


def render_published_html(publication: Mapping[str, Any]) -> str:
    """Render only human-accepted intelligence as a searchable local page."""

    if publication.get("schema_version") != PUBLICATION_SCHEMA_VERSION:
        raise HumanReviewError("publication_schema_invalid")
    learnings = publication.get("learnings")
    if not isinstance(learnings, list):
        raise HumanReviewError("publication_learnings_invalid")
    cards: list[str] = []
    for learning in learnings:
        if not isinstance(learning, Mapping):
            raise HumanReviewError("publication_learning_invalid")
        evidence = "".join(f"<li><code>{_escape(uri)}</code></li>" for uri in learning["evidence_uris"])
        cards.append(f"""<article class="learning" data-topic="{_escape(learning['topic'])}"><div class="meta"><span>{_escape(learning['claim_label'])}</span><span>{_escape(learning['learning_type'])}</span><span>{_escape(learning['review_decision'])}</span></div><h2>{_escape(learning['title'])}</h2><p>{_escape(learning['content'])}</p><p class="action"><strong>Use it:</strong> {_escape(learning['action'])}</p><details><summary>Evidence</summary><ul>{evidence}</ul></details></article>""")
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Accepted marketing intelligence</title><style>*{{box-sizing:border-box}}body{{margin:0;color:#172033;background:#f6f7fb;font:16px/1.55 system-ui,-apple-system,sans-serif}}header{{background:#111936;color:#fff;padding:38px max(24px,calc((100% - 1000px)/2))}}header h1{{margin:0 0 8px}}header p{{margin:0;color:#cbd5e1}}.tools{{max-width:1000px;margin:20px auto;padding:0 24px;display:grid;grid-template-columns:1fr 260px;gap:12px}}input,select{{font:inherit;padding:11px;border:1px solid #d8dee9;border-radius:8px}}main{{max-width:1000px;margin:auto;padding:0 24px 80px}}.learning{{background:#fff;border:1px solid #d8dee9;border-radius:14px;padding:22px;margin-bottom:16px}}.learning h2{{margin:8px 0;font-size:21px}}.meta{{display:flex;gap:8px;flex-wrap:wrap}}.meta span{{background:#eef4ff;color:#174ea6;border-radius:999px;padding:3px 9px;font-size:12px;font-weight:800}}.action{{border-left:3px solid #215ee6;padding-left:12px}}code{{overflow-wrap:anywhere}}@media(max-width:650px){{.tools{{grid-template-columns:1fr}}}}</style></head><body><header><h1>Accepted marketing intelligence</h1><p>Every learning below has an explicit human accept or edit decision. Machine-only candidates are not published.</p></header><div class="tools"><input id="search" placeholder="Search accepted intelligence"><select id="topic"><option value="">All topics</option>{_topic_options('')}</select></div><main>{''.join(cards) or '<p>No candidates were accepted.</p>'}</main><script>const cards=[...document.querySelectorAll('.learning')];function filter(){{const q=document.getElementById('search').value.toLowerCase();const topic=document.getElementById('topic').value;cards.forEach(card=>card.hidden=!(card.textContent.toLowerCase().includes(q)&&(!topic||card.dataset.topic===topic)))}}document.getElementById('search').addEventListener('input',filter);document.getElementById('topic').addEventListener('change',filter);</script></body></html>"""


def _write_private_artifacts(
    root: Path,
    artifacts: Mapping[str, str],
    *,
    require_ignored: bool,
) -> dict[str, Path]:
    private_root = _private_root(Path(root), _REPOSITORY_ROOT, require_ignored)
    if any((private_root / filename).exists() or (private_root / filename).is_symlink() for filename in artifacts):
        raise HumanReviewError("review_output_exists")
    paths: dict[str, Path] = {}
    for filename, content in artifacts.items():
        path = private_root / filename
        secure_write_text(path, content)
        paths[filename] = path
    return paths


def write_review_artifacts(
    queue: Mapping[str, Any],
    root: Path,
    *,
    require_ignored: bool = True,
) -> dict[str, Path]:
    """Write a private queue and its offline review page."""

    _validated_queue(queue)
    receipt = {
        "schema_version": "human-review-prepare-receipt/v1",
        "queue_sha256": queue["queue_sha256"],
        "candidate_count": len(queue["candidates"]),
        "exact_duplicates_collapsed": queue["exact_duplicates_collapsed"],
        "publication_status": "blocked_pending_human_review",
    }
    return _write_private_artifacts(
        root,
        {
            "review-queue.json": canonical_json(dict(queue)) + "\n",
            "review.html": render_review_html(queue),
            "review-receipt.json": canonical_json(receipt) + "\n",
        },
        require_ignored=require_ignored,
    )


def write_publication_artifacts(
    publication: Mapping[str, Any],
    root: Path,
    *,
    require_ignored: bool = True,
) -> dict[str, Path]:
    """Write accepted intelligence and its searchable offline page."""

    if publication.get("schema_version") != PUBLICATION_SCHEMA_VERSION:
        raise HumanReviewError("publication_schema_invalid")
    receipt = {
        "schema_version": "human-review-publication-receipt/v1",
        "publication_sha256": publication.get("publication_sha256"),
        "queue_sha256": publication.get("queue_sha256"),
        "source_sha256": publication.get("source_sha256"),
        "source_payload_sha256": publication.get("source_payload_sha256"),
        "decisions_sha256": publication.get("decisions_sha256"),
        "accepted_learning_count": len(publication.get("learnings", ())),
        "publication_status": "human_reviewed",
    }
    return _write_private_artifacts(
        root,
        {
            "accepted-intelligence.json": canonical_json(dict(publication)) + "\n",
            "index.html": render_published_html(publication),
            "publication-receipt.json": canonical_json(receipt) + "\n",
        },
        require_ignored=require_ignored,
    )
