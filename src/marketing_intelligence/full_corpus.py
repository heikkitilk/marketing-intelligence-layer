"""Human-calibrated, provider-affine full-corpus extraction."""

from __future__ import annotations

from dataclasses import asdict, replace
from math import ceil
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
from typing import Any, Callable, Mapping, Sequence

from .census import _REPOSITORY_ROOT, canonical_json, validate_schema_document
from .estimate import FULL_POC_LIMITS, ResourceEstimate, enforce_r25, estimate_probe_resources
from .extraction import stable_candidate_id, validate_candidate_document
from .normalize import _strict_private_root
from .redact import secure_write_text
from .review import (
    build_extraction_review_queue,
    build_publication,
    write_review_artifacts,
)
from .routing import (
    BYTES_PER_TOKEN,
    MAX_PROVIDER_INPUT_BYTES,
    SessionPreflight,
    build_dependence_groups,
    route_full_extraction_work,
)


CALIBRATION_SCHEMA_VERSION = "human-calibration/v1"
PLAN_SCHEMA_VERSION = "full-corpus-plan/v1"
BATCH_SCHEMA_VERSION = "full-corpus-batch/v1"
RESULT_SCHEMA_VERSIONS = {
    "classification": "full-corpus-classification-result/v1",
    "full_extraction": "full-corpus-extraction-result/v1",
}
POLICY_VERSION = "human-calibrated-full-corpus/v1"
PROVIDER_RESULT_CAP_BYTES = 512 * 1024
PROMPT_RESERVE_BYTES = 4 * 1024

_SCHEMA_ROOT = _REPOSITORY_ROOT / "schemas"
_PROMPT_ROOT = _REPOSITORY_ROOT / "prompts"
_CLASSIFICATION_SCHEMA = _SCHEMA_ROOT / "full-corpus-classification-batch.schema.json"
_EXTRACTION_SCHEMA = _SCHEMA_ROOT / "full-corpus-extraction-batch.schema.json"
_CLASSIFICATION_PROMPT = _PROMPT_ROOT / "session-classification.md"
_EXTRACTION_PROMPT = _PROMPT_ROOT / "session-analysis.md"


class FullCorpusError(ValueError):
    """A content-free full-corpus pipeline error."""


ProviderRunner = Callable[[str, str, Path, Path, str, str, float, int], Mapping[str, Any]]


def _sha256(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _private_json(path: Path) -> dict[str, Any]:
    path = Path(path)
    try:
        details = os.lstat(path)
    except OSError as error:
        raise FullCorpusError("full_corpus_private_input_missing") from error
    if (
        stat.S_ISLNK(details.st_mode)
        or not stat.S_ISREG(details.st_mode)
        or details.st_uid != os.getuid()
        or stat.S_IMODE(details.st_mode) & 0o077
    ):
        raise FullCorpusError("full_corpus_private_input_unsafe")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise FullCorpusError("full_corpus_private_input_invalid") from error
    if not isinstance(value, dict):
        raise FullCorpusError("full_corpus_private_input_invalid")
    return value


def load_full_corpus_input(path: Path) -> dict[str, Any]:
    """Load an owner-only corpus manifest without the small review-file cap."""

    return _private_json(path)


def _write_once(path: Path, value: Mapping[str, Any], mismatch: str) -> None:
    encoded = canonical_json(dict(value)) + "\n"
    if path.exists() or path.is_symlink():
        try:
            details = os.lstat(path)
            current = path.read_text(encoding="utf-8")
        except OSError as error:
            raise FullCorpusError(mismatch) from error
        if (
            stat.S_ISLNK(details.st_mode)
            or not stat.S_ISREG(details.st_mode)
            or details.st_uid != os.getuid()
            or current != encoded
        ):
            raise FullCorpusError(mismatch)
        return
    secure_write_text(path, encoded)


def _ensure_private_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    details = os.lstat(path)
    if stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode) or details.st_uid != os.getuid():
        raise FullCorpusError("full_corpus_output_unsafe")
    os.chmod(path, 0o700)


def _fresh_root(path: Path) -> Path:
    raw = Path(path)
    if raw.exists() or raw.is_symlink():
        raise FullCorpusError("full_corpus_output_exists")
    root = _strict_private_root(raw, _REPOSITORY_ROOT, True)
    if any(root.iterdir()):
        raise FullCorpusError("full_corpus_output_exists")
    return root


def build_calibration(
    queue: Mapping[str, Any],
    decisions: Mapping[str, Any],
    publication: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind the reviewed value probe into bounded positive and negative examples."""

    recomputed = build_publication(queue, decisions)
    if recomputed.get("publication_sha256") != publication.get("publication_sha256"):
        raise FullCorpusError("full_corpus_publication_mismatch")
    rows = decisions.get("decisions")
    candidates = queue.get("candidates")
    if not isinstance(rows, list) or not isinstance(candidates, list):
        raise FullCorpusError("full_corpus_review_invalid")
    decision_by_id = {
        str(row.get("candidate_id")): row
        for row in rows
        if isinstance(row, Mapping)
    }
    queue_by_id = {
        str(row.get("candidate_id")): row
        for row in candidates
        if isinstance(row, Mapping)
    }
    if set(decision_by_id) != set(queue_by_id):
        raise FullCorpusError("full_corpus_review_incomplete")

    positive_examples = [
        {
            "title": str(row["title"])[:180],
            "content": str(row["content"])[:700],
            "recommended_action": str(row["action"])[:500],
            "topic": row["topic"],
            "learning_type": row["learning_type"],
        }
        for row in publication.get("learnings", ())
        if isinstance(row, Mapping)
    ]
    negative_examples = []
    for candidate_id, decision in sorted(decision_by_id.items()):
        if decision.get("decision") != "reject":
            continue
        row = queue_by_id[candidate_id]
        negative_examples.append({
            "title": str(row["title"])[:180],
            "content": str(row["content"])[:700],
            "recommended_action": str(row["action"])[:500],
            "topic": row["topic"],
            "learning_type": row["learning_type"],
        })
    core = {
        "schema_version": CALIBRATION_SCHEMA_VERSION,
        "queue_sha256": queue.get("queue_sha256"),
        "decisions_sha256": _sha256(decisions),
        "publication_sha256": publication.get("publication_sha256"),
        "decision_counts": publication.get("decision_counts"),
        "positive_examples": sorted(positive_examples, key=lambda row: (str(row["topic"]), str(row["title"]))),
        "negative_examples": sorted(negative_examples, key=lambda row: (str(row["topic"]), str(row["title"]))),
    }
    return {**core, "calibration_sha256": _sha256(core)}


def _source_preflight(preflight_run: Path) -> tuple[dict[str, Any], tuple[dict[str, Any], ...]]:
    receipt_envelope = _private_json(Path(preflight_run) / "receipt.json")
    receipt = receipt_envelope.get("receipt")
    if not isinstance(receipt, Mapping) or receipt_envelope.get("receipt_sha256") != _sha256(receipt):
        raise FullCorpusError("full_corpus_preflight_receipt_invalid")
    work_root = Path(preflight_run) / "work-items"
    try:
        paths = sorted(work_root.glob("work-*.json"))
    except OSError as error:
        raise FullCorpusError("full_corpus_preflight_work_items_invalid") from error
    items = tuple(_private_json(path) for path in paths)
    expected = receipt.get("classification_work_item_count")
    if not isinstance(expected, int) or expected != len(items) or not items:
        raise FullCorpusError("full_corpus_preflight_work_item_count_mismatch")
    seen: set[str] = set()
    for item in items:
        work_item_id = item.get("work_item_id")
        packet = item.get("analysis_packet")
        if (
            item.get("stage") != "classification"
            or not isinstance(work_item_id, str)
            or work_item_id in seen
            or item.get("harness") not in {"claude", "codex"}
            or not isinstance(packet, Mapping)
            or item.get("analysis_packet_sha256") != _sha256(packet)
        ):
            raise FullCorpusError("full_corpus_preflight_work_item_invalid")
        seen.add(work_item_id)
    return dict(receipt_envelope), items


def _calibrated_classification_items(
    source_items: Sequence[Mapping[str, Any]],
    *,
    prompt_sha256: str,
    calibration_sha256: str,
) -> tuple[dict[str, Any], ...]:
    policy_version = _sha256({"policy": POLICY_VERSION, "calibration_sha256": calibration_sha256})
    items: list[dict[str, Any]] = []
    for source in source_items:
        identity = {
            "stage": "classification",
            "source_work_item_id": source["work_item_id"],
            "prompt_sha256": prompt_sha256,
            "policy_version": policy_version,
        }
        items.append({
            **dict(source),
            "work_item_id": "work-" + _sha256(identity)[:24],
            "source_work_item_id": source["work_item_id"],
            "prompt_sha256": prompt_sha256,
            "policy_version": policy_version,
        })
    return tuple(sorted(items, key=lambda row: str(row["work_item_id"])))


def _batch_items(
    items: Sequence[Mapping[str, Any]],
    *,
    stage: str,
    calibration: Mapping[str, Any],
    prompt_text: str,
) -> tuple[dict[str, Any], ...]:
    calibration_bytes = len(canonical_json(calibration).encode("utf-8"))
    available = MAX_PROVIDER_INPUT_BYTES - calibration_bytes - len(prompt_text.encode("utf-8")) - PROMPT_RESERVE_BYTES
    if available <= 0:
        raise FullCorpusError("full_corpus_calibration_exceeds_cap")
    batches: list[dict[str, Any]] = []
    for harness in ("claude", "codex"):
        current: list[dict[str, Any]] = []
        for item in (row for row in items if row.get("harness") == harness):
            projected = {
                "work_item_id": item["work_item_id"],
                "group_id": item["group_id"],
                "packet_id": item["packet_id"],
                "session_kind": item.get("session_kind", "?"),
                "analysis_packet": item["analysis_packet"],
            }
            candidate = [*current, projected]
            payload = {"work_items": candidate}
            if len(canonical_json(payload).encode("utf-8")) <= available:
                current = candidate
                continue
            if not current:
                raise FullCorpusError("full_corpus_batch_item_exceeds_cap")
            batches.append(_batch_document(stage, harness, current))
            current = [projected]
        if current:
            batches.append(_batch_document(stage, harness, current))
    return tuple(batches)


def _stage_calibration(calibration: Mapping[str, Any], stage: str) -> dict[str, Any]:
    """Keep full review examples for classification and a compact extraction reminder."""

    if stage == "classification":
        return dict(calibration)
    if stage != "full_extraction":
        raise FullCorpusError("full_corpus_stage_invalid")
    positives = calibration.get("positive_examples")
    negatives = calibration.get("negative_examples")
    if not isinstance(positives, list) or not isinstance(negatives, list):
        raise FullCorpusError("full_corpus_calibration_invalid")
    return {
        "schema_version": CALIBRATION_SCHEMA_VERSION,
        "calibration_sha256": calibration.get("calibration_sha256"),
        "decision_counts": calibration.get("decision_counts"),
        "accepted_patterns": [
            {
                "title": row.get("title"),
                "topic": row.get("topic"),
                "learning_type": row.get("learning_type"),
            }
            for row in positives
            if isinstance(row, Mapping)
        ],
        "rejected_examples": [dict(row) for row in negatives if isinstance(row, Mapping)],
    }


def _batch_document(stage: str, harness: str, work_items: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    identity = {
        "stage": stage,
        "harness": harness,
        "work_item_ids": [row["work_item_id"] for row in work_items],
    }
    return {
        "schema_version": BATCH_SCHEMA_VERSION,
        "batch_id": "batch-" + _sha256(identity)[:24],
        "stage": stage,
        "harness": harness,
        "work_item_count": len(work_items),
        "work_items": [dict(row) for row in work_items],
    }


def _estimate_calls(
    batches: Sequence[Mapping[str, Any]],
    calibration: Mapping[str, Any],
    prompt_text: str,
    *,
    output_tokens_per_call: int,
) -> ResourceEstimate:
    calibration_text = canonical_json(calibration)
    call_bytes = [
        len((prompt_text + calibration_text + canonical_json(batch)).encode("utf-8"))
        for batch in batches
    ]
    estimate = estimate_probe_resources(
        packet_bytes=call_bytes,
        prompt_tokens=0,
        output_tokens_per_call=output_tokens_per_call,
        calls=len(batches),
        concurrency=2,
        per_call_minutes=20,
        bytes_per_token=BYTES_PER_TOKEN,
    )
    enforce_r25(estimate, FULL_POC_LIMITS)
    return estimate


def prepare_full_corpus(
    preflight_run: Path,
    queue: Mapping[str, Any],
    decisions: Mapping[str, Any],
    publication: Mapping[str, Any],
    output_root: Path,
) -> dict[str, Any]:
    """Create a fresh, private full-corpus classification plan."""

    root = _fresh_root(output_root)
    calibration = build_calibration(queue, decisions, publication)
    preflight_envelope, source_items = _source_preflight(preflight_run)
    prompt_text = _CLASSIFICATION_PROMPT.read_text(encoding="utf-8")
    prompt_sha256 = _sha256_bytes(prompt_text.encode("utf-8"))
    items = _calibrated_classification_items(
        source_items,
        prompt_sha256=prompt_sha256,
        calibration_sha256=str(calibration["calibration_sha256"]),
    )
    batches = _batch_items(
        items,
        stage="classification",
        calibration=calibration,
        prompt_text=prompt_text,
    )
    estimate = _estimate_calls(batches, calibration, prompt_text, output_tokens_per_call=3_000)
    classification_root = root / "classification"
    batch_root = classification_root / "batches"
    result_root = classification_root / "results"
    for path in (classification_root, batch_root, result_root):
        _ensure_private_directory(path)
    _write_once(root / "calibration.json", calibration, "full_corpus_calibration_mismatch")
    _write_once(root / "decision-ledger.json", decisions, "full_corpus_decision_ledger_mismatch")
    for batch in batches:
        _write_once(batch_root / f"{batch['batch_id']}.json", batch, "full_corpus_batch_mismatch")
    plan_core = {
        "schema_version": PLAN_SCHEMA_VERSION,
        "stage": "classification",
        "source_preflight_receipt_sha256": preflight_envelope["receipt_sha256"],
        "calibration_sha256": calibration["calibration_sha256"],
        "prompt_sha256": prompt_sha256,
        "policy_version": items[0]["policy_version"],
        "work_item_count": len(items),
        "batch_ids": [batch["batch_id"] for batch in batches],
        "provider_affinity": {"claude": "anthropic", "codex": "openai"},
        "resource_estimate": asdict(estimate),
        "provider_dispatch": "ready_human_calibrated",
    }
    plan = {**plan_core, "plan_sha256": _sha256(plan_core)}
    _write_once(classification_root / "plan.json", plan, "full_corpus_plan_mismatch")
    receipt = {
        "schema_version": "full-corpus-prepare-receipt/v1",
        "status": "ready_human_calibrated",
        "source_preflight_receipt_sha256": preflight_envelope["receipt_sha256"],
        "calibration_sha256": calibration["calibration_sha256"],
        "classification_work_item_count": len(items),
        "classification_batch_count": len(batches),
        "harness_counts": {
            harness: sum(item.get("harness") == harness for item in items)
            for harness in ("claude", "codex")
        },
        "resource_estimate": asdict(estimate),
        "plan_sha256": plan["plan_sha256"],
    }
    _write_once(root / "prepare-receipt.json", receipt, "full_corpus_prepare_receipt_mismatch")
    return receipt


def _schema_for_claude(path: Path) -> str:
    schema = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(schema, dict):
        raise FullCorpusError("full_corpus_schema_invalid")
    schema.pop("$schema", None)
    return canonical_json(schema)


def _parse_claude_result(stdout: str) -> dict[str, Any]:
    try:
        envelope = json.loads(stdout)
    except json.JSONDecodeError as error:
        raise FullCorpusError("full_corpus_provider_response_invalid") from error
    if not isinstance(envelope, Mapping):
        raise FullCorpusError("full_corpus_provider_response_invalid")
    result: object = envelope.get("result", envelope)
    if isinstance(result, str):
        try:
            result = json.loads(result)
        except json.JSONDecodeError as error:
            raise FullCorpusError("full_corpus_provider_response_invalid") from error
    if not isinstance(result, Mapping):
        raise FullCorpusError("full_corpus_provider_response_invalid")
    return dict(result)


def _claude_failure_reason(stdout: str) -> str:
    """Classify a safe provider envelope without returning provider content."""

    try:
        envelope = json.loads(stdout)
    except json.JSONDecodeError:
        return "full_corpus_provider_execution_failed"
    if isinstance(envelope, Mapping) and envelope.get("api_error_status") == 429:
        return "full_corpus_provider_rate_limited"
    return "full_corpus_provider_execution_failed"


def _run_provider(
    harness: str,
    prompt: str,
    schema_path: Path,
    cwd: Path,
    model: str,
    effort: str,
    max_budget_usd: float,
    timeout_seconds: int,
) -> Mapping[str, Any]:
    if harness == "claude":
        command = (
            "claude", "--print", "--output-format", "json", "--json-schema",
            _schema_for_claude(schema_path), "--model", model, "--effort", effort,
            "--tools", "", "--no-session-persistence", "--safe-mode", "--no-chrome",
            "--strict-mcp-config", "--max-budget-usd", format(max_budget_usd, ".2f"),
        )
        try:
            completed = subprocess.run(
                command,
                input=prompt,
                text=True,
                capture_output=True,
                check=False,
                timeout=timeout_seconds,
                cwd=cwd,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise FullCorpusError("full_corpus_provider_execution_failed") from error
        if completed.returncode != 0:
            raise FullCorpusError(_claude_failure_reason(completed.stdout))
        if len(completed.stdout.encode("utf-8")) > PROVIDER_RESULT_CAP_BYTES:
            raise FullCorpusError("full_corpus_provider_result_exceeds_cap")
        return _parse_claude_result(completed.stdout)
    if harness != "codex":
        raise FullCorpusError("full_corpus_provider_harness_invalid")
    descriptor, result_name = tempfile.mkstemp(prefix="codex-result-", suffix=".json", dir=cwd)
    os.close(descriptor)
    result_path = Path(result_name)
    os.chmod(result_path, 0o600)
    command = (
        "/opt/homebrew/bin/codex", "exec", "--ephemeral", "--ignore-user-config",
        "--ignore-rules", "--skip-git-repo-check", "-C", str(cwd), "-s", "read-only",
        "-m", model, "-c", f'model_reasoning_effort="{effort}"',
        "--output-schema", str(schema_path), "-o", str(result_path), "-",
    )
    try:
        completed = subprocess.run(
            command,
            input=prompt,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout_seconds,
            cwd=cwd,
        )
        if completed.returncode != 0:
            raise FullCorpusError("full_corpus_provider_execution_failed")
        if result_path.stat().st_size > PROVIDER_RESULT_CAP_BYTES:
            raise FullCorpusError("full_corpus_provider_result_exceeds_cap")
        result = _private_json(result_path)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise FullCorpusError("full_corpus_provider_execution_failed") from error
    finally:
        try:
            result_path.unlink()
        except OSError:
            pass
    return result


def _stage_paths(root: Path, batch_id: str) -> tuple[str, Path, Path]:
    if re.fullmatch(r"batch-[a-f0-9]{24}", batch_id) is None:
        raise FullCorpusError("full_corpus_batch_id_invalid")
    for stage, directory in (("classification", "classification"), ("full_extraction", "extraction")):
        batch_path = root / directory / "batches" / f"{batch_id}.json"
        if batch_path.exists() and not batch_path.is_symlink():
            return stage, batch_path, root / directory / "results" / f"{batch_id}.json"
    raise FullCorpusError("full_corpus_batch_missing")


def _validate_exact_result_coverage(batch: Mapping[str, Any], result: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    rows = result.get("results")
    if not isinstance(rows, list):
        raise FullCorpusError("full_corpus_provider_response_invalid")
    by_id: dict[str, Mapping[str, Any]] = {}
    for row in rows:
        if not isinstance(row, Mapping) or not isinstance(row.get("work_item_id"), str):
            raise FullCorpusError("full_corpus_provider_response_invalid")
        work_item_id = str(row["work_item_id"])
        if work_item_id in by_id:
            raise FullCorpusError("full_corpus_provider_result_duplicate")
        by_id[work_item_id] = row
    expected = {str(row["work_item_id"]) for row in batch["work_items"]}
    if set(by_id) != expected:
        raise FullCorpusError("full_corpus_provider_result_coverage_mismatch")
    return by_id


def _normalize_extraction_result(
    batch: Mapping[str, Any],
    result: Mapping[str, Any],
    *,
    provider: str,
    provider_override_reason: str | None,
) -> dict[str, Any]:
    by_id = _validate_exact_result_coverage(batch, result)
    item_by_id = {str(row["work_item_id"]): row for row in batch["work_items"]}
    terminal_results: list[dict[str, Any]] = []
    for work_item_id in sorted(by_id):
        row = by_id[work_item_id]
        document = row.get("document")
        item = item_by_id[work_item_id]
        packet = item.get("analysis_packet")
        if not isinstance(document, Mapping) or not isinstance(packet, Mapping):
            raise FullCorpusError("full_corpus_provider_response_invalid")
        normalized = dict(document)
        candidates = normalized.get("candidates")
        if isinstance(candidates, list):
            normalized_candidates = []
            for candidate in candidates:
                if not isinstance(candidate, Mapping):
                    normalized_candidates.append(candidate)
                    continue
                candidate_row = dict(candidate)
                candidate_row["candidate_id"] = stable_candidate_id(str(item["packet_id"]), candidate_row)
                normalized_candidates.append(candidate_row)
            normalized["candidates"] = normalized_candidates
        validation = validate_candidate_document(normalized, packet)
        if not validation.accepted:
            terminal_results.append({
                "work_item_id": work_item_id,
                "group_id": item["group_id"],
                "packet_id": item["packet_id"],
                "terminal_status": "rejected_invalid",
                "validation_errors": list(validation.errors),
            })
            continue
        terminal_results.append({
            "work_item_id": work_item_id,
            "group_id": item["group_id"],
            "packet_id": item["packet_id"],
            "terminal_status": validation.terminal_status,
            "document": normalized,
            "document_sha256": _sha256(normalized),
        })
    core = {
        "schema_version": "full-corpus-terminal-batch/v1",
        "batch_id": batch["batch_id"],
        "stage": "full_extraction",
        "harness": batch["harness"],
        "provider": provider,
        "provider_override_reason": provider_override_reason or "not_applicable",
        "terminal_results": terminal_results,
    }
    return {**core, "result_sha256": _sha256(core)}


def run_batch(
    output_root: Path,
    batch_id: str,
    *,
    claude_model: str = "claude-sonnet-5",
    codex_model: str = "gpt-5.6-luna",
    effort: str = "high",
    max_budget_usd: float = 8.0,
    timeout_seconds: int = 1_200,
    provider_override: str | None = None,
    provider_override_reason: str | None = None,
    provider_runner: ProviderRunner | None = None,
) -> dict[str, Any]:
    """Run one provider-affine batch and persist only validated private output."""

    root = _strict_private_root(Path(output_root), _REPOSITORY_ROOT, True)
    stage, batch_path, result_path = _stage_paths(root, batch_id)
    if result_path.exists() or result_path.is_symlink():
        result = _private_json(result_path)
        return {
            "status": "already_terminal",
            "stage": stage,
            "batch_id": batch_id,
            "source_harness": result.get("harness"),
            "provider": result.get("provider", result.get("harness")),
            "result_sha256": result.get("result_sha256"),
        }
    batch = _private_json(batch_path)
    calibration = _private_json(root / "calibration.json")
    prompt_calibration = _stage_calibration(calibration, stage)
    harness = str(batch.get("harness"))
    if provider_override is not None and provider_override not in {"claude", "codex"}:
        raise FullCorpusError("full_corpus_provider_override_invalid")
    if provider_override is not None:
        if provider_override == harness or not isinstance(provider_override_reason, str) or not provider_override_reason.strip():
            raise FullCorpusError("full_corpus_provider_override_reason_required")
        provider = provider_override
        override_reason = provider_override_reason.strip()[:200]
    else:
        if provider_override_reason is not None:
            raise FullCorpusError("full_corpus_provider_override_invalid")
        provider = harness
        override_reason = None
    prompt_path = _CLASSIFICATION_PROMPT if stage == "classification" else _EXTRACTION_PROMPT
    schema_path = _CLASSIFICATION_SCHEMA if stage == "classification" else _EXTRACTION_SCHEMA
    prompt = (
        prompt_path.read_text(encoding="utf-8")
        + "\n\nHuman calibration:\n"
        + canonical_json(prompt_calibration)
        + "\n\nApproved redacted batch:\n"
        + canonical_json(batch)
    )
    runner = provider_runner or _run_provider
    model = claude_model if provider == "claude" else codex_model
    result = dict(runner(provider, prompt, schema_path, root, model, effort, max_budget_usd, timeout_seconds))
    schema_errors = validate_schema_document(result, schema_path)
    if schema_errors:
        raise FullCorpusError("full_corpus_provider_result_schema_invalid")
    if result.get("schema_version") != RESULT_SCHEMA_VERSIONS[stage]:
        raise FullCorpusError("full_corpus_provider_response_invalid")
    if stage == "classification":
        by_id = _validate_exact_result_coverage(batch, result)
        item_by_id = {str(row["work_item_id"]): row for row in batch["work_items"]}
        for work_item_id, row in by_id.items():
            if row.get("group_id") != item_by_id[work_item_id].get("group_id"):
                raise FullCorpusError("full_corpus_provider_group_mismatch")
        core = {
            "schema_version": "full-corpus-terminal-batch/v1",
            "batch_id": batch_id,
            "stage": stage,
            "harness": harness,
            "provider": provider,
            "provider_override_reason": override_reason or "not_applicable",
            "terminal_results": [dict(by_id[key]) for key in sorted(by_id)],
        }
        terminal = {**core, "result_sha256": _sha256(core)}
    else:
        terminal = _normalize_extraction_result(
            batch,
            result,
            provider=provider,
            provider_override_reason=override_reason,
        )
    _write_once(result_path, terminal, "full_corpus_result_mismatch")
    return {
        "status": "terminal",
        "stage": stage,
        "batch_id": batch_id,
        "source_harness": harness,
        "provider": provider,
        "provider_override_reason": override_reason or "not_applicable",
        "model_requested": model,
        "model_actual": "unverified",
        "work_item_count": len(terminal["terminal_results"]),
        "result_sha256": terminal["result_sha256"],
    }


def _classification_results(root: Path, plan: Mapping[str, Any]) -> dict[str, str]:
    labels: dict[str, str] = {}
    expected_batches = set(plan.get("batch_ids", ()))
    result_root = root / "classification" / "results"
    found = {path.stem for path in result_root.glob("batch-*.json")}
    if found != expected_batches:
        raise FullCorpusError("full_corpus_classification_incomplete")
    for batch_id in sorted(expected_batches):
        result = _private_json(result_root / f"{batch_id}.json")
        for row in result.get("terminal_results", ()):
            if not isinstance(row, Mapping):
                raise FullCorpusError("full_corpus_classification_result_invalid")
            group_id = row.get("group_id")
            label = row.get("classification")
            if not isinstance(group_id, str) or label not in {"marketing_bearing", "not_marketing", "mixed_work"}:
                raise FullCorpusError("full_corpus_classification_result_invalid")
            if group_id in labels and labels[group_id] != label:
                raise FullCorpusError("full_corpus_classification_duplicate_group")
            labels[group_id] = str(label)
    if len(labels) != plan.get("work_item_count"):
        raise FullCorpusError("full_corpus_classification_coverage_mismatch")
    return labels


def _packet_documents(packet_manifest: Mapping[str, Any], packet_root: Path) -> dict[str, Mapping[str, Any]]:
    rows = packet_manifest.get("packets")
    if not isinstance(rows, list):
        raise FullCorpusError("full_corpus_packet_manifest_invalid")
    documents: dict[str, Mapping[str, Any]] = {}
    for row in rows:
        if not isinstance(row, Mapping) or row.get("terminal_outcome") != "prepared_no_egress":
            continue
        packet_id = row.get("packet_id")
        if not isinstance(packet_id, str):
            raise FullCorpusError("full_corpus_packet_manifest_invalid")
        document = _private_json(Path(packet_root) / f"{packet_id}.json")
        documents[packet_id] = document
    return documents


def _resource_estimate(value: Mapping[str, Any]) -> ResourceEstimate:
    try:
        return ResourceEstimate(**{key: value[key] for key in ResourceEstimate.__dataclass_fields__})
    except (KeyError, TypeError, ValueError) as error:
        raise FullCorpusError("full_corpus_resource_estimate_invalid") from error


def _observed_classification_wall(root: Path) -> tuple[int, int]:
    """Return a conservative completed-stage wall bound from local file times."""

    prepare_path = root / "prepare-receipt.json"
    result_paths = sorted((root / "classification" / "results").glob("batch-*.json"))
    if not result_paths:
        raise FullCorpusError("full_corpus_classification_incomplete")
    try:
        start = os.lstat(prepare_path).st_mtime
        end = max(os.lstat(path).st_mtime for path in result_paths)
    except OSError as error:
        raise FullCorpusError("full_corpus_classification_timing_unavailable") from error
    elapsed_seconds = max(1, ceil(end - start))
    return elapsed_seconds, max(1, ceil(elapsed_seconds / 60))


def route_extraction(
    output_root: Path,
    source_manifest: Mapping[str, Any],
    packet_manifest: Mapping[str, Any],
    packet_root: Path,
    *,
    mixed_sample_fraction: float = 0.05,
) -> dict[str, Any]:
    """Route classified groups into bounded full-extraction batches."""

    root = _strict_private_root(Path(output_root), _REPOSITORY_ROOT, True)
    plan = _private_json(root / "classification" / "plan.json")
    labels = _classification_results(root, plan)
    groups = build_dependence_groups(source_manifest, packet_manifest)
    if {group.group_id for group in groups} != set(labels):
        raise FullCorpusError("full_corpus_classification_group_mismatch")
    packet_documents = _packet_documents(packet_manifest, packet_root)
    prompt_text = _EXTRACTION_PROMPT.read_text(encoding="utf-8")
    prompt_sha256 = _sha256_bytes(prompt_text.encode("utf-8"))
    calibration = _private_json(root / "calibration.json")
    policy_version = _sha256({"policy": POLICY_VERSION, "calibration_sha256": calibration["calibration_sha256"]})
    classification_elapsed_seconds, classification_wall_minutes = _observed_classification_wall(root)
    classification_estimate = replace(
        _resource_estimate(plan["resource_estimate"]),
        wall_minutes=classification_wall_minutes,
    )
    preflight = SessionPreflight(
        preflight_id="full-corpus-" + _sha256({"plan": plan["plan_sha256"], "prompt": prompt_sha256})[:24],
        groups=tuple(groups),
        classification_work_items=(),
        classification_call_batches=(),
        coverage={
            "eligible_group_count": len(groups),
            "eligible_packet_count": len(packet_documents),
            "unaccounted_group_count": 0,
        },
        resource_estimate=classification_estimate,
        prompt_sha256=prompt_sha256,
        policy_version=policy_version,
        source_manifest_sha256=_sha256(source_manifest),
        packet_manifest_sha256=_sha256(packet_manifest),
        packet_documents=packet_documents,
    )
    route = route_full_extraction_work(
        preflight,
        labels,
        mixed_sample_fraction=mixed_sample_fraction,
        representative_only=True,
        limits=FULL_POC_LIMITS,
    )
    extraction_calibration = _stage_calibration(calibration, "full_extraction")
    batches = _batch_items(
        route.extraction_work_items,
        stage="full_extraction",
        calibration=extraction_calibration,
        prompt_text=prompt_text,
    )
    estimate = _estimate_calls(batches, extraction_calibration, prompt_text, output_tokens_per_call=8_000)
    combined = ResourceEstimate(
        input_tokens=preflight.resource_estimate.input_tokens + estimate.input_tokens,
        output_tokens=preflight.resource_estimate.output_tokens + estimate.output_tokens,
        calls=preflight.resource_estimate.calls + estimate.calls,
        wall_minutes=preflight.resource_estimate.wall_minutes + estimate.wall_minutes,
        packet_bytes=preflight.resource_estimate.packet_bytes + estimate.packet_bytes,
        prompt_tokens=preflight.resource_estimate.prompt_tokens + estimate.prompt_tokens,
        retry_overhead_tokens=preflight.resource_estimate.retry_overhead_tokens + estimate.retry_overhead_tokens,
        bytes_per_token=BYTES_PER_TOKEN,
        concurrency=2,
        per_call_minutes=20,
    )
    enforce_r25(combined, FULL_POC_LIMITS)
    extraction_root = root / "extraction"
    batch_root = extraction_root / "batches"
    result_root = extraction_root / "results"
    for path in (extraction_root, batch_root, result_root):
        _ensure_private_directory(path)
    for batch in batches:
        _write_once(batch_root / f"{batch['batch_id']}.json", batch, "full_corpus_batch_mismatch")
    extraction_plan_core = {
        "schema_version": PLAN_SCHEMA_VERSION,
        "stage": "full_extraction",
        "classification_plan_sha256": plan["plan_sha256"],
        "calibration_sha256": calibration["calibration_sha256"],
        "prompt_sha256": prompt_sha256,
        "policy_version": policy_version,
        "classified_group_count": len(labels),
        "selected_group_count": sum(status == "extraction_pending" for status in route.group_terminal_statuses.values()),
        "extraction_scope": "one_representative_packet_per_dependence_group",
        "rolled_up_group_count": sum(status == "group_rolled_up" for status in route.group_terminal_statuses.values()),
        "work_item_count": len(route.extraction_work_items),
        "batch_ids": [batch["batch_id"] for batch in batches],
        "group_terminal_statuses": route.group_terminal_statuses,
        "classification_wall_evidence": {
            "method": "prepare_to_last_result_mtime_upper_bound",
            "elapsed_seconds": classification_elapsed_seconds,
            "wall_minutes": classification_wall_minutes,
        },
        "resource_estimate": asdict(combined),
        "provider_dispatch": "ready_human_calibrated",
    }
    extraction_plan = {**extraction_plan_core, "plan_sha256": _sha256(extraction_plan_core)}
    _write_once(extraction_root / "plan.json", extraction_plan, "full_corpus_extraction_plan_mismatch")
    return {
        "status": "ready_human_calibrated",
        "classified_group_count": len(labels),
        "selected_group_count": extraction_plan["selected_group_count"],
        "rolled_up_group_count": extraction_plan["rolled_up_group_count"],
        "extraction_work_item_count": len(route.extraction_work_items),
        "extraction_batch_count": len(batches),
        "resource_estimate": asdict(combined),
        "plan_sha256": extraction_plan["plan_sha256"],
    }


def finalize_full_corpus(output_root: Path, review_output_root: Path) -> dict[str, Any]:
    """Require complete terminal coverage and write a pending review queue."""

    root = _strict_private_root(Path(output_root), _REPOSITORY_ROOT, True)
    classification_plan = _private_json(root / "classification" / "plan.json")
    extraction_plan = _private_json(root / "extraction" / "plan.json")
    expected_batches = set(extraction_plan.get("batch_ids", ()))
    result_root = root / "extraction" / "results"
    found = {path.stem for path in result_root.glob("batch-*.json")}
    if found != expected_batches:
        raise FullCorpusError("full_corpus_extraction_incomplete")
    expected_work_items = int(extraction_plan.get("work_item_count", -1))
    terminal_rows: list[dict[str, Any]] = []
    for batch_id in sorted(expected_batches):
        result = _private_json(result_root / f"{batch_id}.json")
        rows = result.get("terminal_results")
        if not isinstance(rows, list):
            raise FullCorpusError("full_corpus_extraction_result_invalid")
        terminal_rows.extend(dict(row) for row in rows if isinstance(row, Mapping))
    work_item_ids = [str(row.get("work_item_id")) for row in terminal_rows]
    if len(terminal_rows) != expected_work_items or len(set(work_item_ids)) != expected_work_items:
        raise FullCorpusError("full_corpus_extraction_coverage_mismatch")

    candidates: list[dict[str, Any]] = []
    status_counts: dict[str, int] = {}
    provider_counts: dict[str, int] = {}
    for row in terminal_rows:
        status = str(row.get("terminal_status"))
        status_counts[status] = status_counts.get(status, 0) + 1
        document = row.get("document")
        if status == "extracted" and isinstance(document, Mapping):
            candidate_rows = document.get("candidates")
            if isinstance(candidate_rows, list):
                candidates.extend(dict(candidate) for candidate in candidate_rows if isinstance(candidate, Mapping))
    for batch_id in sorted(expected_batches):
        result = _private_json(result_root / f"{batch_id}.json")
        provider = str(result.get("provider", result.get("harness", "unknown")))
        provider_counts[provider] = provider_counts.get(provider, 0) + 1
    source_core = {
        "schema_version": "full-corpus-terminal-result/v1",
        "classification_plan_sha256": classification_plan["plan_sha256"],
        "extraction_plan_sha256": extraction_plan["plan_sha256"],
        "classified_group_count": extraction_plan["classified_group_count"],
        "selected_group_count": extraction_plan["selected_group_count"],
        "rolled_up_group_count": extraction_plan["rolled_up_group_count"],
        "extraction_work_item_count": expected_work_items,
        "terminal_status_counts": dict(sorted(status_counts.items())),
        "provider_batch_counts": dict(sorted(provider_counts.items())),
        "candidate_count": len(candidates),
        "terminal_batch_result_sha256s": [
            _private_json(result_root / f"{batch_id}.json")["result_sha256"]
            for batch_id in sorted(expected_batches)
        ],
    }
    source_document = {**source_core, "result_sha256": _sha256(source_core)}
    queue = build_extraction_review_queue(
        candidates,
        source_sha256=source_document["result_sha256"],
        source_payload_sha256=_sha256(source_document),
        machine_rejected_count=status_counts.get("rejected_invalid", 0),
    )
    review_paths = write_review_artifacts(queue, review_output_root)
    final_receipt = {
        "schema_version": "full-corpus-finalize-receipt/v1",
        "status": "blocked_pending_human_review",
        "terminal_result_sha256": source_document["result_sha256"],
        "classified_group_count": source_document["classified_group_count"],
        "selected_group_count": source_document["selected_group_count"],
        "rolled_up_group_count": source_document["rolled_up_group_count"],
        "extraction_work_item_count": source_document["extraction_work_item_count"],
        "terminal_status_counts": source_document["terminal_status_counts"],
        "provider_batch_counts": source_document["provider_batch_counts"],
        "candidate_count": source_document["candidate_count"],
        "review_queue_sha256": queue["queue_sha256"],
        "review_candidate_count": queue["review_candidate_count"],
        "exact_duplicates_collapsed": queue["exact_duplicates_collapsed"],
        "review_output_root": str(review_paths["review.html"].parent.relative_to(_REPOSITORY_ROOT)),
    }
    _write_once(root / "terminal-result.json", source_document, "full_corpus_terminal_result_mismatch")
    _write_once(root / "finalize-receipt.json", final_receipt, "full_corpus_finalize_receipt_mismatch")
    return {
        "status": "blocked_pending_human_review",
        "classified_group_count": extraction_plan["classified_group_count"],
        "selected_group_count": extraction_plan["selected_group_count"],
        "rolled_up_group_count": extraction_plan["rolled_up_group_count"],
        "extraction_work_item_count": expected_work_items,
        "terminal_status_counts": dict(sorted(status_counts.items())),
        "provider_batch_counts": dict(sorted(provider_counts.items())),
        "candidate_count": len(candidates),
        "review_candidate_count": queue["review_candidate_count"],
        "review_queue_sha256": queue["queue_sha256"],
        "review_page": str(review_paths["review.html"].relative_to(_REPOSITORY_ROOT)),
    }
