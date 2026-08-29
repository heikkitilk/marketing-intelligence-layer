"""Private U7 extraction execution, result ingestion, and terminal scoring.

This module deliberately operates only on the frozen U7 reviewer packets.  It
never opens transcript roots.  Provider output remains in a private,
append-only staging store until every selected packet has a terminal outcome.
Only then does it create the single quality-extractor-results/v1 artifact that
the deterministic quality gate consumes.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any, Mapping, Sequence

from .census import canonical_json
from .checkpoint import CheckpointStore
from .estimate import FULL_POC_LIMITS, ResourceBudgetExceeded, ResourceEstimate, estimate_probe_resources, enforce_r25
from .extraction import approved_packet_fields, stable_candidate_id, validate_candidate_document, validate_provider_release
from .quality import (
    EXTRACTOR_RESULTS_SCHEMA_VERSION,
    PILOT_PACKET_COUNT,
    PilotArtifactStore,
    PilotSelection,
    QualityPilotError,
    QualityPilotEvaluation,
    evaluate_quality_pilot,
)


_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_PROMPT_PATH = _REPOSITORY_ROOT / "prompts" / "session-analysis.md"
_CANDIDATE_SCHEMA_PATH = _REPOSITORY_ROOT / "schemas" / "candidate-learning.schema.json"

QUALITY_EXECUTION_POLICY_VERSION = "quality-pilot-execution/v2"
QUALITY_EXECUTION_DIRECTORY = "execution-v2"
QUALITY_EXECUTION_PREFLIGHT_SCHEMA_VERSION = "quality-pilot-extraction-preflight/v1"
QUALITY_PROVIDER_RESULT_SCHEMA_VERSION = "quality-pilot-provider-result/v1"
QUALITY_PACKET_RESULT_SCHEMA_VERSION = "quality-pilot-packet-result/v1"
QUALITY_EXECUTION_LEDGER_SCHEMA_VERSION = "quality-pilot-execution-ledger/v1"

CLAUDE_EXECUTION_SURFACE = "anthropic-claude-cli"
CODEX_EXECUTION_SURFACE = "authenticated-first-party-codex-seat"

# U7 is part of the full proof-of-concept model stage, so it uses R25's full
# stage envelope rather than U8's smaller value-probe envelope. The selector
# still fixes this pilot at 24 calls. The conservative token conversion remains
# the project-wide three bytes per token.
PILOT_CONCURRENCY = 2
PILOT_PER_CALL_MINUTES = 7
PILOT_TIMEOUT_SECONDS = PILOT_PER_CALL_MINUTES * 60
PILOT_PROMPT_TOKENS = 1_200
PILOT_OUTPUT_TOKENS = 3_500
PILOT_BYTES_PER_TOKEN = 3
MAX_PROVIDER_PACKET_BYTES = 100 * 1024
MAX_PROVIDER_PACKET_TOKENS = 32_000
MAX_PROVIDER_INPUT_BYTES = min(MAX_PROVIDER_PACKET_BYTES, MAX_PROVIDER_PACKET_TOKENS * PILOT_BYTES_PER_TOKEN)
MAX_PROVIDER_RESULT_BYTES = 256 * 1024
MAX_CLAUDE_CALL_BUDGET_USD = Decimal("10")
MAX_PRIVATE_INPUT_BYTES = 256 * 1024

_EVENT_FIELDS = (
    "event_id",
    "evidence_uri",
    "evidence_strength",
    "role",
    "timestamp",
    "text",
)
_RESULT_TERMINAL_STATUSES = frozenset({"extracted", "no_learning", "rejected_invalid"})


class QualityPilotExecutionError(ValueError):
    """Fail closed without placing private result content in an error."""


@dataclass(frozen=True)
class QualityPilotPricing:
    """Optional model pricing supplied by the operator's current price sheet."""

    input_usd_per_million: Decimal
    output_usd_per_million: Decimal


@dataclass(frozen=True)
class QualityPilotPreflight:
    """A deterministic, no-egress plan for exactly the frozen U7 packets."""

    selection: PilotSelection
    reviewer_labels_sha256: str
    reference_set_sha256: str
    prompt_sha256: str
    candidate_schema_sha256: str
    work_items: tuple[dict[str, Any], ...]
    resource_estimate: ResourceEstimate
    status: str
    budget_failure: dict[str, int] | None
    document: dict[str, Any]


@dataclass(frozen=True)
class ExecutionArtifactReceipt:
    """Receipt for a private staged execution artifact."""

    artifact_kind: str
    relative_path: str
    sha256: str
    status: str = "written"


@dataclass(frozen=True)
class IngestedPacketResult:
    """One private, terminal packet result that has not yet been combined."""

    packet_id: str
    harness: str
    terminal_status: str
    validation_errors: tuple[str, ...]
    document_sha256: str
    receipt: ExecutionArtifactReceipt


@dataclass(frozen=True)
class QualityPilotCombination:
    """The only combined extractor artifact and its final gate receipt."""

    extractor_results_sha256: str
    gate_receipt_sha256: str
    status: str
    failing_metrics: tuple[str, ...]
    blocked_units: tuple[str, ...]


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_sha256(value: Mapping[str, Any]) -> str:
    return _sha256_bytes(canonical_json(dict(value)).encode("utf-8"))


def _json_artifact_sha256(value: Mapping[str, Any]) -> str:
    """Match PilotArtifactStore's canonical JSON plus trailing newline format."""

    return _sha256_bytes((canonical_json(dict(value)) + "\n").encode("utf-8"))


def _ensure_private_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        details = os.lstat(path)
    except OSError as error:
        raise QualityPilotExecutionError("quality_execution_directory_invalid") from error
    if stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode):
        raise QualityPilotExecutionError("quality_execution_directory_invalid")
    if details.st_uid != os.getuid():
        raise QualityPilotExecutionError("quality_execution_directory_unsafe_owner")
    os.chmod(path, 0o700)


def _safe_relative_path(value: str) -> Path:
    path = Path(value)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise QualityPilotExecutionError("quality_execution_artifact_path_invalid")
    return path


def _open_private_file(path: Path, *, max_bytes: int | None = None) -> bytes:
    """Read an owned, regular, non-symlink private file through one descriptor."""

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise QualityPilotExecutionError("quality_private_input_unavailable") from error
    try:
        details = os.fstat(descriptor)
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid != os.getuid()
            or details.st_mode & 0o077
        ):
            raise QualityPilotExecutionError("quality_private_input_unsafe")
        limit = max_bytes if max_bytes is not None else max(details.st_size, 1)
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        value = b"".join(chunks)
        if max_bytes is not None and len(value) > max_bytes:
            raise QualityPilotExecutionError("quality_private_input_exceeds_cap")
        return value
    finally:
        os.close(descriptor)


def load_private_json_input(
    *,
    input_file: Path | None = None,
    stdin_bytes: bytes | None = None,
    max_bytes: int = MAX_PRIVATE_INPUT_BYTES,
) -> dict[str, Any]:
    """Load one private JSON object from stdin or a mode-0600 owned file."""

    if (input_file is None) == (stdin_bytes is None):
        raise QualityPilotExecutionError("quality_private_input_source_invalid")
    if stdin_bytes is not None:
        if len(stdin_bytes) > max_bytes:
            raise QualityPilotExecutionError("quality_private_input_exceeds_cap")
        payload = stdin_bytes
    else:
        payload = _open_private_file(Path(input_file), max_bytes=max_bytes)
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise QualityPilotExecutionError("quality_private_input_invalid_json") from error
    if not isinstance(value, dict):
        raise QualityPilotExecutionError("quality_private_input_not_object")
    return value


def read_stdin_private_json() -> dict[str, Any]:
    """Read bounded stdin without echoing its private payload."""

    payload = sys.stdin.buffer.read(MAX_PRIVATE_INPUT_BYTES + 1)
    return load_private_json_input(stdin_bytes=payload)


class _ExecutionArtifactStore:
    """Append-only staging ledger separate from the final U7 artifact ledger."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root).expanduser()
        _ensure_private_directory(self.root)
        self.execution_root = self.root / QUALITY_EXECUTION_DIRECTORY
        _ensure_private_directory(self.execution_root)
        self.ledger_path = self.execution_root / "artifact-order.jsonl"

    def _read_ledger(self) -> tuple[dict[str, Any], ...]:
        if not self.ledger_path.exists():
            return ()
        payload = _open_private_file(self.ledger_path)
        try:
            lines = [line for line in payload.decode("utf-8").splitlines() if line.strip()]
        except UnicodeDecodeError as error:
            raise QualityPilotExecutionError("quality_execution_ledger_invalid") from error
        entries: list[dict[str, Any]] = []
        previous = ""
        for sequence, line in enumerate(lines, start=1):
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as error:
                raise QualityPilotExecutionError("quality_execution_ledger_invalid") from error
            if (
                not isinstance(entry, dict)
                or entry.get("schema_version") != QUALITY_EXECUTION_LEDGER_SCHEMA_VERSION
                or entry.get("sequence") != sequence
                or not isinstance(entry.get("relative_path"), str)
                or not isinstance(entry.get("sha256"), str)
                or not isinstance(entry.get("entry_sha256"), str)
                or entry.get("previous_entry_sha256") != previous
            ):
                raise QualityPilotExecutionError("quality_execution_ledger_invalid")
            unsigned = {key: value for key, value in entry.items() if key != "entry_sha256"}
            if _canonical_sha256(unsigned) != entry["entry_sha256"]:
                raise QualityPilotExecutionError("quality_execution_ledger_chain_invalid")
            relative = _safe_relative_path(str(entry["relative_path"]))
            artifact = self.execution_root / relative
            if _sha256_bytes(_open_private_file(artifact)) != entry["sha256"]:
                raise QualityPilotExecutionError("quality_execution_artifact_hash_mismatch")
            entries.append(entry)
            previous = str(entry["entry_sha256"])
        return tuple(entries)

    def _ledger_entry(self, relative_path: str) -> dict[str, Any] | None:
        return next((entry for entry in self._read_ledger() if entry["relative_path"] == relative_path), None)

    def write_immutable(
        self,
        relative_path: str,
        artifact_kind: str,
        value: Mapping[str, Any],
    ) -> ExecutionArtifactReceipt:
        relative = _safe_relative_path(relative_path)
        destination = self.execution_root / relative
        _ensure_private_directory(destination.parent)
        payload = (canonical_json(dict(value)) + "\n").encode("utf-8")
        digest = _sha256_bytes(payload)
        existing_entry = self._ledger_entry(relative_path)
        if destination.exists() or destination.is_symlink():
            if _open_private_file(destination) != payload:
                raise QualityPilotExecutionError("quality_execution_artifact_immutable_mismatch")
            if existing_entry is None or existing_entry.get("sha256") != digest:
                raise QualityPilotExecutionError("quality_execution_ledger_path_collision")
            return ExecutionArtifactReceipt(artifact_kind, relative_path, digest, "existing")
        if existing_entry is not None:
            raise QualityPilotExecutionError("quality_execution_ledger_path_collision")

        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(destination, flags, 0o600)
        except FileExistsError as error:
            raise QualityPilotExecutionError("quality_execution_artifact_race") from error
        try:
            details = os.fstat(descriptor)
            if not stat.S_ISREG(details.st_mode) or details.st_uid != os.getuid():
                raise QualityPilotExecutionError("quality_execution_artifact_unsafe")
            os.write(descriptor, payload)
            os.fsync(descriptor)
            os.chmod(destination, 0o600)
        finally:
            os.close(descriptor)

        ledger = self._read_ledger()
        entry: dict[str, Any] = {
            "schema_version": QUALITY_EXECUTION_LEDGER_SCHEMA_VERSION,
            "sequence": len(ledger) + 1,
            "artifact_kind": artifact_kind,
            "relative_path": relative_path,
            "sha256": digest,
            "previous_entry_sha256": ledger[-1]["entry_sha256"] if ledger else "",
        }
        entry["entry_sha256"] = _canonical_sha256(entry)
        encoded = (canonical_json(entry) + "\n").encode("utf-8")
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(self.ledger_path, flags, 0o600)
        try:
            details = os.fstat(descriptor)
            if not stat.S_ISREG(details.st_mode) or details.st_uid != os.getuid():
                raise QualityPilotExecutionError("quality_execution_ledger_unsafe")
            os.write(descriptor, encoded)
            os.fsync(descriptor)
            os.chmod(self.ledger_path, 0o600)
        finally:
            os.close(descriptor)
        return ExecutionArtifactReceipt(artifact_kind, relative_path, digest)

    def read(self, relative_path: str) -> dict[str, Any]:
        if self._ledger_entry(relative_path) is None:
            raise QualityPilotExecutionError("quality_execution_artifact_missing")
        try:
            value = json.loads(_open_private_file(self.execution_root / _safe_relative_path(relative_path)).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise QualityPilotExecutionError("quality_execution_artifact_invalid") from error
        if not isinstance(value, dict):
            raise QualityPilotExecutionError("quality_execution_artifact_invalid")
        return value


def _selection_from_store(store: PilotArtifactStore) -> PilotSelection:
    document = store.read_artifact("selection.json")
    selection_sha256 = document.get("selection_sha256")
    unsigned = {key: value for key, value in document.items() if key != "selection_sha256"}
    if (
        not isinstance(selection_sha256, str)
        or re.fullmatch(r"[a-f0-9]{64}", selection_sha256) is None
        or _canonical_sha256(unsigned) != selection_sha256
        or document.get("status") != "ready"
    ):
        raise QualityPilotExecutionError("quality_execution_selection_invalid")
    selected = document.get("selected")
    substitutions = document.get("substitutions")
    if not isinstance(selected, list) or not isinstance(substitutions, list):
        raise QualityPilotExecutionError("quality_execution_selection_invalid")
    rows = tuple(dict(row) for row in selected if isinstance(row, Mapping))
    packet_ids = tuple(str(row.get("packet_id")) for row in rows)
    if (
        len(rows) != PILOT_PACKET_COUNT
        or len(packet_ids) != len(set(packet_ids))
        or any(re.fullmatch(r"packet-[a-f0-9]{24}", packet_id) is None for packet_id in packet_ids)
        or document.get("hard_blockers") not in ([], ())
    ):
        raise QualityPilotExecutionError("quality_execution_selection_coverage_invalid")
    return PilotSelection(
        selected_packet_ids=packet_ids,
        selected_rows=rows,
        substitutions=tuple(dict(row) for row in substitutions if isinstance(row, Mapping)),
        absent_optional_strata=tuple(str(value) for value in document.get("absent_optional_strata", ())),
        absent_required_strata=tuple(str(value) for value in document.get("absent_required_strata", ())),
        hard_blockers=tuple(str(value) for value in document.get("hard_blockers", ())),
        selection_sha256=selection_sha256,
        document=dict(document),
    )


def _reference_and_labels(store: PilotArtifactStore, selection: PilotSelection) -> tuple[str, dict[str, Any], str]:
    reference = store.read_artifact("reference-set-receipt.json")
    labels = store.read_artifact("reviewer-labels.json")
    reference_set_sha256 = reference.get("reference_set_sha256")
    if (
        reference.get("selection_sha256") != selection.selection_sha256
        or not isinstance(reference_set_sha256, str)
        or labels.get("selection_sha256") != selection.selection_sha256
    ):
        raise QualityPilotExecutionError("quality_execution_reference_binding_invalid")
    return reference_set_sha256, labels, _json_artifact_sha256(labels)


def _project_approved_packet(packet: Mapping[str, Any], expected_row: Mapping[str, Any]) -> dict[str, Any]:
    """Copy precisely the provider-approved U2 fields, not the stored packet."""

    packet_id = packet.get("packet_id")
    harness = packet.get("harness")
    source_version = packet.get("source_version")
    event_ids = packet.get("event_ids")
    events = packet.get("events")
    if (
        packet_id != expected_row.get("packet_id")
        or harness != expected_row.get("harness")
        or source_version != expected_row.get("source_version")
        or not isinstance(packet_id, str)
        or harness not in {"claude", "codex"}
        or not isinstance(source_version, str)
        or not isinstance(event_ids, list)
        or not isinstance(events, list)
        or any(not isinstance(event_id, str) for event_id in event_ids)
        or len(event_ids) != len(set(event_ids))
        or set(event_ids) != set(expected_row.get("event_ids", ()))
    ):
        raise QualityPilotExecutionError("quality_execution_packet_binding_invalid")
    projected_events: list[dict[str, Any]] = []
    seen_event_ids: set[str] = set()
    for event in events:
        if not isinstance(event, Mapping) or event.get("event_id") not in event_ids:
            raise QualityPilotExecutionError("quality_execution_packet_binding_invalid")
        event_id = str(event["event_id"])
        if event_id in seen_event_ids:
            raise QualityPilotExecutionError("quality_execution_packet_binding_invalid")
        seen_event_ids.add(event_id)
        projected_events.append({key: event[key] for key in _EVENT_FIELDS if key in event})
    if seen_event_ids != set(event_ids):
        raise QualityPilotExecutionError("quality_execution_packet_binding_invalid")
    return {
        "packet_id": packet_id,
        "harness": harness,
        "source_version": source_version,
        "event_ids": list(event_ids),
        "events": projected_events,
    }


def _parse_pricing(input_price: str | Decimal | None, output_price: str | Decimal | None) -> QualityPilotPricing | None:
    if input_price is None and output_price is None:
        return None
    if input_price is None or output_price is None:
        raise QualityPilotExecutionError("quality_pricing_pair_required")
    try:
        input_value = Decimal(str(input_price))
        output_value = Decimal(str(output_price))
    except (InvalidOperation, ValueError) as error:
        raise QualityPilotExecutionError("quality_pricing_invalid") from error
    if not input_value.is_finite() or not output_value.is_finite() or input_value < 0 or output_value < 0:
        raise QualityPilotExecutionError("quality_pricing_invalid")
    return QualityPilotPricing(input_value, output_value)


def parse_quality_pilot_pricing(input_price: str | None, output_price: str | None) -> QualityPilotPricing | None:
    """Public CLI boundary for optional current provider price inputs."""

    return _parse_pricing(input_price, output_price)


def _with_monetary_cost(estimate: ResourceEstimate, pricing: QualityPilotPricing | None) -> ResourceEstimate:
    if pricing is None:
        return estimate
    total = (
        Decimal(estimate.input_tokens) * pricing.input_usd_per_million
        + Decimal(estimate.output_tokens) * pricing.output_usd_per_million
    ) / Decimal(1_000_000)
    display = total.quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP)
    return replace(estimate, monetary_cost_usd=format(display, "f"))


def build_quality_pilot_preflight(
    store: PilotArtifactStore,
    *,
    pricing: QualityPilotPricing | None = None,
) -> QualityPilotPreflight:
    """Plan all 24 frozen packets before any provider release is possible."""

    selection = _selection_from_store(store)
    reference_set_sha256, _labels, reviewer_labels_sha256 = _reference_and_labels(store, selection)
    try:
        prompt_bytes = _PROMPT_PATH.read_bytes()
        schema_bytes = _CANDIDATE_SCHEMA_PATH.read_bytes()
    except OSError as error:
        raise QualityPilotExecutionError("quality_execution_contract_file_unavailable") from error
    prompt_sha256 = _sha256_bytes(prompt_bytes)
    candidate_schema_sha256 = _sha256_bytes(schema_bytes)
    work_items: list[dict[str, Any]] = []
    packet_bytes: list[int] = []
    packet_cap_failure: dict[str, int] | None = None
    selected_by_id = {str(row["packet_id"]): row for row in selection.selected_rows}
    for packet_id in selection.selected_packet_ids:
        packet = store.read_artifact(f"reviewer-packets/{packet_id}.json")
        projected = _project_approved_packet(packet, selected_by_id[packet_id])
        encoded = canonical_json(projected).encode("utf-8")
        analysis_packet_sha256 = _sha256_bytes(encoded)
        identity = {
            "packet_id": packet_id,
            "harness": projected["harness"],
            "analysis_packet_sha256": analysis_packet_sha256,
            "prompt_sha256": prompt_sha256,
            "policy_version": QUALITY_EXECUTION_POLICY_VERSION,
        }
        work_items.append({
            "schema_version": "quality-pilot-extraction-work-item/v1",
            "work_item_id": "work-" + _canonical_sha256(identity)[:24],
            "stage": "full_extraction",
            "packet_id": packet_id,
            "harness": projected["harness"],
            "prompt_sha256": prompt_sha256,
            "policy_version": QUALITY_EXECUTION_POLICY_VERSION,
            "approved_fields": list(approved_packet_fields("full_extraction")),
            "analysis_packet_sha256": analysis_packet_sha256,
            "analysis_packet_bytes": len(encoded),
        })
        packet_bytes.append(len(encoded))
        if packet_cap_failure is None and len(encoded) > MAX_PROVIDER_INPUT_BYTES:
            packet_cap_failure = {
                "dimension": "packet_bytes",
                "actual": len(encoded),
                "limit": MAX_PROVIDER_INPUT_BYTES,
            }
    ordered_items = tuple(sorted(work_items, key=lambda item: str(item["packet_id"])))
    estimate = estimate_probe_resources(
        packet_bytes=packet_bytes,
        prompt_tokens=PILOT_PROMPT_TOKENS,
        output_tokens_per_call=PILOT_OUTPUT_TOKENS,
        calls=len(ordered_items),
        concurrency=PILOT_CONCURRENCY,
        per_call_minutes=PILOT_PER_CALL_MINUTES,
        bytes_per_token=PILOT_BYTES_PER_TOKEN,
    )
    estimate = _with_monetary_cost(estimate, pricing)
    budget_failure = packet_cap_failure
    if budget_failure is None:
        try:
            enforce_r25(estimate, FULL_POC_LIMITS)
        except ResourceBudgetExceeded as error:
            budget_failure = {"dimension": error.dimension, "actual": error.actual, "limit": error.limit}
    status = "ready" if budget_failure is None else "reduced_scope"
    document = {
        "schema_version": QUALITY_EXECUTION_PREFLIGHT_SCHEMA_VERSION,
        "status": status,
        "selection_sha256": selection.selection_sha256,
        "reference_set_sha256": reference_set_sha256,
        "reviewer_labels_sha256": reviewer_labels_sha256,
        "prompt_sha256": prompt_sha256,
        "candidate_schema_sha256": candidate_schema_sha256,
        "policy_version": QUALITY_EXECUTION_POLICY_VERSION,
        "packet_count": len(ordered_items),
        "approved_fields": list(approved_packet_fields("full_extraction")),
        "work_items": [dict(item) for item in ordered_items],
        "resource_estimate": asdict(estimate),
        "r25_limits": asdict(FULL_POC_LIMITS),
        "r25_failure": budget_failure,
        "provider_packet_input_cap_bytes": MAX_PROVIDER_INPUT_BYTES,
        "provider_dispatch": "not_started",
        "blocked_units": ["U4", "U5", "U6"] if budget_failure else [],
    }
    return QualityPilotPreflight(
        selection=selection,
        reviewer_labels_sha256=reviewer_labels_sha256,
        reference_set_sha256=reference_set_sha256,
        prompt_sha256=prompt_sha256,
        candidate_schema_sha256=candidate_schema_sha256,
        work_items=ordered_items,
        resource_estimate=estimate,
        status=status,
        budget_failure=budget_failure,
        document=document,
    )


def write_quality_pilot_preflight(store: PilotArtifactStore, preflight: QualityPilotPreflight) -> ExecutionArtifactReceipt:
    """Persist the no-egress preflight with a separate immutable staging ledger."""

    return _ExecutionArtifactStore(store.root).write_immutable(
        "preflight.json",
        "quality_pilot_preflight",
        preflight.document,
    )


def _load_ready_preflight(
    store: PilotArtifactStore,
) -> tuple[PilotSelection, dict[str, Any], dict[str, dict[str, Any]], _ExecutionArtifactStore]:
    selection = _selection_from_store(store)
    execution_store = _ExecutionArtifactStore(store.root)
    preflight = execution_store.read("preflight.json")
    reference_set_sha256, _labels, labels_sha256 = _reference_and_labels(store, selection)
    if (
        preflight.get("schema_version") != QUALITY_EXECUTION_PREFLIGHT_SCHEMA_VERSION
        or preflight.get("status") != "ready"
        or preflight.get("selection_sha256") != selection.selection_sha256
        or preflight.get("reference_set_sha256") != reference_set_sha256
        or preflight.get("reviewer_labels_sha256") != labels_sha256
        or preflight.get("policy_version") != QUALITY_EXECUTION_POLICY_VERSION
    ):
        raise QualityPilotExecutionError("quality_execution_preflight_not_releasable")
    rows = preflight.get("work_items")
    if not isinstance(rows, list) or len(rows) != PILOT_PACKET_COUNT:
        raise QualityPilotExecutionError("quality_execution_preflight_coverage_invalid")
    work_items: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, Mapping) or not isinstance(row.get("packet_id"), str):
            raise QualityPilotExecutionError("quality_execution_preflight_coverage_invalid")
        packet_id = str(row["packet_id"])
        if packet_id in work_items:
            raise QualityPilotExecutionError("quality_execution_preflight_coverage_invalid")
        work_items[packet_id] = dict(row)
    if set(work_items) != set(selection.selected_packet_ids):
        raise QualityPilotExecutionError("quality_execution_preflight_coverage_invalid")
    return selection, preflight, work_items, execution_store


def _validate_release_contract(
    release: Mapping[str, Any],
    work_item: Mapping[str, Any],
    *,
    expected_harness: str,
) -> tuple[str, ...]:
    """Extend U3's provider gate with U7's surface, budget, and retry bounds."""

    errors = list(validate_provider_release(release, work_item).errors)
    if work_item.get("harness") != expected_harness:
        errors.append("work_item_harness_mismatch")
    if release.get("work_item_id") != work_item.get("work_item_id"):
        errors.append("work_item_binding_mismatch")
    if release.get("analysis_packet_sha256") != work_item.get("analysis_packet_sha256"):
        errors.append("packet_binding_mismatch")
    if release.get("model_available_verified") is not True:
        errors.append("model_availability_unverified")
    if "fallback_model" in release or "fallback" in release:
        errors.append("fallback_forbidden")
    if expected_harness == "claude":
        if release.get("execution_surface") != CLAUDE_EXECUTION_SURFACE:
            errors.append("claude_cli_required")
        if release.get("tools_disabled") is not True:
            errors.append("claude_tools_not_disabled")
        if release.get("persistence_disabled") is not True:
            errors.append("claude_persistence_not_disabled")
        if release.get("authentication_verified") is not True:
            errors.append("claude_authentication_unverified")
        timeout = release.get("timeout_seconds")
        if not isinstance(timeout, int) or timeout <= 0 or timeout > PILOT_TIMEOUT_SECONDS:
            errors.append("claude_timeout_invalid")
        try:
            budget = Decimal(str(release.get("max_budget_usd")))
        except (InvalidOperation, ValueError):
            errors.append("claude_budget_invalid")
        else:
            if not budget.is_finite() or budget <= 0 or budget > MAX_CLAUDE_CALL_BUDGET_USD:
                errors.append("claude_budget_invalid")
    elif expected_harness == "codex":
        if release.get("execution_surface") != CODEX_EXECUTION_SURFACE:
            errors.append("codex_first_party_seat_required")
        if release.get("seat_verified") is not True:
            errors.append("codex_seat_unverified")
        if release.get("authentication_verified") is not True:
            errors.append("codex_authentication_unverified")
    else:
        errors.append("work_item_harness_invalid")
    return tuple(sorted(set(errors)))


def _normalize_candidate_ids(document: Mapping[str, Any], packet_id: str) -> dict[str, Any]:
    """Replace model IDs, including placeholders, with stable code-owned IDs."""

    normalized = dict(document)
    candidates = normalized.get("candidates")
    if not isinstance(candidates, list):
        return normalized
    rewritten: list[Any] = []
    for candidate in candidates:
        if not isinstance(candidate, Mapping):
            rewritten.append(candidate)
            continue
        stable = dict(candidate)
        stable["candidate_id"] = stable_candidate_id(packet_id, stable)
        rewritten.append(stable)
    normalized["candidates"] = rewritten
    return normalized


def ingest_provider_result(
    store: PilotArtifactStore,
    envelope: Mapping[str, Any],
    *,
    expected_harness: str,
) -> IngestedPacketResult:
    """Validate and immutably stage one verified provider result without logging it."""

    selection, preflight, work_items, execution_store = _load_ready_preflight(store)
    if envelope.get("schema_version") != QUALITY_PROVIDER_RESULT_SCHEMA_VERSION:
        raise QualityPilotExecutionError("quality_provider_result_schema_invalid")
    packet_id = envelope.get("packet_id")
    release = envelope.get("release")
    document = envelope.get("document")
    if not isinstance(packet_id, str) or not isinstance(release, Mapping) or not isinstance(document, Mapping):
        raise QualityPilotExecutionError("quality_provider_result_shape_invalid")
    work_item = work_items.get(packet_id)
    if work_item is None:
        raise QualityPilotExecutionError("quality_provider_result_packet_not_selected")
    if packet_id not in selection.selected_packet_ids:
        raise QualityPilotExecutionError("quality_provider_result_packet_not_selected")
    release_errors = _validate_release_contract(release, work_item, expected_harness=expected_harness)
    if release_errors:
        raise QualityPilotExecutionError("quality_provider_release_rejected")
    expected_row = next(row for row in selection.selected_rows if row["packet_id"] == packet_id)
    packet = store.read_artifact(f"reviewer-packets/{packet_id}.json")
    projected = _project_approved_packet(packet, expected_row)
    if _sha256_bytes(canonical_json(projected).encode("utf-8")) != work_item.get("analysis_packet_sha256"):
        raise QualityPilotExecutionError("quality_provider_result_packet_binding_invalid")
    normalized_document = _normalize_candidate_ids(document, packet_id)
    validation = validate_candidate_document(normalized_document, packet)
    terminal_status = validation.terminal_status
    if terminal_status not in _RESULT_TERMINAL_STATUSES:
        raise QualityPilotExecutionError("quality_provider_result_terminal_invalid")
    document_sha256 = _json_artifact_sha256(normalized_document)
    payload = {
        "schema_version": QUALITY_PACKET_RESULT_SCHEMA_VERSION,
        "selection_sha256": selection.selection_sha256,
        "reviewer_labels_sha256": preflight["reviewer_labels_sha256"],
        "preflight_sha256": _json_artifact_sha256(preflight),
        "packet_id": packet_id,
        "harness": expected_harness,
        "work_item_id": work_item["work_item_id"],
        "provider": release.get("provider"),
        "model": release.get("model"),
        "release_sha256": _json_artifact_sha256(dict(release)),
        "terminal_status": terminal_status,
        "validation_errors": list(validation.errors),
        "document_sha256": document_sha256,
        "document": normalized_document,
    }
    receipt = execution_store.write_immutable(
        f"packet-results/{packet_id}.json",
        "provider_packet_result",
        payload,
    )
    return IngestedPacketResult(
        packet_id=packet_id,
        harness=expected_harness,
        terminal_status=terminal_status,
        validation_errors=validation.errors,
        document_sha256=document_sha256,
        receipt=receipt,
    )


def _candidate_schema_for_claude() -> str:
    try:
        value = json.loads(_CANDIDATE_SCHEMA_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise QualityPilotExecutionError("quality_execution_candidate_schema_invalid") from error
    if not isinstance(value, dict):
        raise QualityPilotExecutionError("quality_execution_candidate_schema_invalid")
    # Claude CLI's structured-output validator does not register the draft
    # 2020-12 meta-schema URI. The local validator still applies the canonical
    # schema after receipt; only the transport annotation is omitted here.
    value.pop("$schema", None)
    return canonical_json(value)


def build_claude_cli_command(release: Mapping[str, Any]) -> tuple[str, ...]:
    """Return the sole supported Claude invocation: first-party CLI, no tools."""

    model = release.get("model")
    budget = release.get("max_budget_usd")
    if not isinstance(model, str) or not model.strip():
        raise QualityPilotExecutionError("quality_claude_model_invalid")
    try:
        budget_value = Decimal(str(budget))
    except (InvalidOperation, ValueError) as error:
        raise QualityPilotExecutionError("quality_claude_budget_invalid") from error
    if not budget_value.is_finite() or budget_value <= 0 or budget_value > MAX_CLAUDE_CALL_BUDGET_USD:
        raise QualityPilotExecutionError("quality_claude_budget_invalid")
    return (
        "claude",
        "--print",
        "--output-format",
        "json",
        "--json-schema",
        _candidate_schema_for_claude(),
        "--model",
        model,
        "--tools",
        "",
        "--no-session-persistence",
        "--safe-mode",
        "--no-chrome",
        "--strict-mcp-config",
        "--max-budget-usd",
        format(budget_value, "f"),
    )


def _claude_response_document(stdout: str) -> dict[str, Any]:
    """Accept only the CLI's one structured JSON result, never prose wrappers."""

    try:
        response = json.loads(stdout)
    except json.JSONDecodeError as error:
        raise QualityPilotExecutionError("quality_claude_response_invalid") from error
    if not isinstance(response, Mapping):
        raise QualityPilotExecutionError("quality_claude_response_invalid")
    candidate = response.get("result", response)
    if isinstance(candidate, str):
        try:
            candidate = json.loads(candidate)
        except json.JSONDecodeError as error:
            raise QualityPilotExecutionError("quality_claude_response_invalid") from error
    if not isinstance(candidate, Mapping):
        raise QualityPilotExecutionError("quality_claude_response_invalid")
    return dict(candidate)


def _safe_claude_failure_code(stdout: str, returncode: int) -> str:
    """Classify a Claude CLI failure from allow-listed envelope fields only."""

    suffix = "unknown"
    try:
        response = json.loads(stdout)
    except json.JSONDecodeError:
        response = None
    if isinstance(response, Mapping):
        for field in ("subtype", "terminal_reason", "stop_reason"):
            value = response.get(field)
            if isinstance(value, str) and value:
                normalized = re.sub(r"[^a-z0-9_]+", "_", value.casefold()).strip("_")
                if normalized:
                    suffix = normalized[:80]
                    break
    return f"claude_returncode_{returncode}_{suffix}"


def execute_claude_packet(
    store: PilotArtifactStore,
    *,
    packet_id: str,
    release: Mapping[str, Any],
) -> IngestedPacketResult:
    """Run one Claude packet only after every first-party privacy gate passes.

    This function intentionally does not retry, invoke a fallback model, or
    print provider stderr/stdout.  An operator may perform a later explicit
    retry only after inspecting the provider state.
    """

    selection, _preflight, work_items, execution_store = _load_ready_preflight(store)
    work_item = work_items.get(packet_id)
    if work_item is None or packet_id not in selection.selected_packet_ids:
        raise QualityPilotExecutionError("quality_provider_result_packet_not_selected")
    release_errors = _validate_release_contract(release, work_item, expected_harness="claude")
    if release_errors:
        raise QualityPilotExecutionError("quality_provider_release_rejected")
    expected_row = next(row for row in selection.selected_rows if row["packet_id"] == packet_id)
    packet = store.read_artifact(f"reviewer-packets/{packet_id}.json")
    projected = _project_approved_packet(packet, expected_row)
    if _sha256_bytes(canonical_json(projected).encode("utf-8")) != work_item.get("analysis_packet_sha256"):
        raise QualityPilotExecutionError("quality_provider_result_packet_binding_invalid")
    checkpoint_store = CheckpointStore(execution_store.execution_root / "claude-checkpoints")
    checkpoint_store.write_immutable_work_item(work_item)
    if work_item["work_item_id"] in {row["work_item_id"] for row in checkpoint_store.terminal_results()}:
        raise QualityPilotExecutionError("quality_claude_execution_already_terminal")
    try:
        prompt_text = _PROMPT_PATH.read_text(encoding="utf-8")
    except OSError as error:
        raise QualityPilotExecutionError("quality_execution_contract_file_unavailable") from error
    invocation_prompt = (
        prompt_text
        + "\n\nReturn only the schema-bound result for this approved redacted packet.\n"
        + canonical_json(projected)
    )
    command = build_claude_cli_command(release)
    try:
        completed = subprocess.run(
            command,
            input=invocation_prompt,
            text=True,
            capture_output=True,
            check=False,
            timeout=int(release["timeout_seconds"]),
            cwd=execution_store.execution_root,
        )
    except subprocess.TimeoutExpired as error:
        state = checkpoint_store.record_failure(str(work_item["work_item_id"]), "claude_timeout")
        reason = "quality_claude_execution_terminal_failure" if state == "failed" else "quality_claude_execution_failed"
        raise QualityPilotExecutionError(reason) from error
    except OSError as error:
        state = checkpoint_store.record_failure(str(work_item["work_item_id"]), "claude_invocation_error")
        reason = "quality_claude_execution_terminal_failure" if state == "failed" else "quality_claude_execution_failed"
        raise QualityPilotExecutionError(reason) from error
    if completed.returncode != 0:
        state = checkpoint_store.record_failure(
            str(work_item["work_item_id"]),
            _safe_claude_failure_code(completed.stdout, completed.returncode),
        )
        reason = "quality_claude_execution_terminal_failure" if state == "failed" else "quality_claude_execution_failed"
        raise QualityPilotExecutionError(reason)
    if len(completed.stdout.encode("utf-8")) > MAX_PROVIDER_RESULT_BYTES:
        state = checkpoint_store.record_failure(
            str(work_item["work_item_id"]),
            "claude_result_exceeds_cap",
        )
        reason = "quality_claude_execution_terminal_failure" if state == "failed" else "quality_claude_execution_failed"
        raise QualityPilotExecutionError(reason)
    try:
        document = _claude_response_document(completed.stdout)
    except QualityPilotExecutionError as error:
        state = checkpoint_store.record_failure(
            str(work_item["work_item_id"]),
            "claude_schema_response_invalid",
        )
        reason = "quality_claude_execution_terminal_failure" if state == "failed" else "quality_claude_execution_failed"
        raise QualityPilotExecutionError(reason) from error
    result = ingest_provider_result(
        store,
        {
            "schema_version": QUALITY_PROVIDER_RESULT_SCHEMA_VERSION,
            "packet_id": packet_id,
            "release": dict(release),
            "document": document,
        },
        expected_harness="claude",
    )
    checkpoint_store.append_terminal_result({
        "work_item_id": work_item["work_item_id"],
        "terminal_status": result.terminal_status if result.terminal_status in {"extracted", "no_learning"} else "failed",
        "result_sha256": result.document_sha256,
    })
    return result


def _load_exact_deduplications(value: Sequence[Mapping[str, Any]] | None) -> list[dict[str, Any]]:
    if value is None:
        return []
    rows: list[dict[str, Any]] = []
    for row in value:
        if not isinstance(row, Mapping):
            raise QualityPilotExecutionError("quality_exact_deduplications_invalid")
        rows.append(dict(row))
    return rows


def combine_and_score_quality_pilot(
    store: PilotArtifactStore,
    *,
    exact_deduplications: Sequence[Mapping[str, Any]] | None = None,
) -> QualityPilotCombination:
    """Combine exactly 24 staged outcomes, then write the immutable U7 gate."""

    selection, preflight, work_items, execution_store = _load_ready_preflight(store)
    _reference_set_sha256, labels, labels_sha256 = _reference_and_labels(store, selection)
    staged: list[dict[str, Any]] = []
    terminal_outcomes: list[dict[str, Any]] = []
    for packet_id in selection.selected_packet_ids:
        try:
            result = execution_store.read(f"packet-results/{packet_id}.json")
        except QualityPilotExecutionError as error:
            if str(error) == "quality_execution_artifact_missing":
                raise QualityPilotExecutionError("quality_execution_terminal_coverage_incomplete") from error
            raise
        work_item = work_items[packet_id]
        if (
            result.get("schema_version") != QUALITY_PACKET_RESULT_SCHEMA_VERSION
            or result.get("selection_sha256") != selection.selection_sha256
            or result.get("reviewer_labels_sha256") != labels_sha256
            or result.get("preflight_sha256") != _json_artifact_sha256(preflight)
            or result.get("packet_id") != packet_id
            or result.get("harness") != work_item.get("harness")
            or result.get("work_item_id") != work_item.get("work_item_id")
            or result.get("terminal_status") not in _RESULT_TERMINAL_STATUSES
            or not isinstance(result.get("document"), Mapping)
        ):
            raise QualityPilotExecutionError("quality_execution_terminal_result_invalid")
        packet = store.read_artifact(f"reviewer-packets/{packet_id}.json")
        validation = validate_candidate_document(result["document"], packet)
        if validation.terminal_status != result.get("terminal_status"):
            raise QualityPilotExecutionError("quality_execution_terminal_result_invalid")
        staged.append(dict(result["document"]))
        terminal_outcomes.append({
            "packet_id": packet_id,
            "harness": result["harness"],
            "terminal_status": result["terminal_status"],
            "document_sha256": result.get("document_sha256"),
            "release_sha256": result.get("release_sha256"),
        })
    if len(staged) != PILOT_PACKET_COUNT or set(work_items) != set(selection.selected_packet_ids):
        raise QualityPilotExecutionError("quality_execution_terminal_coverage_incomplete")
    result_document = {
        "schema_version": EXTRACTOR_RESULTS_SCHEMA_VERSION,
        "selection_sha256": selection.selection_sha256,
        "reviewer_labels_sha256": labels_sha256,
        "documents": staged,
        "exact_deduplications": _load_exact_deduplications(exact_deduplications),
        "terminal_outcomes": terminal_outcomes,
    }
    packets = {
        packet_id: store.read_artifact(f"reviewer-packets/{packet_id}.json")
        for packet_id in selection.selected_packet_ids
    }
    # Evaluate before writing the combined artifact so an unexpected evaluator
    # contract failure cannot leave a partially terminal U7 artifact sequence.
    evaluation = evaluate_quality_pilot(selection, packets, labels, result_document)
    invalid_packet_count = sum(
        1 for outcome in terminal_outcomes if outcome["terminal_status"] == "rejected_invalid"
    )
    if invalid_packet_count:
        metrics = {
            **evaluation.metrics,
            "candidate_document_validity": {
                "invalid_packet_count": invalid_packet_count,
                "passed": False,
            },
        }
        failing_metrics = tuple(sorted(name for name, metric in metrics.items() if not metric["passed"]))
        evaluation = QualityPilotEvaluation(
            selection_sha256=evaluation.selection_sha256,
            status="reduced_scope",
            metrics=metrics,
            failing_metrics=failing_metrics,
            blocked_units=("U4", "U5", "U6"),
            document={
                **evaluation.document,
                "status": "reduced_scope",
                "metrics": metrics,
                "failing_metrics": list(failing_metrics),
                "blocked_units": ["U4", "U5", "U6"],
                "decision": "delivered_reduced_scope",
            },
        )
    results_receipt = store.write_extractor_results(result_document)
    gate_document = {
        **evaluation.document,
        "reviewer_labels_sha256": labels_sha256,
        "extractor_results_sha256": results_receipt.sha256,
        "terminal_outcome_count": len(terminal_outcomes),
    }
    bound_evaluation = QualityPilotEvaluation(
        selection_sha256=evaluation.selection_sha256,
        status=evaluation.status,
        metrics=evaluation.metrics,
        failing_metrics=evaluation.failing_metrics,
        blocked_units=evaluation.blocked_units,
        document=gate_document,
    )
    gate_receipt = store.write_gate_receipt(bound_evaluation)
    return QualityPilotCombination(
        extractor_results_sha256=results_receipt.sha256,
        gate_receipt_sha256=gate_receipt.sha256,
        status=bound_evaluation.status,
        failing_metrics=bound_evaluation.failing_metrics,
        blocked_units=bound_evaluation.blocked_units,
    )
