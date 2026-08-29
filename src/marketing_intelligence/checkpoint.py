"""Private immutable work items and append-only U3 checkpoint results."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any, Iterable, Mapping

from .census import canonical_json


TERMINAL_PACKET_STATUSES = frozenset({
    "extracted",
    "no_learning",
    "group_rolled_up",
    "quarantined",
    "failed",
})


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _safe_failure_code(value: str) -> str:
    """Keep failure identity without copying provider output into a receipt."""

    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
    compact = "".join(character for character in value if character in allowed)
    return compact[:80] or "provider_failure"


class CheckpointStore:
    """Persist U3 work with immutable inputs and append-only outcomes.

    The store has separate append-only attempt and terminal ledgers. A first
    failure remains non-terminal. The second consecutive identical failure
    writes the terminal ``failed`` outcome required by LAW section 4.
    """

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self._ensure_private_directory(self.root)
        self.work_item_root = self.root / "work-items"
        self.attempt_path = self.root / "attempts.jsonl"
        self.terminal_path = self.root / "terminal-results.jsonl"
        self._ensure_private_directory(self.work_item_root)

    @staticmethod
    def _ensure_private_directory(path: Path) -> None:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        details = os.lstat(path)
        if stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode):
            raise ValueError("private_output_not_directory")
        if details.st_uid != os.getuid():
            raise PermissionError("private_output_unsafe_owner")
        os.chmod(path, 0o700)

    @staticmethod
    def _read_json_lines(path: Path) -> tuple[dict[str, Any], ...]:
        if not path.exists():
            return ()
        details = os.lstat(path)
        if stat.S_ISLNK(details.st_mode) or not stat.S_ISREG(details.st_mode):
            raise ValueError("checkpoint_ledger_unsafe")
        rows: list[dict[str, Any]] = []
        with path.open("r", encoding="utf-8") as stream:
            for ordinal, line in enumerate(stream, start=1):
                if not line.strip():
                    continue
                try:
                    value = json.loads(line)
                except json.JSONDecodeError as error:
                    raise ValueError("checkpoint_ledger_invalid_json") from error
                if not isinstance(value, dict):
                    raise ValueError("checkpoint_ledger_invalid_row")
                if not isinstance(value.get("work_item_id"), str):
                    raise ValueError("checkpoint_ledger_missing_work_item_id")
                value["_ordinal"] = ordinal
                rows.append(value)
        return tuple(rows)

    @staticmethod
    def _append_json_line(path: Path, value: Mapping[str, Any]) -> None:
        encoded = (canonical_json(dict(value)) + "\n").encode("utf-8")
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags, 0o600)
        try:
            details = os.fstat(descriptor)
            if details.st_uid != os.getuid() or not stat.S_ISREG(details.st_mode):
                raise PermissionError("checkpoint_ledger_unsafe")
            os.write(descriptor, encoded)
            os.fsync(descriptor)
            os.chmod(path, 0o600)
        finally:
            os.close(descriptor)

    def write_immutable_work_item(self, work_item: Mapping[str, Any]) -> bool:
        """Write an item exactly once; an identical retry is idempotent."""

        work_item_id = work_item.get("work_item_id")
        if not isinstance(work_item_id, str) or not work_item_id.startswith("work-"):
            raise ValueError("work_item_invalid_id")
        path = self.work_item_root / f"{work_item_id}.json"
        expected = canonical_json(dict(work_item)) + "\n"
        if path.exists() or path.is_symlink():
            details = os.lstat(path)
            if stat.S_ISLNK(details.st_mode) or not stat.S_ISREG(details.st_mode):
                raise ValueError("work_item_path_unsafe")
            existing = path.read_text(encoding="utf-8")
            if existing == expected:
                return False
            raise ValueError("work_item_immutable_mismatch")

        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags, 0o600)
        except FileExistsError:
            return self.write_immutable_work_item(work_item)
        try:
            details = os.fstat(descriptor)
            if details.st_uid != os.getuid() or not stat.S_ISREG(details.st_mode):
                raise PermissionError("work_item_descriptor_unsafe")
            os.write(descriptor, expected.encode("utf-8"))
            os.fsync(descriptor)
            os.chmod(path, 0o600)
        finally:
            os.close(descriptor)
        return True

    def terminal_results(self) -> tuple[dict[str, Any], ...]:
        rows = self._read_json_lines(self.terminal_path)
        identifiers: set[str] = set()
        terminal: list[dict[str, Any]] = []
        for row in rows:
            work_item_id = str(row["work_item_id"])
            if work_item_id in identifiers:
                raise ValueError("checkpoint_duplicate_terminal_result")
            if row.get("terminal_status") not in TERMINAL_PACKET_STATUSES:
                raise ValueError("checkpoint_invalid_terminal_status")
            identifiers.add(work_item_id)
            row.pop("_ordinal", None)
            terminal.append(row)
        return tuple(terminal)

    def pending_work_item_ids(self, work_items: Iterable[Mapping[str, Any]]) -> tuple[str, ...]:
        terminal_ids = {str(row["work_item_id"]) for row in self.terminal_results()}
        identifiers: list[str] = []
        for work_item in work_items:
            work_item_id = work_item.get("work_item_id")
            if not isinstance(work_item_id, str):
                raise ValueError("work_item_invalid_id")
            if work_item_id not in terminal_ids:
                identifiers.append(work_item_id)
        return tuple(identifiers)

    def append_terminal_result(self, result: Mapping[str, Any]) -> bool:
        """Append exactly one terminal result for a work item."""

        work_item_id = result.get("work_item_id")
        terminal_status = result.get("terminal_status")
        if not isinstance(work_item_id, str):
            raise ValueError("checkpoint_terminal_missing_work_item_id")
        if terminal_status not in TERMINAL_PACKET_STATUSES:
            raise ValueError("checkpoint_invalid_terminal_status")
        work_item_path = self.work_item_root / f"{work_item_id}.json"
        if not work_item_path.exists() or work_item_path.is_symlink():
            raise ValueError("checkpoint_terminal_work_item_missing")
        details = os.lstat(work_item_path)
        if stat.S_ISLNK(details.st_mode) or not stat.S_ISREG(details.st_mode) or details.st_uid != os.getuid():
            raise ValueError("checkpoint_terminal_work_item_unsafe")
        prior = {str(row["work_item_id"]): row for row in self.terminal_results()}
        canonical = dict(result)
        if work_item_id in prior:
            existing = dict(prior[work_item_id])
            if canonical_json(existing) == canonical_json(canonical):
                return False
            raise ValueError("checkpoint_terminal_result_immutable_mismatch")
        self._append_json_line(self.terminal_path, canonical)
        return True

    def record_failure(self, work_item_id: str, failure: str) -> str:
        """Record a safe failure fingerprint and stop after an exact repeat."""

        if not isinstance(work_item_id, str) or not work_item_id.startswith("work-"):
            raise ValueError("work_item_invalid_id")
        if work_item_id in {str(row["work_item_id"]) for row in self.terminal_results()}:
            return "terminal"
        fingerprint = _sha256_text(failure)
        attempts = [row for row in self._read_json_lines(self.attempt_path) if row["work_item_id"] == work_item_id]
        previous = attempts[-1] if attempts else None
        attempt = {
            "work_item_id": work_item_id,
            "failure_code": _safe_failure_code(failure),
            "failure_fingerprint": fingerprint,
            "attempt_number": len(attempts) + 1,
        }
        self._append_json_line(self.attempt_path, attempt)
        if previous is not None and previous.get("failure_fingerprint") == fingerprint:
            self.append_terminal_result({
                "work_item_id": work_item_id,
                "terminal_status": "failed",
                "failure_code": attempt["failure_code"],
                "failure_fingerprint": fingerprint,
                "repeated_failure_fingerprint": fingerprint,
                "attempt_count": len(attempts) + 1,
            })
            return "failed"
        return "retrying"
