"""R24 injected-context removal and privacy-preserving packet redaction."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import html
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Iterable, Mapping


_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_RULES_PATH = _REPOSITORY_ROOT / "config" / "redaction-rules.json"
_DEFAULT_FINGERPRINTS_PATH = _REPOSITORY_ROOT / "config" / "injected-context-fingerprints.json"


class RedactionStatus(str, Enum):
    SAFE = "safe"
    QUARANTINED = "quarantined"


@dataclass(frozen=True)
class TextRedactionResult:
    status: RedactionStatus
    reason: str | None
    text: str | None
    redaction_count: int = 0


@dataclass(frozen=True)
class RecordRedactionResult:
    status: RedactionStatus
    reason: str | None
    records: tuple[dict[str, str], ...]
    excluded_injected_blocks: int
    excluded_fingerprints: tuple[str, ...]
    redaction_count: int = 0


def _load_json(path: Path) -> Mapping[str, Any]:
    with path.open("r", encoding="utf-8") as stream:
        payload = json.load(stream)
    if not isinstance(payload, dict):
        raise ValueError(f"expected JSON object in {path.name}")
    return payload


def _normalize_for_fingerprint(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _compile_rules(rules_path: Path) -> tuple[tuple[str, re.Pattern[str]], tuple[str, re.Pattern[str], str], tuple[re.Pattern[str], ...]]:
    rules = _load_json(rules_path)
    credential_patterns = tuple(
        (str(entry["id"]), re.compile(str(entry["pattern"])))
        for entry in rules.get("credential_patterns", [])
    )
    redaction_patterns = tuple(
        (str(entry["id"]), re.compile(str(entry["pattern"])), str(entry["replacement"]))
        for entry in rules.get("redaction_patterns", [])
    )
    unsafe_markup = tuple(re.compile(str(pattern)) for pattern in rules.get("unsafe_markup_patterns", []))
    return credential_patterns, redaction_patterns, unsafe_markup


def redact_text(text: str, *, rules_path: Path = _DEFAULT_RULES_PATH) -> TextRedactionResult:
    """Redact sensitive personal data and reject credential-shaped content.

    Credential-shaped material is quarantined instead of masked because the
    provider release check must not rely on a replacement being complete.
    """

    credential_patterns, redaction_patterns, _ = _compile_rules(rules_path)
    for _identifier, pattern in credential_patterns:
        if pattern.search(text):
            return TextRedactionResult(
                status=RedactionStatus.QUARANTINED,
                reason="credential_detected",
                text=None,
            )

    result = text
    redaction_count = 0
    for _identifier, pattern, replacement in redaction_patterns:
        result, count = pattern.subn(replacement, result)
        redaction_count += count

    # HTML escaping preserves readable text while making raw markup inert in
    # packets, receipts, and any later local renderer.
    return TextRedactionResult(
        status=RedactionStatus.SAFE,
        reason=None,
        text=html.escape(result, quote=False),
        redaction_count=redaction_count,
    )


def _stringify_content(value: Any) -> str:
    """Return text fields only; skip non-text structured tool payloads."""

    if isinstance(value, str):
        return value
    if isinstance(value, Mapping):
        if isinstance(value.get("text"), str):
            return str(value["text"])
        content = value.get("content")
        if isinstance(content, (str, list, tuple, Mapping)):
            return _stringify_content(content)
        return ""
    if isinstance(value, (list, tuple)):
        fragments: list[str] = []
        for item in value:
            if isinstance(item, Mapping):
                block_type = item.get("type")
                if block_type not in (None, "text"):
                    continue
            fragment = _stringify_content(item)
            if fragment:
                fragments.append(fragment)
        return "\n".join(fragments)
    return ""


def _strip_known_injected_context(text: str, fingerprints_path: Path) -> tuple[str, int, set[str], bool]:
    """Remove all configured marker blocks and retain hashes only."""

    config = _load_json(fingerprints_path)
    remaining = text
    exclusion_count = 0
    fingerprints: set[str] = set()
    unresolved_marker = False
    for entry in config.get("fingerprints", []):
        start = str(entry.get("start", ""))
        end = str(entry.get("end", ""))
        if not start or not end:
            continue
        search_from = 0
        pieces: list[str] = []
        while True:
            start_index = remaining.find(start, search_from)
            if start_index == -1:
                break
            end_index = remaining.find(end, start_index + len(start))
            if end_index == -1:
                # A partial marker is unsafe. It could be a truncated injected
                # block, so the caller must quarantine before provider egress.
                unresolved_marker = True
                break
            end_index += len(end)
            removed = remaining[start_index:end_index]
            fingerprints.add(_sha256(_normalize_for_fingerprint(removed)))
            exclusion_count += 1
            pieces.append(remaining[search_from:start_index])
            search_from = end_index
        if pieces:
            pieces.append(remaining[search_from:])
            remaining = "".join(pieces)
    return remaining, exclusion_count, fingerprints, unresolved_marker


def redact_records(
    records: Iterable[Mapping[str, Any]],
    *,
    rules_path: Path = _DEFAULT_RULES_PATH,
    fingerprints_path: Path = _DEFAULT_FINGERPRINTS_PATH,
) -> RecordRedactionResult:
    """Apply R24 before any role-specific packet construction.

    Known blocks are stripped from every serialized role. Unknown system or
    hook context fails closed because it must never reach a provider.
    """

    safe_records: list[dict[str, str]] = []
    excluded_count = 0
    excluded_fingerprints: set[str] = set()
    redaction_count = 0

    for record in records:
        role = str(record.get("role", "unknown"))
        original = _stringify_content(record.get("content", ""))
        stripped, block_count, block_fingerprints, unresolved_marker = _strip_known_injected_context(original, fingerprints_path)
        excluded_count += block_count
        excluded_fingerprints.update(block_fingerprints)
        if unresolved_marker:
            return RecordRedactionResult(
                status=RedactionStatus.QUARANTINED,
                reason="unresolved_injected_context",
                records=(),
                excluded_injected_blocks=excluded_count,
                excluded_fingerprints=tuple(sorted(excluded_fingerprints)),
                redaction_count=redaction_count,
            )
        if role.casefold() in {"system", "hook"} and stripped.strip():
            return RecordRedactionResult(
                status=RedactionStatus.QUARANTINED,
                reason="unknown_injected_context",
                records=(),
                excluded_injected_blocks=excluded_count,
                excluded_fingerprints=tuple(sorted(excluded_fingerprints)),
                redaction_count=redaction_count,
            )
        if not stripped.strip():
            continue
        text_result = redact_text(stripped, rules_path=rules_path)
        if text_result.status is RedactionStatus.QUARANTINED:
            return RecordRedactionResult(
                status=RedactionStatus.QUARANTINED,
                reason=text_result.reason,
                records=(),
                excluded_injected_blocks=excluded_count,
                excluded_fingerprints=tuple(sorted(excluded_fingerprints)),
                redaction_count=redaction_count,
            )
        redaction_count += text_result.redaction_count
        if text_result.text:
            safe_records.append({"role": role, "content": text_result.text})

    return RecordRedactionResult(
        status=RedactionStatus.SAFE,
        reason=None,
        records=tuple(safe_records),
        excluded_injected_blocks=excluded_count,
        excluded_fingerprints=tuple(sorted(excluded_fingerprints)),
        redaction_count=redaction_count,
    )


def scan_for_unsafe_content(text: str, *, rules_path: Path = _DEFAULT_RULES_PATH) -> tuple[str, ...]:
    """Return identifiers of sensitive or executable shapes still present."""

    credential_patterns, _redaction_patterns, unsafe_markup = _compile_rules(rules_path)
    findings = [identifier for identifier, pattern in credential_patterns if pattern.search(text)]
    findings.extend("unsafe_markup" for pattern in unsafe_markup if pattern.search(text))
    return tuple(sorted(set(findings)))


def _ensure_private_directory(directory: Path) -> None:
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory_stat = os.lstat(directory)
    if not stat.S_ISDIR(directory_stat.st_mode) or stat.S_ISLNK(directory_stat.st_mode):
        raise ValueError("private output parent is not a real directory")
    if directory_stat.st_uid != os.getuid():
        raise PermissionError("private output parent is not owned by this user")
    os.chmod(directory, 0o700)


def secure_write_text(path: Path, text: str) -> None:
    """Atomically write a 0600 private derived artifact under a 0700 directory."""

    path = Path(path)
    _ensure_private_directory(path.parent)
    if path.exists() or path.is_symlink():
        existing = os.lstat(path)
        if stat.S_ISLNK(existing.st_mode):
            raise ValueError("refusing symlinked private output")

    encoded = text.encode("utf-8")
    temporary = path.parent / f".{path.name}.{os.getpid()}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600)
    try:
        file_stat = os.fstat(descriptor)
        if file_stat.st_uid != os.getuid() or not stat.S_ISREG(file_stat.st_mode):
            raise PermissionError("private output descriptor failed ownership check")
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        os.close(descriptor)
        if temporary.exists():
            temporary.unlink()
