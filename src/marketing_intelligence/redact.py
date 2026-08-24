"""Versioned R24 context removal and deterministic packet redaction.

This module keeps source text in memory only long enough to produce redacted
packet text. Callers receive safe reason codes, typed markers, and normalized
fingerprints, never source values or local paths.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from enum import Enum
from functools import lru_cache
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
from typing import Any, Iterable, Mapping


_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_RULES_PATH = _REPOSITORY_ROOT / "config" / "redaction-rules.json"
_DEFAULT_FINGERPRINTS_PATH = _REPOSITORY_ROOT / "config" / "injected-context-fingerprints.json"
_HTML_ENTITY = re.compile(r"&(?!amp;|lt;|gt;|quot;|#\d+;|#x[0-9a-fA-F]+;)")
_TOKEN = re.compile(r"[A-Za-z0-9._~+/-]+")


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
class ContextInspection:
    """A source-free description of injected-context handling for one string."""

    status: RedactionStatus
    reason: str | None
    text: str | None
    excluded_injected_blocks: int = 0
    excluded_fingerprints: tuple[str, ...] = ()


@dataclass(frozen=True)
class RecordRedactionResult:
    status: RedactionStatus
    reason: str | None
    records: tuple[dict[str, str], ...]
    excluded_injected_blocks: int
    excluded_fingerprints: tuple[str, ...]
    redaction_count: int = 0


@dataclass(frozen=True)
class _EntropyRule:
    identifier: str
    minimum_length: int
    minimum_shannon_entropy: float
    context_pattern: re.Pattern[str]


@dataclass(frozen=True)
class _RedactionPolicy:
    version: str
    credential_patterns: tuple[tuple[str, re.Pattern[str]], ...]
    redaction_patterns: tuple[tuple[str, re.Pattern[str], str], ...]
    unsafe_markup_patterns: tuple[re.Pattern[str], ...]
    entropy_rules: tuple[_EntropyRule, ...]
    false_positive_overrides: tuple[re.Pattern[str], ...]


@dataclass(frozen=True)
class _FingerprintRule:
    identifier: str
    start: str
    end: str
    expected_hashes: frozenset[str]


@dataclass(frozen=True)
class _FingerprintPolicy:
    version: str
    rules: tuple[_FingerprintRule, ...]
    unknown_instruction_patterns: tuple[re.Pattern[str], ...]


def _load_json(path: Path) -> Mapping[str, Any]:
    with Path(path).open("r", encoding="utf-8") as stream:
        payload = json.load(stream)
    if not isinstance(payload, dict):
        raise ValueError("redaction_config_not_object")
    return payload


def _cache_key(path: Path) -> str:
    return str(Path(path).expanduser().resolve())


@lru_cache(maxsize=16)
def _load_redaction_policy(path_text: str) -> _RedactionPolicy:
    rules = _load_json(Path(path_text))
    credential_patterns = tuple(
        (str(entry["id"]), re.compile(str(entry["pattern"])))
        for entry in rules.get("credential_patterns", ())
        if isinstance(entry, Mapping) and "id" in entry and "pattern" in entry
    )
    redaction_patterns = tuple(
        (str(entry["id"]), re.compile(str(entry["pattern"])), str(entry["replacement"]))
        for entry in rules.get("redaction_patterns", ())
        if isinstance(entry, Mapping) and "id" in entry and "pattern" in entry and "replacement" in entry
    )
    unsafe_markup = tuple(re.compile(str(pattern)) for pattern in rules.get("unsafe_markup_patterns", ()))
    entropy_rules = tuple(
        _EntropyRule(
            identifier=str(entry["id"]),
            minimum_length=int(entry["minimum_length"]),
            minimum_shannon_entropy=float(entry["minimum_shannon_entropy"]),
            context_pattern=re.compile(str(entry["requires_context_pattern"])),
        )
        for entry in rules.get("entropy_rules", ())
        if isinstance(entry, Mapping)
        and {"id", "minimum_length", "minimum_shannon_entropy", "requires_context_pattern"}.issubset(entry)
    )
    overrides = tuple(
        re.compile(str(entry["pattern"]))
        for entry in rules.get("false_positive_overrides", ())
        if isinstance(entry, Mapping) and "pattern" in entry
    )
    version = rules.get("version")
    if not isinstance(version, str) or not version:
        raise ValueError("redaction_policy_version_missing")
    return _RedactionPolicy(
        version=version,
        credential_patterns=credential_patterns,
        redaction_patterns=redaction_patterns,
        unsafe_markup_patterns=unsafe_markup,
        entropy_rules=entropy_rules,
        false_positive_overrides=overrides,
    )


@lru_cache(maxsize=16)
def _load_fingerprint_policy(path_text: str) -> _FingerprintPolicy:
    config = _load_json(Path(path_text))
    rules: list[_FingerprintRule] = []
    for entry in config.get("fingerprints", ()):
        if not isinstance(entry, Mapping):
            continue
        start = entry.get("start")
        end = entry.get("end")
        identifier = entry.get("id")
        if not isinstance(start, str) or not start or not isinstance(end, str) or not end or not isinstance(identifier, str):
            continue
        configured_hashes = entry.get("normalized_sha256", ())
        if isinstance(configured_hashes, str):
            configured_hashes = (configured_hashes,)
        expected_hashes = frozenset(
            value for value in configured_hashes if isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value)
        ) if isinstance(configured_hashes, (list, tuple, frozenset)) else frozenset()
        rules.append(_FingerprintRule(identifier=identifier, start=start, end=end, expected_hashes=expected_hashes))
    unknown_patterns = tuple(re.compile(str(pattern)) for pattern in config.get("unknown_instruction_patterns", ()))
    version = config.get("version")
    if not isinstance(version, str) or not version:
        raise ValueError("injected_context_policy_version_missing")
    return _FingerprintPolicy(version=version, rules=tuple(rules), unknown_instruction_patterns=unknown_patterns)


def redaction_policy_version(*, rules_path: Path = _DEFAULT_RULES_PATH) -> str:
    """Return the configured redaction policy version without policy bodies."""

    return _load_redaction_policy(_cache_key(rules_path)).version


def fingerprint_policy_version(*, fingerprints_path: Path = _DEFAULT_FINGERPRINTS_PATH) -> str:
    """Return the context-fingerprint policy version without source text."""

    return _load_fingerprint_policy(_cache_key(fingerprints_path)).version


def _normalize_for_fingerprint(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def normalized_fingerprint(value: str) -> str:
    """Return a stable normalized SHA-256 fingerprint for safe provenance."""

    return hashlib.sha256(_normalize_for_fingerprint(value).encode("utf-8")).hexdigest()


def _stringify_content(value: Any) -> str:
    """Return textual content only and intentionally ignore binary/image blocks."""

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
            if isinstance(item, Mapping) and item.get("type") not in (None, "text", "tool_result"):
                continue
            fragment = _stringify_content(item)
            if fragment:
                fragments.append(fragment)
        return "\n".join(fragments)
    return ""


def inspect_injected_context(
    text: str,
    *,
    fingerprints_path: Path = _DEFAULT_FINGERPRINTS_PATH,
) -> ContextInspection:
    """Strip registered R24 blocks and fail closed on changed or unknown blocks."""

    policy = _load_fingerprint_policy(_cache_key(fingerprints_path))
    remaining = text
    fingerprints: set[str] = set()
    excluded = 0
    for rule in policy.rules:
        search_from = 0
        pieces: list[str] = []
        found = False
        while True:
            start_index = remaining.find(rule.start, search_from)
            if start_index == -1:
                break
            found = True
            end_index = remaining.find(rule.end, start_index + len(rule.start))
            if end_index == -1:
                return ContextInspection(
                    status=RedactionStatus.QUARANTINED,
                    reason="unresolved_injected_context",
                    text=None,
                    excluded_injected_blocks=excluded,
                    excluded_fingerprints=tuple(sorted(fingerprints)),
                )
            end_index += len(rule.end)
            removed = remaining[start_index:end_index]
            digest = normalized_fingerprint(removed)
            if rule.expected_hashes and digest not in rule.expected_hashes:
                return ContextInspection(
                    status=RedactionStatus.QUARANTINED,
                    reason="unknown_injected_context",
                    text=None,
                    excluded_injected_blocks=excluded,
                    excluded_fingerprints=tuple(sorted(fingerprints)),
                )
            fingerprints.add(digest)
            excluded += 1
            pieces.append(remaining[search_from:start_index])
            search_from = end_index
        if found:
            pieces.append(remaining[search_from:])
            remaining = "".join(pieces)
    if any(pattern.search(remaining) for pattern in policy.unknown_instruction_patterns):
        return ContextInspection(
            status=RedactionStatus.QUARANTINED,
            reason="unknown_injected_context",
            text=None,
            excluded_injected_blocks=excluded,
            excluded_fingerprints=tuple(sorted(fingerprints)),
        )
    return ContextInspection(
        status=RedactionStatus.SAFE,
        reason=None,
        text=remaining,
        excluded_injected_blocks=excluded,
        excluded_fingerprints=tuple(sorted(fingerprints)),
    )


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    size = len(value)
    return -sum((count / size) * math.log2(count / size) for count in counts.values())


def _matches_false_positive_override(value: str, policy: _RedactionPolicy) -> bool:
    return any(pattern.fullmatch(value) for pattern in policy.false_positive_overrides)


def _contains_high_entropy_secret(text: str, policy: _RedactionPolicy) -> bool:
    for rule in policy.entropy_rules:
        for match in _TOKEN.finditer(text):
            candidate = match.group(0)
            if len(candidate) < rule.minimum_length or _matches_false_positive_override(candidate, policy):
                continue
            prefix = text[max(0, match.start() - 96):match.start()]
            if rule.context_pattern.search(prefix) and _shannon_entropy(candidate) >= rule.minimum_shannon_entropy:
                return True
    return False


def _escape_markup_idempotent(value: str) -> str:
    """Escape executable markup without double-escaping an already safe packet."""

    escaped = _HTML_ENTITY.sub("&amp;", value)
    return escaped.replace("<", "&lt;").replace(">", "&gt;")


def redact_text(text: str, *, rules_path: Path = _DEFAULT_RULES_PATH) -> TextRedactionResult:
    """Apply the versioned policy before and after packet serialization."""

    policy = _load_redaction_policy(_cache_key(rules_path))
    for _identifier, pattern in policy.credential_patterns:
        if pattern.search(text):
            return TextRedactionResult(status=RedactionStatus.QUARANTINED, reason="credential_detected", text=None)
    if _contains_high_entropy_secret(text, policy):
        return TextRedactionResult(status=RedactionStatus.QUARANTINED, reason="credential_detected", text=None)
    result = text
    redaction_count = 0
    for _identifier, pattern, replacement in policy.redaction_patterns:
        result, count = pattern.subn(replacement, result)
        redaction_count += count
    return TextRedactionResult(
        status=RedactionStatus.SAFE,
        reason=None,
        text=_escape_markup_idempotent(result),
        redaction_count=redaction_count,
    )


def redact_records(
    records: Iterable[Mapping[str, Any]],
    *,
    rules_path: Path = _DEFAULT_RULES_PATH,
    fingerprints_path: Path = _DEFAULT_FINGERPRINTS_PATH,
) -> RecordRedactionResult:
    """Apply R24 before role filtering, then redact text with typed markers."""

    safe_records: list[dict[str, str]] = []
    excluded_count = 0
    excluded_fingerprints: set[str] = set()
    redaction_count = 0
    for record in records:
        role = str(record.get("role", "unknown"))
        inspection = inspect_injected_context(
            _stringify_content(record.get("content", "")),
            fingerprints_path=fingerprints_path,
        )
        excluded_count += inspection.excluded_injected_blocks
        excluded_fingerprints.update(inspection.excluded_fingerprints)
        if inspection.status is RedactionStatus.QUARANTINED:
            return RecordRedactionResult(
                status=RedactionStatus.QUARANTINED,
                reason=inspection.reason,
                records=(),
                excluded_injected_blocks=excluded_count,
                excluded_fingerprints=tuple(sorted(excluded_fingerprints)),
                redaction_count=redaction_count,
            )
        assert inspection.text is not None
        if role.casefold() in {"system", "developer", "hook"} and inspection.text.strip():
            return RecordRedactionResult(
                status=RedactionStatus.QUARANTINED,
                reason="unknown_injected_context",
                records=(),
                excluded_injected_blocks=excluded_count,
                excluded_fingerprints=tuple(sorted(excluded_fingerprints)),
                redaction_count=redaction_count,
            )
        if not inspection.text.strip():
            continue
        text_result = redact_text(inspection.text, rules_path=rules_path)
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
    """Return detector identifiers for secret or executable markup still present."""

    policy = _load_redaction_policy(_cache_key(rules_path))
    findings = [identifier for identifier, pattern in policy.credential_patterns if pattern.search(text)]
    if _contains_high_entropy_secret(text, policy):
        findings.append("high_entropy_secret")
    findings.extend("unsafe_markup" for pattern in policy.unsafe_markup_patterns if pattern.search(text))
    return tuple(sorted(set(findings)))


def _ensure_private_directory(directory: Path) -> None:
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory_stat = os.lstat(directory)
    if not stat.S_ISDIR(directory_stat.st_mode) or stat.S_ISLNK(directory_stat.st_mode):
        raise ValueError("private_output_not_directory")
    if directory_stat.st_uid != os.getuid():
        raise PermissionError("private_output_unsafe_owner")
    os.chmod(directory, 0o700)


def secure_write_text(path: Path, text: str) -> None:
    """Atomically write a 0600 private derived artifact under a 0700 directory."""

    path = Path(path)
    _ensure_private_directory(path.parent)
    if path.exists() or path.is_symlink():
        existing = os.lstat(path)
        if stat.S_ISLNK(existing.st_mode):
            raise ValueError("refusing_symlinked_private_output")
    encoded = text.encode("utf-8")
    temporary = path.parent / f".{path.name}.{os.getpid()}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600)
    try:
        file_stat = os.fstat(descriptor)
        if file_stat.st_uid != os.getuid() or not stat.S_ISREG(file_stat.st_mode):
            raise PermissionError("private_output_descriptor_unsafe")
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
