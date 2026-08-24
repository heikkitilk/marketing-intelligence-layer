"""KTD19 resource estimation and R25 envelope enforcement."""

from __future__ import annotations

from dataclasses import dataclass
from math import ceil
from typing import Iterable


@dataclass(frozen=True)
class ResourceLimits:
    """The fixed U8 resource envelope from R25."""

    max_input_tokens: int = 500_000
    max_calls: int = 24
    max_wall_minutes: int = 90


R25_LIMITS = ResourceLimits()
FULL_POC_LIMITS = ResourceLimits(
    max_input_tokens=5_000_000,
    max_calls=300,
    max_wall_minutes=360,
)


@dataclass(frozen=True)
class ResourceEstimate:
    """A conservative pre-dispatch resource estimate.

    ``input_tokens`` reserves prompt and retry overhead as well as serialized
    redacted packet bytes. The estimator intentionally uses three bytes per
    token rather than the commonly quoted four-byte approximation.
    """

    input_tokens: int
    output_tokens: int
    calls: int
    wall_minutes: int
    packet_bytes: int
    prompt_tokens: int
    retry_overhead_tokens: int
    bytes_per_token: int
    concurrency: int
    per_call_minutes: int
    monetary_cost_usd: str = "?"


@dataclass(frozen=True)
class TieredStageEstimate:
    """KTD19 estimate derived from manifest groups and bounded packet policy."""

    artifact_count: int
    dependence_group_count: int
    in_window_event_count: int
    classification_representative_count: int
    full_extract_group_count: int
    mixed_sample_group_count: int
    full_stage_group_count: int
    classification_groups_per_call: int
    full_extract_groups_per_call: int
    classification_calls: int
    full_extract_calls: int
    resource_estimate: ResourceEstimate


class ResourceBudgetExceeded(RuntimeError):
    """Raised before model dispatch when an R25 dimension would be crossed."""

    def __init__(self, dimension: str, actual: int, limit: int) -> None:
        super().__init__(f"R25 {dimension} estimate {actual} exceeds limit {limit}")
        self.dimension = dimension
        self.actual = actual
        self.limit = limit


def estimate_probe_resources(
    *,
    packet_bytes: Iterable[int],
    prompt_tokens: int,
    output_tokens_per_call: int,
    calls: int,
    concurrency: int,
    per_call_minutes: int,
    bytes_per_token: int = 3,
    retry_overhead_ratio: float = 0.20,
) -> ResourceEstimate:
    """Estimate an R25-bounded model stage from serialized redacted bytes.

    The caller must include every planned call in ``calls``. The explicit
    retry reserve covers parser or transient retry prompt overhead without
    silently increasing the authorized provider-call count.
    """

    byte_values = tuple(packet_bytes)
    if any(value < 0 for value in byte_values):
        raise ValueError("packet_bytes must be non-negative")
    if min(prompt_tokens, output_tokens_per_call, calls, concurrency, per_call_minutes) < 0:
        raise ValueError("resource inputs must be non-negative")
    if bytes_per_token <= 0 or concurrency <= 0 or per_call_minutes <= 0:
        raise ValueError("bytes_per_token, concurrency, and per_call_minutes must be positive")

    serialized_bytes = sum(byte_values)
    serialized_tokens = ceil(serialized_bytes / bytes_per_token)
    prompt_total = prompt_tokens * calls
    base_input = serialized_tokens + prompt_total
    retry_overhead = ceil(base_input * retry_overhead_ratio)
    output_total = output_tokens_per_call * calls
    wall_minutes = ceil(calls / concurrency) * per_call_minutes
    return ResourceEstimate(
        input_tokens=base_input + retry_overhead,
        output_tokens=output_total,
        calls=calls,
        wall_minutes=wall_minutes,
        packet_bytes=serialized_bytes,
        prompt_tokens=prompt_total,
        retry_overhead_tokens=retry_overhead,
        bytes_per_token=bytes_per_token,
        concurrency=concurrency,
        per_call_minutes=per_call_minutes,
    )


def enforce_r25(estimate: ResourceEstimate, limits: ResourceLimits = R25_LIMITS) -> None:
    """Fail closed before dispatch when an estimate crosses the U8 envelope."""

    checks = (
        ("input_tokens", estimate.input_tokens, limits.max_input_tokens),
        ("calls", estimate.calls, limits.max_calls),
        ("wall_minutes", estimate.wall_minutes, limits.max_wall_minutes),
    )
    for dimension, actual, limit in checks:
        if actual > limit:
            raise ResourceBudgetExceeded(dimension, actual, limit)


def _groups_per_call(*, item_bytes: int, max_packet_bytes: int, max_packet_tokens: int, bytes_per_token: int, stage: str) -> int:
    """Return a capacity that cannot exceed either KTD15 packet limit."""

    packet_payload_limit = min(max_packet_bytes, max_packet_tokens * bytes_per_token)
    if item_bytes > packet_payload_limit:
        raise ValueError(f"{stage}_packet_bytes_exceeds_ktd15_cap")
    return packet_payload_limit // item_bytes


def _batched_packet_bytes(*, item_count: int, item_bytes: int, groups_per_call: int) -> tuple[int, ...]:
    """Make bounded serialized payload sizes without creating provider calls."""

    return tuple(
        min(groups_per_call, item_count - offset) * item_bytes
        for offset in range(0, item_count, groups_per_call)
    )


def estimate_tiered_stage(
    *,
    artifact_count: int,
    dependence_group_count: int,
    in_window_event_count: int,
    full_extract_fraction: float = 0.10,
    mixed_sample_fraction: float = 0.05,
    classification_packet_bytes: int = 1_024,
    full_packet_bytes: int = 10_240,
    max_packet_bytes: int = 100 * 1024,
    max_packet_tokens: int = 32_000,
    bytes_per_token: int = 3,
    prompt_tokens: int = 800,
    output_tokens_per_call: int = 5_000,
    concurrency: int = 2,
    per_call_minutes: int = 20,
) -> TieredStageEstimate:
    """Estimate KTD18's tiered stage from manifest counts, not transcript text.

    Every dependence group remains in scope, but multiple redacted group
    representatives may share one provider request. ``*_packet_bytes`` must
    include each representative's serialized redacted content and packet
    framing. Calls are packed below both KTD15 limits: 100 KiB and 32,000
    estimated tokens by default. U2 must re-estimate from the actual packets
    before dispatch; this preflight never authorizes an oversized packet.
    """

    scalar_values = (
        artifact_count,
        dependence_group_count,
        in_window_event_count,
        classification_packet_bytes,
        full_packet_bytes,
        max_packet_bytes,
        max_packet_tokens,
        bytes_per_token,
        prompt_tokens,
        output_tokens_per_call,
        concurrency,
        per_call_minutes,
    )
    if any(value < 0 for value in scalar_values):
        raise ValueError("tiered estimation inputs must be non-negative")
    if not 0 <= full_extract_fraction <= 1 or not 0 <= mixed_sample_fraction <= 1:
        raise ValueError("tier fractions must be between zero and one")
    if min(
        classification_packet_bytes,
        full_packet_bytes,
        max_packet_bytes,
        max_packet_tokens,
        bytes_per_token,
        concurrency,
        per_call_minutes,
    ) <= 0:
        raise ValueError("packet and execution limits must be positive")

    classification_groups_per_call = _groups_per_call(
        item_bytes=classification_packet_bytes,
        max_packet_bytes=max_packet_bytes,
        max_packet_tokens=max_packet_tokens,
        bytes_per_token=bytes_per_token,
        stage="classification",
    )
    full_extract_groups_per_call = _groups_per_call(
        item_bytes=full_packet_bytes,
        max_packet_bytes=max_packet_bytes,
        max_packet_tokens=max_packet_tokens,
        bytes_per_token=bytes_per_token,
        stage="full_extract",
    )
    classification_representative_count = dependence_group_count
    full_extract_group_count = ceil(dependence_group_count * full_extract_fraction) if dependence_group_count else 0
    mixed_sample_group_count = ceil(dependence_group_count * mixed_sample_fraction) if dependence_group_count else 0
    full_stage_group_count = min(dependence_group_count, full_extract_group_count + mixed_sample_group_count)
    classification_calls = ceil(classification_representative_count / classification_groups_per_call) if classification_representative_count else 0
    full_extract_calls = ceil(full_stage_group_count / full_extract_groups_per_call) if full_stage_group_count else 0
    total_calls = classification_calls + full_extract_calls
    packet_bytes = (
        _batched_packet_bytes(
            item_count=classification_representative_count,
            item_bytes=classification_packet_bytes,
            groups_per_call=classification_groups_per_call,
        )
        + _batched_packet_bytes(
            item_count=full_stage_group_count,
            item_bytes=full_packet_bytes,
            groups_per_call=full_extract_groups_per_call,
        )
    )
    estimate = estimate_probe_resources(
        packet_bytes=packet_bytes,
        prompt_tokens=prompt_tokens,
        output_tokens_per_call=output_tokens_per_call,
        calls=total_calls,
        concurrency=concurrency,
        per_call_minutes=per_call_minutes,
        bytes_per_token=bytes_per_token,
    )
    return TieredStageEstimate(
        artifact_count=artifact_count,
        dependence_group_count=dependence_group_count,
        in_window_event_count=in_window_event_count,
        classification_representative_count=classification_representative_count,
        full_extract_group_count=full_extract_group_count,
        mixed_sample_group_count=mixed_sample_group_count,
        full_stage_group_count=full_stage_group_count,
        classification_groups_per_call=classification_groups_per_call,
        full_extract_groups_per_call=full_extract_groups_per_call,
        classification_calls=classification_calls,
        full_extract_calls=full_extract_calls,
        resource_estimate=estimate,
    )
