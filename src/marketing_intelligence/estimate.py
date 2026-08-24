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
