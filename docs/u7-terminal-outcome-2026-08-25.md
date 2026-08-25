# U7 quality pilot: terminal reduced-scope outcome

Date: 2026-08-25 (AMT).

This document supersedes the operational conclusions in
`u7-blockers-2026-08-25.md` without rewriting that historical record. The
earlier note came from Claude session `1097723f-7c2e-4d59-b346-6d505ab8c4b9`.

## Corrections to the pre-dispatch note

- [DATA] U7 originally imported the 500,000-token U8 value-probe limit. Plan
  R25 assigns the full proof-of-concept model stage a 5,000,000-token limit.
  Policy `quality-pilot-execution/v2` now applies the full-stage limits and
  preserves the incorrect v1 receipt under `execution/`.
- [DATA] Conditional quality metrics originally divided by all five expected
  learning packets. The corrected scorer divides relevance by labels that
  require relevance, transferability by labels that require transferability,
  and novelty/usefulness by labels marked both baseline-novel and
  non-harness-useful.
- [DATA] A verified authenticated `gpt-5.6-terra` at `max` seat completed the
  single Codex-affine packet. No cross-provider substitution occurred.

## Corrected preflight

- [DATA] Selection SHA-256:
  `9521597e067c1c53806e39f3123f7641206efc1da4df7d6f8e78c3702e36ef3b`.
- [DATA] Reviewer-label SHA-256:
  `f69e65886e16eb73b48ef1318c875f4a282779d45f4b1beb5b79284edaf77128`.
- [DATA] Preflight SHA-256:
  `53850e2bbf987f9b9adaf38ce094c0830e13e5a28179ada0966b35b6c3242c45`.
- [DATA] Projected use: 532,280 input tokens, 84,000 output tokens, 24 calls,
  and 84 minutes at concurrency two. Monetary cost remains `?` because no
  verified current provider prices were supplied.
- [DATA] R25 status: ready under 5,000,000 input tokens, 300 calls, and 360
  minutes.

## Terminal extraction result

- [DATA] All 24 selected packets have immutable terminal outcomes: 23 Claude
  packets and one Codex packet.
- [DATA] Claude outcomes: nine extracted, nine `no_learning`, and five
  `rejected_invalid`.
- [DATA] Each invalid Claude document cited at least one non-observed evidence
  event for a `[DATA]` candidate. The validator preserved all five failures.
- [DATA] The Codex packet ended as a valid `no_learning` result.
- [DATA] Extractor-results SHA-256:
  `4087324f94270cf5f0a76db2617180af8eaf4fe299c69be1a3dfdcfec1e02c36`.
- [DATA] Pilot-gate receipt SHA-256:
  `3774aedc7fcfd3ded653396d1286eaab40a9470f43f312e523132a31e772b27a`.

## Gate metrics

- [DATA] Candidate-document validity failed with five invalid packets; zero
  were allowed.
- [DATA] Data faithfulness failed at 0/22, or 0%; 100% was required.
- [DATA] Relevance failed at 2/5, or 40%; at least 80% was required.
- [DATA] Transferability failed at 0/1, or 0%; at least 70% was required.
- [DATA] No-learning accuracy failed at 15/24, or 62.5%; at least 80% was
  required.
- [DATA] Novelty and non-harness usefulness failed at 1/2, or 50%; 100% was
  required.
- [DATA] Exact deduplication passed with zero false collapses; zero was the
  maximum.

## Terminal decision

[LOGIC] The proof of concept ends as delivered with reduced scope. U4, U5, and
U6 remain unbuilt because the predeclared U7 extraction-quality gate failed.
Building reconciliation, rendering, or full-corpus extraction would turn a
measured model-quality failure into a polished but unreliable output.

[LOGIC] A future attempt must start a new extraction experiment with a revised
prompt or model strategy and a fresh blind reference set. It must not rewrite
this immutable run or its reviewer labels.
