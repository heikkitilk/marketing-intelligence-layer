# Session proof-of-concept runbook

## U7 extraction-quality pilot

The U7 pilot evaluates redacted U2 packets only. It never reads raw transcript
sources, calls a provider, runs an extractor, or lets a reviewer see extractor
results.

### Prepare the reference set

Use a fresh, Git-ignored output directory. The command first verifies that the
U2 manifest binds the canonical U1 manifest document. It joins every prepared
U2 packet to the U1 record with the same `artifact_id`, and fails closed if
the harness, source version, eligibility, or required U1 metadata disagrees.
It then reads only redacted U2 packet text to calculate the deterministic
pre-label heuristic. It never reads raw transcripts or calls a provider.

```sh
PYTHONPATH=src python3 -m marketing_intelligence.cli quality-pilot prepare \
  --source-manifest <u1-root>/manifest.json \
  --packet-manifest <u2-root>/packet-manifest.json \
  --packet-root <u2-root>/packets \
  --output-root .u8-private/u7-quality-pilot-<run-id>
```

The selector has 24 predeclared slots. It globally minimizes weighted
substitutions while keeping all selected packet IDs unique. It gets
`execution_kind` and its provenance from
`classification.execution_shape`, maps `source_kind` to `artifact_role`, and
uses only U1 working-directory or dependence metadata for `workload_class`.
It calculates `learning_expectation` with the fixed
`redacted_packet_heuristic_v1` rule: at least 2 marketing terms, at least 1
decision term, and more marketing than harness terms in redacted event text.
The selection records the rule, provenance, and term counts. It does not use a
provider or model output for that label.

The receipt records every requested and actual stratum, a deterministic
`selection_sha256`, explicit absent required strata, and every weighted
substitution. It never labels a substituted packet as coverage of a missing
stratum. `mixed_work` is optional and remains explicitly absent unless U1
metadata contains that category.

The command returns one of these states:

- `reviewer_packet_frozen`: The private root contains `selection.json`,
  `reviewer-label-schema.json`, `reviewer-packets/`, `reviewer-index.json`,
  `reference-set-receipt.json`, and `artifact-order.jsonl`. Directories use
  mode `0700`; files use mode `0600`.
- `reduced_scope`: The root contains only
  `reduced-scope-selection-receipt.json` and `artifact-order.jsonl`. Do not
  create reviewer labels, extractor results, or a provider dispatch. The
  receipt names the blocking stratum and blocks U4, U5, and U6.

Both outputs are content-addressed. `artifact-order.jsonl` chains every
artifact hash in creation order. A changed artifact, an unledgered artifact,
or a symlink causes a fail-closed error.

### Run the blind review

Only after `reviewer_packet_frozen`, give a fresh read-only reviewer exactly
these private artifacts:

- `reviewer-index.json`
- `reviewer-label-schema.json`
- `reviewer-packets/`

Do not give the reviewer an extractor result, raw source, source manifest, or
provider tool. The reviewer returns one schema-valid labels document that binds
to `selection_sha256`. Each packet label records its expected outcome,
approved observed `[DATA]` evidence URIs, eligible topics, relevance and
transferability expectations, novelty against the U8/R23 baseline, and whether
the learning has a non-harness marketing use.

The labels artifact must be written before any extractor result artifact. The
immutable store rejects extractor results without the labels hash and rejects
late labels after extractor results exist.

### Ingest the blind labels

The labels document is private input. Keep a file input mode `0600`, or supply
the complete JSON document on standard input. The command validates the
complete document against the frozen selection and observed reviewer-packet
evidence before it writes `reviewer-labels.json`. It prints only hashes and
counts, never label content.

```sh
chmod 600 <private-labels>.json
PYTHONPATH=src python3 -m marketing_intelligence.cli quality-pilot labels \
  --output-root .u8-private/u7-quality-pilot-<run-id> \
  --input-file <private-labels>.json
```

To use standard input, use this exact command. Do not redirect an untrusted or
shared file into the command.

```sh
PYTHONPATH=src python3 -m marketing_intelligence.cli quality-pilot labels \
  --output-root .u8-private/u7-quality-pilot-<run-id> \
  --stdin < <private-labels>.json
```

### Preflight the 24 extraction packets

Run preflight after immutable labels exist and before any provider release. It
projects only the approved redacted packet fields: `packet_id`, `harness`,
`source_version`, `event_ids`, and redacted `events`. It reports input tokens,
output tokens, 24-call count, two-call concurrency, concurrency-adjusted wall
time, and monetary cost when you supply current input and output prices. It
does not print packet or candidate bodies.

```sh
PYTHONPATH=src python3 -m marketing_intelligence.cli quality-pilot preflight \
  --output-root .u8-private/u7-quality-pilot-<run-id> \
  --input-usd-per-million <current-input-price> \
  --output-usd-per-million <current-output-price>
```

Omit both price flags when no current provider price is available. The output
then reports `projected_monetary_cost_usd: "?"`.

The preflight reserves `1,200` prompt tokens and `3,500` output tokens per
packet, uses the conservative three-bytes-per-token conversion, limits the
Claude timeout to seven minutes, and uses two concurrent calls. That produces
an 84-minute upper wall-time bound for 24 calls. If any R25 limit is exceeded,
the command writes an immutable `execution-v2/preflight.json` reduced-scope
receipt, returns exit status `2`, blocks U4-U6, and makes provider dispatch
unavailable. It also blocks egress when one approved packet exceeds the smaller
of `100 KiB` and `32,000` estimated input tokens. Claude result output is
bounded to `256 KiB` before JSON parsing.

### Extract and ingest provider-affine results

Only run these commands after preflight reports `preflight_ready`.

For a Claude packet, use the built-in first-party Claude CLI path. The private
release file must attest to the authenticated first-party Claude account, an
available verified model, first-party encrypted transport, the preflight work
item and packet hashes, disabled tools, disabled persistence, a bounded timeout
of at most seven minutes, and a bounded per-call budget. The command invokes
`claude --print` with `--tools ""`, `--no-session-persistence`, safe mode,
strict MCP configuration, a JSON schema, and no fallback model. It does not
retry automatically and never prints provider output. It records only a safe
failure fingerprint in the private Claude checkpoint. One later attended retry
is possible when it yields a different failure. Two consecutive identical
failures become a terminal failed checkpoint and block another Claude call.

```sh
chmod 600 <private-claude-release>.json
PYTHONPATH=src python3 -m marketing_intelligence.cli quality-pilot claude-extract \
  --output-root .u8-private/u7-quality-pilot-<run-id> \
  --packet-id <selected-claude-packet-id> \
  --release-file <private-claude-release>.json
```

If the verified Claude CLI result arrives through a separate attended path,
ingest its complete private result envelope instead. The envelope has schema
version `quality-pilot-provider-result/v1` and binds `packet_id`, `release`,
and `document`; its release must identify `anthropic-claude-cli`.

```sh
chmod 600 <private-claude-result>.json
PYTHONPATH=src python3 -m marketing_intelligence.cli quality-pilot ingest-claude-result \
  --output-root .u8-private/u7-quality-pilot-<run-id> \
  --input-file <private-claude-result>.json
```

Codex has no cross-provider fallback. A verified authenticated first-party
Codex seat must produce its result first. Its private envelope must bind the
preflight work-item ID and packet hash, identify
`authenticated-first-party-codex-seat`, and attest to first-party account,
seat, available model, encrypted transport, and an empty raw-tools list. Then
ingest it through the explicit Codex path.

```sh
chmod 600 <private-codex-result>.json
PYTHONPATH=src python3 -m marketing_intelligence.cli quality-pilot ingest-codex-result \
  --output-root .u8-private/u7-quality-pilot-<run-id> \
  --input-file <private-codex-result>.json
```

Every ingestion normalizes each candidate ID in code from its packet ID and
candidate body. Missing IDs, placeholder IDs, and provider-chosen IDs all
become deterministic stable IDs before candidate-schema validation. An invalid
candidate document is retained only in the private staging ledger with terminal
status `rejected_invalid`; the command prints its count and hash, not its body.
That terminal outcome creates a failed `candidate_document_validity` gate metric
and blocks U4-U6. Provider-affinity or release failures are rejected before any
result write.

### Combine and score all terminal outcomes

Run this only after every selected packet has one staged terminal outcome. The
command fails closed without writing `extractor-results.json` when one of the
24 packet outcomes is absent. It revalidates every document against
`candidate-learning.schema.json`, writes exactly one
`quality-extractor-results/v1` document bound to `reviewer_labels_sha256`,
then evaluates and writes `pilot-gate-receipt.json`.

```sh
PYTHONPATH=src python3 -m marketing_intelligence.cli quality-pilot combine \
  --output-root .u8-private/u7-quality-pilot-<run-id>
```

The command returns exit status `0` only for `passed`. Any failed quality
metric returns exit status `2` after writing the immutable `reduced_scope`
receipt. The receipt records the reviewer-label hash, extractor-results hash,
24 terminal-outcome count, failed metrics, and `blocked_units: [U4, U5, U6]`.

### Score the pilot

The evaluation applies the candidate schema and U2 evidence URI contract before
scoring. It permits `[DATA]` only when every cited URI is an observed event in
the selected packet and appears in the reviewer-approved evidence set.

U4, U5, and U6 proceed only if all of these hold:

- `[DATA]` faithfulness is `100%`.
- Relevance is at least `80%`.
- Transferability is at least `70%`.
- No-learning accuracy is at least `80%`.
- False exact-deduplication collapses equal `0`.
- Every accepted candidate is baseline-novel and has a non-harness marketing
  decision, action, or consequence.

Any failed metric produces an immutable `pilot-gate-receipt.json` with
`status: reduced_scope`, the failed metrics, and `blocked_units: [U4, U5, U6]`.

### Clear a hard real-selection block

If the receipt contains `codex_packets_absent`, do not substitute Claude
packets and do not begin blind review. Repair U2 so its real private manifest
contains both harnesses, then run `quality-pilot prepare` with the matching U1
manifest and a new private output root. If the command reports a U1/U2 hash,
harness, source-version, or eligibility mismatch, repair the mismatched source
artifact rather than weakening the join. That new frozen packet is the only
valid input for a fresh blind reviewer.

### Verify the implementation

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_quality_pilot.py'
PYTHONPATH=src python3 -m unittest discover -s tests
```

The first command covers deterministic strata and hash selection, blind-order
gating, private reviewer-label ingestion, R25 preflight caps, provider
affinity, deterministic candidate IDs, invalid output handling, complete
24-packet combination, failed-threshold receipts, and false
exact-deduplication detection.
