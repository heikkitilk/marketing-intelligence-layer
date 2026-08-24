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
gating, generic-candidate rejection, unsupported `[DATA]` rejection, failed
threshold receipts, and false exact-deduplication detection.
