# Session packet redaction policy

## Purpose

The session normalizer treats transcript material as untrusted input. It keeps raw
transcripts in their original local roots and writes only redacted packets and
source-free metadata to an ignored private directory.

The current policy versions are `u2-redaction-v2` and
`u2-injected-context-v2`. Packet metadata records both versions so a later run
can identify the exact deterministic policy that produced it.

## Processing order

1. The normalizer opens a regular source file with no-follow checks, verifies
   that the opened descriptor belongs to the current user, and verifies that
   the descriptor is unchanged from open through the end of that read.
2. It checks every textual field for registered injected-context blocks before
   mapping a record to a user, assistant, tool, or tool-result event.
3. It removes a registered block only when its normalized fingerprint is
   accepted by the configured rule. It retains only the SHA-256 fingerprint,
   record-type provenance, and aggregate count.
4. It quarantines an unresolved, changed, or unregistered instruction, memory,
   policy, startup, system, or hook block. The quarantine record contains a
   safe reason code, not the source text.
5. It applies typed redaction markers to sensitive personal data, proprietary
   identifiers, local paths, and similar configured text. Credential-shaped or
   high-entropy secrets in a sensitive context quarantine the full artifact.
6. It escapes raw markup, serializes a packet deterministically, then runs the
   same redaction policy and unsafe-content scan over the serialized bytes.
   A packet that needs a second unexpected transformation is rebuilt from the
   safe serialized form or quarantined if that form is invalid.

## Safe outputs

Each packet stores only these fields:

- Stable packet, artifact, event, and evidence identifiers.
- Event ordinal, timestamp, normalized role, and evidence strength.
- Versioned evidence URI in the form `session://<harness>/<artifact>@<version>#event=<id>`.
- Redacted, escaped event text.
- Policy versions and packet event coverage.

Receipts and coverage records store aggregate counts, fingerprints, terminal
states, reason codes, and deterministic hashes. They do not store source paths,
raw record bodies, credentials, or candidate-learning content. A two-pass
receipt records any cross-pass raw-byte delta only as aggregate counts and
hashes. A post-cutoff append can change that observation without changing the
fixed-window canonical event or packet hashes.

## Fail-closed conditions

The normalizer quarantines an artifact or packet for these safe reason classes:

- `record_too_large`, `event_too_large`, or `packet_too_large`.
- `credential_detected` or post-serialization unsafe-content detection.
- `unknown_injected_context` or `unresolved_injected_context`.
- A changed source descriptor, malformed record, source-manifest mismatch, or
  unsafe source/output filesystem object.

The limits are 2 MiB per source record, 256 KiB per normalized event, and
100 KiB or 32,000 estimated tokens per packet. Packets split only between
events. An event that cannot fit alone quarantines instead of being truncated.

## Private output boundary

The command accepts only a new Git-ignored output root. The root and all
subdirectories must be owned by the current user and use mode `0700`. Files use
mode `0600`. Existing permissive roots and every symlinked root or child are
rejected.

No packet leaves the local boundary in U2, which has no model stage. The
receipt labels its KTD19 value as a naive all-packet egress shape based on
actual serialized redacted packet bytes. If that shape exceeds its envelope,
U3 must derive compact dependence-group classification work and re-estimate it
before any future dispatch.
