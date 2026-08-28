# Human-review continuation after the U7 reduced-scope result

Date: August 28, 2026 (AMT)

## Outcome

[DATA] The historical U7 pilot remains a delivered-with-reduced-scope record.
It measured automated extraction proxies and did not authorize publication.

[DATA] This continuation adds a separate human-review queue and accepted-only
publication path. It preserves the upstream requirement to show extracted
learnings before updating the intelligence layer.

[LOGIC] Machine-qualified value-probe candidates are proposals, not accepted
intelligence. Every proposal starts pending and requires exactly one human
`accept`, `edit`, or `reject` decision.

## Publication contract

- [DATA] The review queue is content-addressed and retains every evidence URI
  and source candidate ID through exact duplicate collapse.
- [DATA] The exported decision document binds to the queue hash.
- [DATA] Publication fails when a proposal is undecided, duplicated, unknown,
  or attached to a different queue.
- [DATA] Rejected proposals never enter `accepted-intelligence.json` or
  `index.html`.
- [DATA] Review and publication artifacts remain in Git-ignored owner-only
  directories.

## Deferred scope

[LOGIC] The continuation does not run unattended extraction across the complete
August 17-24 corpus. That U6 scope remains deferred until reviewed candidates
demonstrate enough value to justify the additional model work.
