# JAA evidence framing revision, 10 August 2026

## Authority and purpose

The operator's standing instruction is to use the strongest truthful positive
framing that the approved evidence supports. Employer-facing material must not
volunteer internal provenance, implementation disclaimers, unfinished-work
notes, contract caveats or rejection rationales. This revision applies that
instruction without adding a qualification or strengthening a disjunction.

The new append-only source is
`approved_evidence_packet_2026-08-10.json`, SHA-256
`074f036ea50a89bf75402a923fa1be1ddb6f583f385095d73fb96b61c8562eff`.
It supersedes, but does not replace or modify,
`approved_evidence_packet_2026-08-07.json`, SHA-256
`af65238f66490904a46f7adea54706eea08140cca14107b178a5f15dfbce9578`.

## Changed statements

Nine records were rephrased: E-003, E-007, E-008, E-009, E-011, E-014,
E-015, E-017 and E-018. Each new sentence is a positive subset of the prior
sentence. E-007 still says recruited, trained or coached. E-008 still says
design or implementation. Neither disjunction was converted into a conjunction.

Source-bound certification also exposed two stale atlas keys for the unchanged
E-012 and E-016 statements. Their semantic mappings were retained and rebound
to the exact statement hashes in this packet.

The typed evidence atlas now treats E-008 conservatively as professional
website experience. It no longer lets that disjunctive statement satisfy a
requirement that demands both design and implementation.

## Writing audit

The draft removed the negative codas but initially left several related
weakness disclosures elsewhere in the packet. The final pass removed those
remaining disclosures, kept the concrete names and measured test result, and
introduced no em dash, en dash, promotional claim or invented metric.

## Deterministic protection

The employer-facing framing guard now also rejects:

- an unnecessary written-contract caveat;
- commentary that a client abandoned a project;
- disclaiming personal implementation with "rather than" language;
- a statement that work still required repair;
- "not a separate professional project" wording; and
- instructions that evidence "should not be presented" as something.

These patterns are covered by negative-control tests. Positive, supported
capability statements remain accepted.
