# JAA candidate-authority materialization — 2026-08-06

## Implemented boundary

`career_automation.candidate_authority` now materializes the production candidate
projection and all 21 Greenhouse vacancy decision receipts from the cited immutable
sources. It opens the imported jobs database with SQLite read-only/immutable mode,
verifies every approved source hash, and writes only create-only content-addressed
objects under the configured application archive.

The materializer:

- projects only approved E-001 through E-018 statements and hashes;
- retains Q-001 through Q-010 only as negative claim suppressors;
- normalizes the current UK work-right, residence, availability, and attendance facts;
- extracts atomic requirements from the exact database vacancy body;
- computes matched, gap, and suppressed evidence rows deterministically;
- recomputes eligible fit with the policy's essential/desirable weights;
- keeps eligibility separate from fit and preserves all audited hard outcomes;
- binds discovery, database, source, schema, policy, projection, duplicate snapshot,
  vacancy description, decision, and evidence-matrix hashes;
- verifies every terminal attempt before deriving duplicate/click-intent quarantine;
- rejects a stale or caller-minted authority document by rebuilding it at session load.

The original discovery document remains immutable. Its
`ranking_candidate_profile: "empty"` values are retained only as historical evidence
and are never consumed as fit authority.

## Focused verification

The focused candidate/session and existing archive/runner/provider/submit-boundary
suites pass together: 106 tests. The adversarial cases include mutated candidate
sources, symlinked archive namespaces, caller-substituted fit/hash values, unresolved
commuter facts relabelled eligible, stale duplicate snapshots, and legacy numeric-fit
reuse.

## Remaining release gate

This slice closes materialization, not the complete production release gate. The
concrete sink-first application preparation factory, authenticated general provider
observation capture, narrow production Gmail reconciler, and exact-clean-HEAD
independent PASS remain mandatory before any consequential submission.
