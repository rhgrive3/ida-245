# Simple issue owner-lane checkpoint — Capability parity IDs

Status: `PR_OPEN_CANDIDATE_VERIFIED`

This checkpoint records the resumable state for the `codex` owner lane for
capability ID identity alignment between parity auditing and runtime lookup.

## Scope and ownership

- Issue: #6170 (non-string capability IDs)
- Source owners: `js/ai/capabilities/parity.js`, `js/ai/capabilities/catalog.js`
- Regression owner: `tests/phase12/integration/issue-6170-capability-parity-ids.test.mjs`
- Shared-board claim: lanes message #304
- Branch: `fix/issues-capability-parity-ids-6170`
- Candidate base: `origin/main` at `6774b1b6f3f2980ee1bef82aaf5ee0f165a0f03b`
- PR: #6521 — https://github.com/rhgrive3/hex-ida/pull/6521

## Stages

- [x] Read the shared board and checked open-PR path overlap; no active PR owns parity.js or catalog.js.
- [x] Traced audit, catalog construction, and lookup callers.
- [x] Made parity IDs strict non-empty strings with canonical trimming.
- [x] Made catalog construction and lookup use the same string-only identity contract.
- [x] Added Phase 12 regressions for malformed IDs, semantic duplicates, trimmed IDs, and strict lookup.
- [x] Run focused tests, Phase 12 tests, lint, and compare any unrelated red gate with pristine `origin/main`.
- [x] Create one owner PR for #6170 and record exact-head candidate evidence.
- [ ] Merge only after exact-head evidence and required checks are green; otherwise record the blocker here and on the board.

## Exact-head candidate evidence

- Candidate head: `909890e07b1310b924068c3270c3af9b70eb8c01`
- Candidate merge tree: `76ef1a6a0cb72e08b638dc70530365bf099e08c1`
- Verification commit: `2da3b8bad502fcdc055408880829a774bfa9a909`
- Candidate changed-file union: this checkpoint, `js/ai/capabilities/catalog.js`,
  `js/ai/capabilities/parity.js`, and the #6170 regression test.
- Dedicated regression, agent capability plane, capability tool contract, and
  lint: passed.
- Phase 12 candidate: 26 passed, 7 failed. Pristine `origin/main`: 25 passed,
  7 failed; the seven failures are the same pre-existing foundation/import
  failures, while the #6170 regression passes in the candidate.

## Resume procedure

Fetch `origin/main`, verify the exact candidate base, read the shared board after
#304, then continue from the first unchecked stage. Repository-wide red gates
must be compared with a pristine `origin/main` baseline before being treated as
a lane regression.
