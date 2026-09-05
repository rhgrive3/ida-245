# Simple issue owner-lane checkpoint — Runtime event byte budget

Status: `CHECKS_PENDING`

This checkpoint records the resumable state for the `codex` owner lane for
UTF-8 runtime event queue accounting.

## Scope and ownership

- Issue: #6176 (UTF-8 maxBytes accounting)
- Source owner: `js/runtime/events.js`
- Regression owner: `tests/phase10/events/issue-6176-runtime-event-byte-budget.test.mjs`
- Shared-board claim: lanes messages #299–#300
- Owner PR: #6518 (https://github.com/rhgrive3/hex-ida/pull/6518)
- Branch: `fix/issues-runtime-events-6176-6179`
- Candidate base: `origin/main` at `6774b1b6f3f2980ee1bef82aaf5ee0f165a0f03b`

## Stages

- [x] Read the shared board and checked open-PR path overlap; #6426 is merged and no active PR owns `js/runtime/events.js`.
- [x] Traced the live normalizer byte-budget path.
- [x] Changed payload preflight and canonical queue accounting to UTF-8 byte length.
- [x] Confirmed #6179 is already fixed by merged PR #6426 and removed it from this lane.
- [x] Added a phase 10 regression for exact Unicode byte boundaries.
- [x] Run focused tests, Phase 10 tests, lint, and compare any unrelated red gate with pristine `origin/main`.
- [x] Create one owner PR for #6176 and record exact-head candidate evidence for PR head `649e5e6c22be4401af1238a4760fab6f602aa400` (candidate merge tree `f939059a0db953a38e32edec25e0df590c2d4220`; board evidence #301).
- [ ] Merge only after exact-head evidence and required checks are green; otherwise record the blocker here and on the board.

## Resume procedure

Fetch `origin/main`, verify the exact candidate base, read the shared board after
#300, then continue from the first unchecked stage. Repository-wide red gates
must be compared with a pristine `origin/main` baseline before being treated as
a lane regression.
