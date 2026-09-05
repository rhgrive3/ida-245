/**
 * Phase 8 analysis state and pass transactions.
 *
 * A Phase 8 pass never writes to shared state. It reads an authoritative
 * analysis state, stages what it wants to produce, and returns. This module is
 * the only thing that commits, and it commits everything or nothing.
 *
 * That is not defensive style. The existing `PassManager` merges each pass's
 * return value into shared state as the pass returns, so a pass that is
 * cancelled or throws part way through leaves its partial work behind as
 * authoritative fact. With fixed-point optimizers that is the shape of a bug
 * nobody can reproduce: the output depends on when the deadline happened to
 * fire.
 *
 * Invalidation is fail-closed. A pass that changed something invalidates every
 * analysis it did not explicitly promise to preserve. Declaring `invalidates` is
 * still required — it documents intent and is checked — but correctness does not
 * depend on the declaration being complete, because the one thing an author
 * reliably forgets is the analysis they never thought about.
 */

import { stableDigest } from '../../core/identity/index.js';

import { ANALYSIS_KEYS, PHASE8_CONTRACT_VERSION } from './contract.js';

function fail(code) { throw new TypeError(code); }

const ANALYSIS_SET = new Set(ANALYSIS_KEYS);

/**
 * The authoritative analysis state.
 *
 * Every entry carries a version. A version is what lets a consumer say "the fact
 * I cached was derived from ssa@3 and ssa is now at 4", which is the difference
 * between reuse and stale reuse.
 */
export function createAnalysisState(initial = {}, initialVersions = null) {
  const values = new Map();
  const versions = new Map();
  for (const key of ANALYSIS_KEYS) {
    const present = Object.hasOwn(initial, key);
    const requestedVersion = initialVersions?.[key];
    const version = Number.isInteger(requestedVersion) && requestedVersion >= 0
      ? requestedVersion : (present ? 1 : 0);
    values.set(key, present ? initial[key] : null);
    versions.set(key, version);
  }

  const api = {
    get(key) {
      if (!ANALYSIS_SET.has(key)) fail(`phase8-analysis-unknown-key:${key}`);
      return values.get(key);
    },
    version(key) {
      if (!ANALYSIS_SET.has(key)) fail(`phase8-analysis-unknown-key:${key}`);
      return versions.get(key);
    },
    /** A version-only view. Comparing two snapshots shows exactly what moved. */
    snapshot() {
      return Object.freeze(Object.fromEntries(ANALYSIS_KEYS.map((key) => [key, versions.get(key)])));
    },
    /** Present analyses, for a consumer deciding what it may rely on. */
    available() {
      return Object.freeze(ANALYSIS_KEYS.filter((key) => versions.get(key) > 0));
    },
    // Deliberately not exported on the public surface: only commitTransaction
    // reaches these, so there is no second way to mutate authoritative state.
    __write(key, value) {
      values.set(key, value);
      versions.set(key, versions.get(key) + 1);
    },
    __drop(key) {
      if (versions.get(key) === 0) return false;
      values.set(key, null);
      versions.set(key, versions.get(key) + 1);
      return true;
    },
  };
  return api;
}

/** Clone an authoritative state without resetting the evidence versions. */
export function forkAnalysisState(source) {
  if (source == null || typeof source.snapshot !== 'function' || typeof source.get !== 'function') {
    fail('phase8-analysis-state-required');
  }
  const versions = source.snapshot();
  const initial = {};
  for (const key of ANALYSIS_KEYS) if (versions[key] > 0) initial[key] = source.get(key);
  return createAnalysisState(initial, versions);
}

/**
 * Commit a private vertical state while preserving the exact version delta.
 * The snapshot guard makes a concurrent writer a failed publication rather
 * than silently overwriting newer authoritative evidence.
 */
export function commitAnalysisState(target, working, before) {
  if (target == null || working == null || before == null) return false;
  const current = target.snapshot();
  if (ANALYSIS_KEYS.some((key) => current[key] !== before[key])) return false;
  for (const key of ANALYSIS_KEYS) {
    const delta = working.version(key) - before[key];
    if (delta < 0) return false;
    if (delta === 0) continue;
    const finalValue = working.get(key);
    for (let step = 0; step < delta; step += 1) {
      const last = step === delta - 1;
      if (last && finalValue == null && target.version(key) > 0) target.__drop(key);
      else target.__write(key, last ? finalValue : null);
    }
  }
  return true;
}

/**
 * The write surface a pass sees.
 *
 * Writes go into a private map. The pass cannot reach authoritative state even
 * by accident, so "did this pass mutate something it should not have" is not a
 * question that needs asking.
 */
function createStagingArea(descriptor) {
  const staged = new Map();
  return {
    area: {
      stage(key, value) {
        if (!ANALYSIS_SET.has(key)) fail(`phase8-analysis-unknown-key:${key}`);
        // A pass may only stage what it declared it produces. An undeclared
        // write is an undeclared dependency for everything downstream.
        if (!descriptor.produces.includes(key)) fail(`phase8-pass-undeclared-production:${descriptor.id}:${key}`);
        if (value == null) fail(`phase8-pass-produced-analysis-value-required:${key}`);
        staged.set(key, value);
      },
      staged: () => Object.freeze([...staged.keys()].sort()),
    },
    take: () => staged,
  };
}

function aborted(budget) {
  try { return typeof budget?.shouldAbort === 'function' && budget.shouldAbort() === true; }
  catch { return true; }
}

/**
 * Computes what a committed pass invalidates.
 *
 * `preserves` is the promise; everything else the pass could have touched is
 * assumed broken. `produces` is written rather than dropped, so a pass that
 * recomputes an analysis does not invalidate the thing it just produced.
 */
export function invalidationFor(descriptor, { changed }) {
  if (!changed) return Object.freeze([]);
  const kept = new Set([...descriptor.preserves, ...descriptor.produces]);
  return Object.freeze(ANALYSIS_KEYS.filter((key) => !kept.has(key)).sort());
}

/**
 * Runs one pass against the state and commits atomically on success.
 *
 * Returns `{ committed, result, invalidated, staged, stopReason }`. When
 * `committed` is false nothing was written and no version moved: the state is
 * exactly what it was before the call.
 */
export function runPassTransaction(state, pass, context = {}, budget = {}) {
  const descriptor = pass.descriptor;
  if (!descriptor || descriptor.contractVersion !== PHASE8_CONTRACT_VERSION) fail('phase8-transaction-descriptor-required');

  // A pass may not run at all if a fact it consumes is absent. Running it anyway
  // and letting it improvise is how a decompiler grows a private heuristic in
  // place of a missing upstream fact.
  const missing = descriptor.consumes.filter((key) => state.version(key) === 0);
  if (missing.length) {
    return Object.freeze({
      committed: false, result: null, invalidated: Object.freeze([]), staged: Object.freeze([]),
      stopReason: `missing-input:${missing.join(',')}`,
    });
  }
  if (aborted(budget)) {
    return Object.freeze({ committed: false, result: null, invalidated: Object.freeze([]), staged: Object.freeze([]), stopReason: 'cancelled-before-start' });
  }

  const { area, take } = createStagingArea(descriptor);
  let result;
  try {
    result = pass.run(context, budget, area);
  } catch (error) {
    return Object.freeze({
      committed: false, result: null, invalidated: Object.freeze([]), staged: Object.freeze([]),
      stopReason: `failed:${error?.message ?? String(error)}`,
    });
  }

  // Checked after the pass as well as before it. A pass that outlived the
  // deadline must not have its work committed as if it had finished in time.
  if (aborted(budget)) {
    return Object.freeze({ committed: false, result: null, invalidated: Object.freeze([]), staged: Object.freeze([]), stopReason: 'cancelled-mid-pass' });
  }

  const stagedWrites = take();
  const refuse = (stopReason) => Object.freeze({
    committed: false, result: null, invalidated: Object.freeze([]), staged: Object.freeze([]), stopReason,
  });
  // A result may only exercise the descriptor authority of the pass that was
  // actually invoked. Otherwise mutation/invalidation uses one descriptor while
  // provenance and replay identity name another pass.
  if (result.contractVersion !== descriptor.contractVersion
      || result.passId !== descriptor.id
      || result.passVersion !== descriptor.version
      || result.stage !== descriptor.stage) {
    return refuse(`result-descriptor-mismatch:${descriptor.id}`);
  }
  // A contract violation is refused the same way a cancellation is: nothing
  // commits and the caller gets a reason. Throwing here instead would turn a
  // withheld ledger into an uncaught exception at the vertical, which is a
  // worse failure mode for the same fault.
  if (!result.changed && stagedWrites.size > 0) return refuse(`unchanged-with-staged-writes:${descriptor.id}`);
  // What the pass staged and what it declared it produced must agree, or the
  // ledger describes a different commit than the one that happened.
  const stagedKeys = [...stagedWrites.keys()].sort().join(',');
  const declaredKeys = [...result.produced].sort().join(',');
  if (stagedKeys !== declaredKeys) return refuse(`staged-production-mismatch:${descriptor.id}:${stagedKeys || 'none'}!=${declaredKeys || 'none'}`);

  // A partial result may be useful when there is no prior artifact, but it can
  // never replace a complete authoritative result.  The vertical runner uses
  // a private state as well, so this guard also protects direct pass callers.
  if (result.completeness !== 'complete') {
    const completeKey = result.produced.find((key) => state.get(key)?.completeness === 'complete');
    if (completeKey != null) return refuse(`incomplete-result-would-overwrite-complete:${descriptor.id}:${completeKey}`);
  }

  // Last check immediately before the only mutation point.  A cancellation
  // that arrives while validating the staged result must not become a commit.
  if (aborted(budget)) return refuse('cancelled-before-commit');

  // Commit. Nothing above this line touched authoritative state.
  const invalidated = invalidationFor(descriptor, { changed: result.changed });
  const actuallyInvalidated = [];
  for (const key of invalidated) if (state.__drop(key)) actuallyInvalidated.push(key);
  for (const [key, value] of stagedWrites) state.__write(key, value);

  return Object.freeze({
    committed: true,
    result,
    invalidated: Object.freeze(actuallyInvalidated),
    staged: Object.freeze([...stagedWrites.keys()].sort()),
    stopReason: null,
  });
}

/**
 * Replay identity for a transaction outcome.
 *
 * Deliberately excludes timings. Two runs of the same pass over the same input
 * must agree on what changed, what was invalidated and why — a differing
 * elapsed time is not a differing result.
 */
export function transactionDigest(outcome) {
  return stableDigest({
    committed: outcome.committed,
    stopReason: outcome.stopReason,
    invalidated: outcome.invalidated,
    staged: outcome.staged,
    result: outcome.result == null ? null : {
      passId: outcome.result.passId,
      passVersion: outcome.result.passVersion,
      status: outcome.result.status,
      changed: outcome.result.changed,
      completeness: outcome.result.completeness,
      transforms: outcome.result.transforms,
      invalidated: outcome.result.invalidated,
      stopReason: outcome.result.stopReason,
    },
  });
}

/**
 * Seeds the analysis state from the canonical facts the decompiler already
 * holds.
 *
 * Phase 8 does not recompute CFG, dominance, loops, SSA or origins. Those are
 * upstream truth and they are already attached to the IR the pipeline consumes;
 * seeding from them is what keeps Phase 8 from growing a second copy of any of
 * them. An absent fact stays absent — version 0, unavailable — rather than being
 * approximated, so a pass that needs it refuses to run instead of improvising.
 */
export function seedAnalysisState(ir, upstream = {}) {
  if (!ir || typeof ir !== 'object') return createAnalysisState({});
  const seed = {};
  // Recovered types arrive from Phase 7 alongside the IR rather than on it.
  // Seeding them here is the same rule as everything else in this function: the
  // fact is upstream truth, and a Phase 8 pass that needs it must read it rather
  // than grow a second type engine.
  if (upstream.types != null) seed.types = Object.freeze({ recovered: upstream.types });
  if (Array.isArray(ir.blocks) && ir.blocks.length > 0) {
    seed.cfg = Object.freeze({ blocks: ir.blocks, entry: ir.entry ?? null, backEdges: ir.backEdges ?? null });
  }
  if (ir.idom != null || ir.dominators != null) {
    // Post-dominance travels with dominance: both are views of the same
    // canonical control-flow analysis, and a consumer that has one and not the
    // other ends up deriving the missing half itself.
    seed.dominators = Object.freeze({
      idom: ir.idom ?? null,
      dominators: ir.dominators ?? null,
      ipdom: ir.ipdom ?? ir.immediatePostDominators ?? null,
      postDominators: ir.postDominators ?? null,
    });
  }
  if (ir.loops != null) {
    seed.loops = Object.freeze({ loops: ir.loops, backEdges: ir.backEdges ?? null });
  }
  if (Array.isArray(ir.values) && ir.values.length > 0) {
    seed.ssa = Object.freeze({ values: ir.values, defUse: ir.defUse ?? null });
  }
  // Origins are what every transform record has to point back at. If the IR
  // carries no origin at all, Phase 8 must not claim provenance it cannot show.
  if (ir.origin != null || (Array.isArray(ir.values) && ir.values.some((value) => value?.origin != null))) {
    seed.origins = Object.freeze({ functionOrigin: ir.origin ?? null, values: ir.values ?? [] });
  }
  return createAnalysisState(seed);
}
