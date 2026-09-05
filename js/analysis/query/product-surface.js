import { classifyFunction, discoverSubsystems } from '../../recognition/classifier.js';
import { STRING_SCAN_BUDGET, StringCollectionBudget } from '../../string-budget.js';

const REPORT_BINDINGS = new WeakMap();
const STRING_STATES = new WeakMap();
const CANONICAL_VERDICTS = new Set(['confirmed','supported','likely','unverified','contradicted','unknown']);

function abortError(signal) {
  if (signal?.reason instanceof Error) return signal.reason;
  const error = new Error('AbortError');
  error.name = 'AbortError';
  return error;
}

function abortIfNeeded(signal) {
  if (signal?.aborted) throw abortError(signal);
}

function pageOf(page = {}) {
  const offset = page.offset ?? 0;
  const limit = page.limit ?? 200;
  return {
    offset: typeof offset === 'number' && Number.isSafeInteger(offset) && offset >= 0 ? offset : 0,
    limit: typeof limit === 'number' && Number.isSafeInteger(limit) && limit > 0 ? Math.min(5000, limit) : 200,
  };
}

function sameSnapshot(left, right) {
  return !!left && !!right && left.snapshotId === right.snapshotId;
}

function queryText(value) {
  return typeof value === 'string' ? value.trim().toLowerCase() : '';
}
function claimIdFilter(value) {
  if (value == null) return null;
  if (typeof value !== 'string' || !value.trim()) throw new TypeError('analysis-product-claim-id-invalid');
  return value.trim();
}
function verdictFilter(values) {
  if (!Array.isArray(values) || !values.length) return null;
  if (values.some((value) => typeof value !== 'string' || !value.trim())) throw new TypeError('analysis-product-verdict-invalid');
  const set = new Set();
  for (const value of values) {
    const norm = value.trim().toLowerCase();
    if (!CANONICAL_VERDICTS.has(norm)) throw new TypeError('analysis-product-verdict-invalid');
    set.add(norm);
  }
  return set;
}
function functionAddress(value) {
  if (typeof value === 'bigint') {
    if (value < 0n) throw new TypeError('analysis-product-function-id-invalid');
    return value;
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) throw new TypeError('analysis-product-function-id-invalid');
    return BigInt(value);
  }
  if (typeof value === 'string') {
    const text = value.trim();
    if (!/^(?:0[xX][0-9a-fA-F]+|[0-9]+)$/.test(text)) throw new TypeError('analysis-product-function-id-invalid');
    return BigInt(text);
  }
  throw new TypeError('analysis-product-function-id-invalid');
}

function canonicalRecognitionConfidence(value) {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 1 ? value : 0;
}

async function assertCurrentSnapshot(app, snapshot, options = {}) {
  abortIfNeeded(options.signal);
  const current = await app.analysisQueries.snapshot(options);
  abortIfNeeded(options.signal);
  if (!sameSnapshot(snapshot, current)) {
    const error = new Error('analysis-product-snapshot-stale');
    error.name = 'AnalysisSnapshotStaleError';
    error.code = 'ANALYSIS_SNAPSHOT_STALE';
    throw error;
  }
}

function queryEnvelope(snapshot, value, completeness, status = {}, page = null) {
  return Object.freeze({
    snapshotId: snapshot.snapshotId,
    analysisEpoch: snapshot.analysisEpoch,
    completeness,
    value,
    status: Object.freeze({ ...status, completeness }),
    page,
  });
}

function stringPriority(region) {
  const section = region?.section || '';
  if (region?.cstrings || /^__(cstring|objc_methname|objc_classname|swift5_reflstr|oslogstring)$/.test(section)) return 0;
  if (/string|objc_method|objc_class|ustring/i.test(section)) return 1;
  return 2;
}

function newStringState(app) {
  const regions = app.store?.get?.('regions') || [];
  const targets = regions.filter((region) => region?.size > 0n &&
    (region.cstrings || /string|cstring|objc_methname|objc_method|objc_classname|objc_class|oslogstring|const|ustring|swift5_reflstr/i.test(region.section || '')))
    .sort((a, b) => stringPriority(a) - stringPriority(b));
  const current = app.store?.get?.('currentRegion') || null;
  if (!targets.length && current?.size > 0n) targets.push(current);
  const budget = new StringCollectionBudget(STRING_SCAN_BUDGET);
  const plan = [];
  const skipped = [];
  for (const region of targets) {
    const bytes = budget.requestBytes(Number(region.size));
    if (bytes <= 0) { skipped.push(region); continue; }
    plan.push({ region, bytes });
    if (bytes < Number(region.size)) skipped.push(region);
  }
  return {
    key: `${Number(app.backend?.gen ?? 0)}:${Number(app.store?.get?.('sliceIndex') ?? -1)}`,
    budget,
    plan,
    skipped,
    cursor: 0,
    rows: [],
    scannedBytes: 0,
    backendIncomplete: false,
    complete: false,
    truncationReason: skipped.length ? 'input-budget' : null,
    inFlight: null,
  };
}

function stringState(app) {
  const key = `${Number(app.backend?.gen ?? 0)}:${Number(app.store?.get?.('sliceIndex') ?? -1)}`;
  let state = STRING_STATES.get(app);
  if (!state || state.key !== key) {
    state = newStringState(app);
    STRING_STATES.set(app, state);
  }
  return state;
}

function waitForShared(entry, signal) {
  abortIfNeeded(signal);
  entry.waiters++;
  if (!signal) return entry.promise.finally(() => { entry.waiters = Math.max(0, entry.waiters - 1); });
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      signal.removeEventListener('abort', onAbort);
      entry.waiters = Math.max(0, entry.waiters - 1);
      fn(value);
    };
    const onAbort = () => {
      if (settled) return;
      entry.waiters = Math.max(0, entry.waiters - 1);
      signal.removeEventListener('abort', onAbort);
      settled = true;
      if (entry.waiters === 0) entry.cancel?.();
      reject(abortError(signal));
    };
    signal.addEventListener('abort', onAbort, { once:true });
    if (signal.aborted) {
      onAbort();
      return;
    }
    entry.promise.then((value) => finish(resolve, value), (error) => finish(reject, error));
  });
}

async function scanNextStringRegion(app, state, options = {}) {
  if (state.complete || state.cursor >= state.plan.length || state.budget.exhausted) {
    state.complete = state.cursor >= state.plan.length && !state.backendIncomplete && !state.truncationReason && !state.budget.truncationReason;
    state.truncationReason ||= state.budget.truncationReason || (state.backendIncomplete ? 'backend-partial' : state.cursor < state.plan.length ? 'collection-budget' : null);
    return;
  }
  if (!state.inFlight) {
    const index = state.cursor;
    const item = state.plan[index];
    const remaining = state.budget.requestLimit();
    if (remaining <= 0) {
      state.truncationReason ||= 'result-budget';
      return;
    }
    const request = app.backend.strings(
      { regionId:item.region.id, min:4, maxBytes:item.bytes, limit:remaining },
      // Only a real function observes progress. A truthy non-function would
      // build a callback that throws TypeError on first progress and fail an
      // otherwise healthy scan, so malformed observers are ignored instead.
      typeof options.onProgress === 'function'
        ? (progress) => options.onProgress({ ...progress, phase:'strings', region:item.region.id })
        : null,
    );
    const entry = { waiters:0, cancel:typeof request?.cancel === 'function' ? () => request.cancel() : null, promise:null };
    entry.promise = Promise.resolve(request).then((result) => {
      state.scannedBytes += Number(result?.scannedBytes || 0);
      if (result?.complete !== true) state.backendIncomplete = true;
      for (const row of result?.results || []) {
        if (!state.budget.accept(row.text)) break;
        state.rows.push({ addr:row.addr, text:String(row.text || ''), normalizedText:String(row.text || '').toLowerCase(), region:item.region });
      }
      if (result?.capped) state.truncationReason ||= result.truncationReason || 'result-budget';
      state.cursor = Math.max(state.cursor, index + 1);
      if (state.cursor >= state.plan.length) state.complete = !state.backendIncomplete && !state.truncationReason && !state.budget.truncationReason;
    }).finally(() => {
      if (state.inFlight === entry) state.inFlight = null;
    });
    state.inFlight = entry;
  }
  await waitForShared(state.inFlight, options.signal);
}

function matchingStrings(state, needle) {
  if (!needle) return state.rows;
  return state.rows.filter((row) => row.normalizedText.includes(needle));
}

export function canonicalClaimVerdict(item) {
  const raw = item?.verdict ?? item?.evidenceVerdict ?? item?.proof?.verdict ?? item?.claim?.verdict ?? null;
  const normalized = typeof raw === 'string' ? raw.trim().toLowerCase() : null;
  return normalized && CANONICAL_VERDICTS.has(normalized) ? normalized : 'unverified';
}

function canonicalClaimId(item, index) {
  const raw = item?.claimId ?? item?.id ?? item?.key;
  if (raw == null) return `claim-${index}`;
  if (typeof raw !== 'string' || !raw.trim()) return null;
  return raw.trim();
}

function canonicalClaimConfidence(value) {
  if (value == null) return null;
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > 1) return undefined;
  return value;
}

function canonicalClaimEvidenceIds(value) {
  if (value == null) return [];
  if (!Array.isArray(value)) return null;
  const ids = [];
  for (const raw of value) {
    if (typeof raw !== 'string' || !raw.trim()) return null;
    ids.push(raw.trim());
  }
  return ids;
}

function claimRows(report, snapshot) {
  const source = report?.findings || report?.results || report?.goals || [];
  if (!Array.isArray(source)) return { rows:[], invalidCount:0 };
  const rows = [];
  let invalidCount = 0;
  for (let index = 0; index < source.length; index++) {
    const item = source[index];
    const address = item?.addr ?? item?.address ?? item?.functionAddr ?? item?.function ?? null;
    const claimId = canonicalClaimId(item, index);
    const confidence = canonicalClaimConfidence(item?.confidence);
    const evidenceIds = canonicalClaimEvidenceIds(item?.evidenceIds);
    if (claimId == null || confidence === undefined || evidenceIds == null) {
      invalidCount++;
      continue;
    }
    rows.push({
      claimId,
      title:String(item?.title || item?.label || item?.goal?.text || item?.goal || 'Finding'),
      address,
      verdict:canonicalClaimVerdict(item),
      confidence,
      evidenceIds,
      contradictions:Array.isArray(item?.contradictions) ? item.contradictions : [],
      assumptions:Array.isArray(item?.assumptions) ? item.assumptions : [],
      summary:item?.summary || item?.description || item?.detail || null,
      snapshotId:snapshot.snapshotId,
      source:item,
    });
  }
  return { rows, invalidCount };
}

function findRecognitionRecord(app, address) {
  const records = app?.recognition?.records || [];
  return records.find((row) => {
    // Recognition addresses use the same typed contract as query addresses.
    // A bare BigInt() would stringify Array/object identities (e.g.
    // BigInt(['4096']) === 4096n) and misjoin a malformed record to a real
    // function, so anything outside the canonical form never matches.
    let recordAddress = null;
    try { recordAddress = functionAddress(row.address); } catch { return false; }
    return recordAddress === address;
  }) || null;
}

export function buildClassificationInput(app, address, result) {
  const owner = app.ownerOf?.(address);
  const model = result?.model || {};
  const semantic = result?.semanticFacts || result?.semantic || {};
  const fn = app.symbols?.functionAt?.(address);
  const instructions = (model.instructions || []).map((item) => ({ mnemonic:item.mnemonic || item.mn || '', operands:item.operands || item.ops || '' }));
  const blocks = model.blocks || [];
  const calls = (semantic.calls || []).map((call) => call?.name).filter(Boolean);
  const writes = (semantic.stores || []).map((store) => store?.location?.key || store?.location?.text || store?.lhsText).filter(Boolean);
  const operations = [];
  for (const store of semantic.stores || []) {
    const op = store?.readModifyWrite?.kind || store?.expression?.op || store?.expression?.name;
    if (op) operations.push(op);
  }
  return {
    address,
    name:app.symbols?.nameAt?.(address) || null,
    architecture:String(app.store?.get?.('architecture') || app.store?.get?.('capability')?.architecture || 'unknown').toLowerCase(),
    size:fn?.end != null && fn.end > fn.start ? Number(fn.end - fn.start) : 0,
    instructions,
    cfg:{ blocks:blocks.length, edges:blocks.reduce((sum, block) => sum + (block.succ?.length || block.successors?.length || 0), 0), exits:blocks.filter((block) => !(block.succ?.length || block.successors?.length)).length, calls:calls.length },
    semantic:{ writes, calls, operations, reads:[], thresholds:[] },
    calls,
    objcClass:owner?.className || null,
    objcSelector:owner?.sel || null,
  };
}

export function createProductSurfaceQueries(app) {
  if (!app?.analysisQueries?.snapshot) throw new TypeError('analysis-query-api-required');
  return Object.freeze({
    snapshot:(options = {}) => app.analysisQueries.snapshot(options),

    async strings(snapshot, query = {}, page = {}, options = {}) {
      await assertCurrentSnapshot(app, snapshot, options);
      const state = stringState(app);
      const needle = queryText(query.text ?? query.query ?? '');
      const { offset, limit } = pageOf(page);
      while (true) {
        abortIfNeeded(options.signal);
        const matches = matchingStrings(state, needle);
        if (matches.length >= offset + limit || state.complete || state.budget.exhausted || state.cursor >= state.plan.length) break;
        await scanNextStringRegion(app, state, options);
      }
      const matches = matchingStrings(state, needle);
      const value = matches.slice(offset, offset + limit).map(({ normalizedText, ...row }) => row);
      const globallyComplete = state.complete === true;
      const next = offset + value.length < matches.length || (!globallyComplete && value.length === limit) ? offset + value.length : null;
      await assertCurrentSnapshot(app, snapshot, options);
      return queryEnvelope(snapshot, value, globallyComplete ? 'complete' : 'partial', {
        reason:globallyComplete ? null : state.truncationReason || state.budget.truncationReason || 'string-artifact-incomplete',
        producer:'canonical-product-string-artifact/v1',
        scannedRegions:state.cursor,
        totalRegions:state.plan.length + state.skipped.length,
        scannedBytes:state.scannedBytes,
        unscannedRegions:state.plan.slice(state.cursor).map((item) => item.region.id).concat(state.skipped.map((region) => region.id)),
      }, { offset, limit, returned:value.length, total:globallyComplete ? matches.length : null, next });
    },

    async claims(snapshot, query = {}, page = {}, options = {}) {
      await assertCurrentSnapshot(app, snapshot, options);
      const report = app?.autoReport?.report ?? null;
      if (!report || typeof report !== 'object') return queryEnvelope(snapshot, [], 'complete', { producer:'canonical-claim-adapter/v1' }, { offset:0, limit:pageOf(page).limit, returned:0, total:0, next:null });
      // Reports generated by InvestigationService carry their origin snapshot
      // identity. A never-bound stale report must not be first-bound to a
      // newer snapshot and re-attributed as current claims. The WeakMap below
      // remains only a fallback for legacy reports without any identity.
      const reportSnapshotId = typeof report.snapshotId === 'string' && report.snapshotId ? report.snapshotId : null;
      const autoSnapshotId = typeof app?.autoReport?.snapshotId === 'string' && app.autoReport.snapshotId ? app.autoReport.snapshotId : null;
      if ((reportSnapshotId != null && reportSnapshotId !== snapshot.snapshotId) ||
        (autoSnapshotId != null && autoSnapshotId !== snapshot.snapshotId)) {
        return queryEnvelope(snapshot, [], 'unsupported', { reason:'claim-report-snapshot-mismatch', producer:'canonical-claim-adapter/v1' }, null);
      }
      const bound = REPORT_BINDINGS.get(report);
      if (bound && bound !== snapshot.snapshotId) {
        return queryEnvelope(snapshot, [], 'unsupported', { reason:'claim-report-snapshot-mismatch', producer:'canonical-claim-adapter/v1' }, null);
      }
      if (!bound) REPORT_BINDINGS.set(report, snapshot.snapshotId);
      const projected = claimRows(report, snapshot);
      let rows = projected.rows;
      const claimId = claimIdFilter(query.claimId);
      if (claimId != null) rows = rows.filter((row) => row.claimId === claimId);
      const accepted = verdictFilter(query.verdict);
      if (accepted) rows = rows.filter((row) => accepted.has(row.verdict));
      const { offset, limit } = pageOf(page);
      const value = rows.slice(offset, offset + limit);
      const sourceInvalid = projected.invalidCount > 0;
      const reportIncomplete = report?.truncated === true;
      const incomplete = sourceInvalid || reportIncomplete;
      await assertCurrentSnapshot(app, snapshot, options);
      return queryEnvelope(snapshot, value, incomplete ? 'partial' : 'complete', {
        reason:reportIncomplete ? 'auto-report-incomplete' : sourceInvalid ? 'claim-source-invalid' : null,
        producer:'canonical-claim-adapter/v1',
      }, { offset, limit, returned:value.length, total:incomplete ? null : rows.length, next:offset + value.length < rows.length ? offset + value.length : null });
    },

    async classification(snapshot, functionId, options = {}) {
      await assertCurrentSnapshot(app, snapshot, options);
      const address = functionAddress(functionId);
      let base = findRecognitionRecord(app, address);
      if (!base && typeof app.ensureRecognition === 'function') {
        const producer = Promise.resolve(app.ensureRecognition({ maxFunctions:350000 }));
        await waitForShared({ promise:producer, waiters:0, cancel:null }, options.signal);
        base = findRecognitionRecord(app, address);
      }
      abortIfNeeded(options.signal);
      let local = null;
      try { local = await app.analyzeFunctionAt(address, { signal:options.signal }); } catch (error) { if (options.signal?.aborted) throw error; }
      const baseResult = base ? {
        classification:base.classification || 'UNKNOWN',
        confidence:canonicalRecognitionConfidence(base.confidence),
        evidence:Array.isArray(base.evidence) ? base.evidence.slice() : [],
        knowledgeSourceId:base.knowledgeSourceId || null,
      } : null;
      if (!local?.model) {
        const value = {
          classification:baseResult?.classification || 'UNKNOWN',
          confidence:baseResult?.confidence || 0,
          evidence:baseResult?.evidence || [],
          base:baseResult,
          refinement:null,
          subsystems:[],
          refinementReason:'semantic-evidence-unavailable',
        };
        await assertCurrentSnapshot(app, snapshot, options);
        return queryEnvelope(snapshot, value, 'partial', { reason:'semantic-evidence-unavailable', producer:'function-classification-artifact/v1' });
      }
      const input = buildClassificationInput(app, address, local);
      const signature = base?.knowledge?.classification ? {
        classification:base.knowledge.classification,
        confidence:base.knowledgeConfidence || base.knowledge.confidence || 0,
        exact:base.knowledge.exact === true,
        identity:base.knowledge.identity || null,
        name:base.knowledge.names?.[0] || null,
      } : null;
      const refined = classifyFunction(input, { notKnownVendor:true, ...(signature ? { signature } : {}) });
      const subsystems = discoverSubsystems(input);
      const value = {
        classification:refined.classification,
        confidence:refined.confidence,
        evidence:refined.evidence,
        base:baseResult,
        refinement:{ classification:refined.classification, confidence:refined.confidence, evidence:refined.evidence, from:baseResult?.classification || null },
        subsystems,
        refinementReason:baseResult && baseResult.classification !== refined.classification ? 'semantic-evidence-refined-classification' : 'semantic-evidence-confirmed-classification',
        facts:{ instructions:local.instructions || local.model?.instructions?.length || 0, blocks:local.model?.blocks?.length || 0, address },
      };
      await assertCurrentSnapshot(app, snapshot, options);
      return queryEnvelope(snapshot, value, local?.completeness?.complete === false || local?.truncated ? 'partial' : 'complete', {
        reason:local?.truncated ? 'function-analysis-truncated' : local?.completeness?.complete === false ? local.completeness.reason || 'function-analysis-partial' : null,
        producer:'function-classification-artifact/v1',
      });
    },
  });
}
