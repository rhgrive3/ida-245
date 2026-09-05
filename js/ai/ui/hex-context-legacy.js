/*
 * app -> AI core local context.
 *
 * The AI core (js/ai/*) is written against a plain object of capabilities; the
 * Hex app is a class with workers, caches and BigInt regions. This adapter is
 * the seam between them and lives on the UI side on purpose: the core must not
 * learn about `app`, and the app must not learn about the core.
 *
 * Everything here is read-only. Mutations (rename, comment) go through the
 * proposal path in interaction/proposals.js, never through a tool.
 */
import { analyzeFunctionCached, supportsArm64SemanticAnalysis } from '../../analyze.js';
import { decompile, decompiledText } from '../../decompile.js';
import { runtimeEvidenceForApp, runtimePlatformForApp, verifyAppHypothesis } from '../../runtime/app-runtime.js';
import { functionNameOf, selectionOf } from './workbench.js';
import { currentFunctionAddr } from '../../tools.js';
import { resolveObjcDispatch } from '../../objc.js';

const MAX_SELECTION_ROWS = 80;

function toBigInt(value) {
  if (value == null) return null;
  if (typeof value === 'bigint') return value;
  try { return BigInt(typeof value === 'string' && /^0x/i.test(value) ? value : String(value)); } catch { return null; }
}

function nonNegativeOffset(value) {
  if (value == null) return 0;
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : 0;
}

function fixedRows(app) {
  return !!app.store.get('canDisassemble') && Number(app.store.get('instructionAlignment') || app.store.get('capability')?.instructionAlignment || 0) > 0;
}
function instructionBytes(app) {
  return Math.max(1, Number(app.store.get('instructionAlignment') || app.store.get('capability')?.instructionAlignment || 4));
}
function containsAddress(region, addr) {
  try { return !!region && region.size > 0n && addr >= region.vmAddr && addr < region.vmAddr + region.size; } catch { return false; }
}
function regionForAddress(app, address) {
  const addr = toBigInt(address);
  if (addr == null) return null;
  let current = null;
  try { current = app.codeRegion?.() || app.store.get('currentRegion'); } catch { current = app.store.get('currentRegion'); }
  if (containsAddress(current, addr)) return current;
  const matches = (app.store.get('regions') || []).filter((region) => containsAddress(region, addr));
  return matches.find((region) => region.exec === true) || matches.find((region) => region.exec !== false) || matches[0] || null;
}

/** Legacy/headless compatibility oracle. First-party product AI uses hex-context.js. */
export async function analyzeModelAt(app, address, end = null, options = {}) {
  const addr = toBigInt(address);
  if (addr == null) return null;
  const architecture = app.store.get('architecture') || app.store.get('capability')?.architecture || null;
  if (!supportsArm64SemanticAnalysis(architecture)) return null;
  const region = regionForAddress(app, addr);
  if (!region || !app.store.get('canDisassemble')) return null;
  const sym = app.symbols;
  const fn = sym && sym.functionCount ? sym.functionAt(addr) : null;
  const start = fn ? fn.start : addr;
  if (!containsAddress(region, start)) return null;
  const step = BigInt(instructionBytes(app));
  if (step !== 4n || (start - region.vmAddr) % step !== 0n) return null;
  const startRow = Number((start - region.vmAddr) / step);
  const totalRows = Number(region.size / step);
  const regionEnd = region.vmAddr + region.size;
  const provenEnd = fn?.end == null ? null : toBigInt(fn.end);
  const requestedEnd = toBigInt(end);
  let boundedEnd = provenEnd;
  if (requestedEnd != null) boundedEnd = boundedEnd == null ? requestedEnd : (requestedEnd < boundedEnd ? requestedEnd : boundedEnd);
  if (boundedEnd == null) boundedEnd = start + 2048n * step;
  if (boundedEnd > regionEnd) boundedEnd = regionEnd;
  if (boundedEnd <= start) return null;
  const endRow = Math.min(totalRows - 1, Number((boundedEnd - region.vmAddr + step - 1n) / step) - 1);
  if (endRow < startRow) return null;
  const rawMax = Number(options?.maxInstructions);
  if (Number.isFinite(rawMax) && Math.floor(rawMax) <= 0) return null;
  const maxRows = Number.isFinite(rawMax) ? Math.max(1, Math.floor(rawMax)) : undefined;
  const coversProvenEnd = provenEnd != null && provenEnd <= regionEnd && boundedEnd >= provenEnd;
  try {
    const res = await analyzeFunctionCached(app.backend, region, startRow, endRow, sym, null, {
      maxRows,
      signal: options?.signal || null,
    });
    const model = res?.model;
    if (!model) return null;
    const incomplete = !coversProvenEnd || res.truncated === true || model.truncated === true;
    return incomplete && model.truncated !== true ? { ...model, truncated: true } : model;
  } catch (error) {
    if (options?.signal?.aborted || error?.name === 'AbortError' || error?.code === 'ABORT_ERR') throw error;
    return null;
  }
}

function selectionContext(app) {
  const viewer = app.viewer;
  const selection = selectionOf(app);
  if (!selection || !viewer) return null;
  const rows = [];
  if (selection.kind === 'range') {
    const range = viewer.selectionRange();
    const end = Math.min(range.end, range.start + MAX_SELECTION_ROWS - 1);
    for (let row = range.start; row <= end; row++) {
      const data = viewer.rowData(row);
      if (data && data.address != null) rows.push({ address: data.address, mnemonic: data.mnemonic, operands: data.operands });
    }
  } else if (selection.row != null) {
    const data = viewer.rowData(selection.row);
    if (data && data.address != null) rows.push({ address: data.address, mnemonic: data.mnemonic, operands: data.operands });
  }
  if (!rows.length) return null;
  return { start: rows[0].address, end: rows[rows.length - 1].address, instructions: rows };
}

export function createHexAIContext(app) {
  const nameOf = (addr) => functionNameOf(app, addr);
  const context = {
    get binaryId() {
      const info = app.store.get('fileInfo');
      return info ? info.name + ':' + String(app.store.get('sliceIndex')) : null;
    },
    get symbols() { return app.symbols; },
    get program() { return app.program; },
    get knowledge() { return app.knowledge || null; },
    get functions() { return (app.recognition?.records || []).map((item)=>item.fingerprint).filter(Boolean).slice(0,5000); },
    get strings() { return app.stringIndex || []; },
    get candidateFunctions() {
      const ranked=app.recognition?.records;
      if (Array.isArray(ranked) && ranked.length) return ranked.slice(0,5000).map((item)=>item.address);
      const addr = safeCurrentFunction(app);
      return addr == null ? [] : [addr];
    },
    get currentAddress() {
      const addr = safeCurrentFunction(app);
      return addr == null ? null : addr;
    },
    get activeFunction() {
      const addr = safeCurrentFunction(app);
      if (addr == null) return null;
      return { address: addr, name: nameOf(addr) };
    },
    get selection() { return selectionContext(app); },
    get project() {
      return app.workspace?.project || app.activeProject || {
        binary:null,user:{names:app.notes?app.notes.nameEntries().slice(0,400):[]},navigation:{lastQuery:app.lastGoal?.text||null},
      };
    },
    get binaryDiff() { return app.getBinaryDiff?.() || null; },
    getBinaryDiff: () => app.getBinaryDiff?.() || null,
    functionName: nameOf,
    analyze: (address, end, options) => analyzeModelAt(app, address, end, options),
    async searchStrings(query, options = {}) {
      const limit = Math.max(1, Math.min(200, Number(options.limit) || 50));
      const offset = nonNegativeOffset(options.offset);
      const rows = await app.ensureStrings();
      const q = String(query || '').toLowerCase();
      const out = [];
      let matches = 0;
      for (const row of rows || []) {
        if (q && !String(row.text || '').toLowerCase().includes(q)) continue;
        matches++;
        if (matches <= offset) continue;
        out.push({ text: row.text, stringAddress: row.addr });
        if (out.length >= limit) break;
      }
      return out;
    },
    async searchFunctions(query, options = {}) {
      const limit = Math.max(1, Math.min(200, Number(options.limit) || 40));
      const offset = nonNegativeOffset(options.offset);
      const q = String(query || '').toLowerCase();
      try { await app.ensureRecognition?.({maxFunctions:350000,knowledgeLimit:512}); } catch {}
      const ranked=app.recognition?.records || [];
      if(ranked.length){
        const out=[]; let matches=0;
        for(const item of ranked){
          const name=String(item.name||item.originalName||'');
          const cls=String(item.classification||'');
          const knowledge=(item.knowledge?.names||[]).concat(item.knowledge?.roles||[]).join(' ');
          if(q && !(`${name} ${cls} ${knowledge}`.toLowerCase().includes(q)))continue;
          matches++;
          if(matches<=offset)continue;
          if(out.length<limit)out.push({addr:item.address,name:name||null,score:item.score||0,classification:item.classification,confidence:item.confidence,knowledge:item.knowledge||null});
        }
        const pageEnd=offset+out.length;
        out.complete=app.recognition.complete===true && pageEnd>=matches;
        out.scannedCount=app.recognition.scannedCount;out.total=app.recognition.total;out.matchCount=matches;
        out.truncationReason=app.recognition.complete!==true?(app.recognition.truncationReason||'recognition-incomplete'):pageEnd<matches?'result-limit':null;
        out.coverage=app.recognition.total?app.recognition.scannedCount/app.recognition.total:1;
        return out;
      }
      const sym = app.symbols;
      if (!sym || !Array.isArray(sym.names)) return [];
      const maxScan=Math.min(sym.names.length,1_000_000), out=[]; let matches=0;
      for (let i = 0; i < maxScan; i++) {
        const name = String(sym.names[i] || '');
        if (q && !name.toLowerCase().includes(q)) continue;
        matches++;
        if(matches<=offset)continue;
        if(out.length<limit) out.push({ addr: sym.addrs[i], name });
      }
      const pageEnd=offset+out.length;
      out.complete=maxScan===sym.names.length && pageEnd>=matches; out.scannedCount=maxScan;out.total=sym.names.length;out.matchCount=matches;
      out.truncationReason=maxScan<sym.names.length?'scan-budget':pageEnd<matches?'result-limit':null;out.coverage=sym.names.length?maxScan/sym.names.length:1;
      return out;
    },
    async decompile(address) {
      if (!fixedRows(app)) return null;
      try { await app.ensureObjc?.(); } catch {}
      const model = await analyzeModelAt(app, address);
      if (!model) return null;
      return decompiledText(pseudocode(app, model, toBigInt(address), nameOf));
    },
    async resolveObjcDispatch(receiverClass, selector, kind = 'instance') {
      try { await app.ensureObjc?.(); } catch {}
      const index = app.objcRuntime || app.objcModel?.runtimeIndex || null;
      if (!index) return { resolved: null, reason: 'objc-runtime-unavailable', candidates: [], requirements: [], confidence: 0 };
      const result = resolveObjcDispatch(index, {
        receiverType: String(receiverClass || ''), selector: String(selector || ''), classMethod: kind === 'class',
      });
      return { ...result, candidates: (result.candidates || []).slice(0, 32), requirements: (result.requirements || []).slice(0, 32) };
    },
    async resolveSwiftDispatch(call = {}) {
      try { await app.ensureSwift?.(); } catch {}
      const result=app.resolveSwiftCall?.(call) || {resolved:null,candidates:[],confidence:0,reason:'swift-runtime-unavailable'};
      return { ...result, candidates:(result?.candidates||[]).slice(0,32), requirements:(result?.requirements||[]).slice(0,32), complete:result?.complete===true && app.swiftModel?.complete===true };
    },
    pseudocodeFor(address, model) {
      if (!model || !fixedRows(app)) return null;
      try { return decompiledText(pseudocode(app, model, toBigInt(address), nameOf)); } catch { return null; }
    },
    addressExists(address) {
      const addr = toBigInt(address);
      if (addr == null) return false;
      for (const region of app.store.get('regions') || []) if (containsAddress(region, addr)) return true;
      return false;
    },
    runtime: {
      getObservations({ functionAddress, limit = 100 } = {}) {
        const addr = toBigInt(functionAddress);
        const results = runtimeEvidenceForApp(app, addr).slice(-limit);
        const completeConfirmed = results.filter((item)=>item?.verdict==='confirmed' && item?.observedState?.factsComplete !== false && item?.reproducibility?.replayable === true);
        const contradicted = results.filter((item)=>item?.verdict==='contradicted').length;
        return {
          results, returned:results.length,
          status:contradicted ? 'contradicted' : completeConfirmed.length ? 'confirmed' : results.length ? 'observed' : 'none',
          verified:completeConfirmed.length > 0 && contradicted === 0,
          verification:{confirmedCompleteReplayable:completeConfirmed.length,contradictions:contradicted,total:results.length}
        };
      },
      async verifyHypothesis(hypothesis, options) {
        try { return await verifyAppHypothesis(app, hypothesis, options || {}); }
        catch (error) { return { verified: false, reason: String(error && error.message || error) }; }
      },
      async platform() { return runtimePlatformForApp(app); },
    },
  };
  return context;
}

function safeCurrentFunction(app) {
  try { return currentFunctionAddr(app); } catch { return null; }
}

function pseudocode(app, model, addr, nameOf) {
  const region = regionForAddress(app, addr);
  return decompile(model, {
    name: nameOf(addr),
    addr,
    rowOfAddress: (a) => (region && a != null && containsAddress(region, a) ? Number((a - region.vmAddr) / BigInt(instructionBytes(app))) : null),
    addrOfRow: (row) => (region ? region.vmAddr + BigInt(row) * BigInt(instructionBytes(app)) : null),
    symbolFor: (a) => app.symbols?.nameAt?.(a) || null,
    objcModel: app.objcModel || null,
    objcRuntimeIndex: app.objcRuntime || null,
    swiftModel: app.swiftModel || null,
    swiftRuntimeIndex: app.swiftRuntime || null,
    resolveSwiftDispatch: (call) => app.resolveSwiftCall?.(call) || null,
    notes: app.notes,
  });
}

export default createHexAIContext;
