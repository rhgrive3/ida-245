/*
 * プログラム全体の索引 — 「誰が誰を呼び、誰が何を見ているか」。
 * 中身は型付き配列と二分探索。query arrayにはcomplete/capped metadataも付け、
 * edge cap到達時に「結果が無い」を「参照が無い」と誤解させない。
 */
import './words.js';

const Words = globalThis.Words;
export const KIND = Words.KIND;

function lowerBound(values, order, addr) {
  let lo = 0, hi = order.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (values[order[mid]] < addr) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}
function lowerBoundDirect(values, addr) {
  let lo = 0, hi = values.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (values[mid] < addr) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}
export const PROGRAM_MERGE_LIMITS = Object.freeze({
  calls: 2_000_000,
  refs: 2_000_000,
  kindWords: 16 * 1024 * 1024,
});

function boundedCount(scan, countKey, ...arrays) {
  const requested = Number.isSafeInteger(scan?.[countKey]) ? scan[countKey] : (arrays[0]?.length || 0);
  return Math.max(0, Math.min(requested, ...arrays.map((x) => x?.length || 0)));
}

function strictLimit(value, fallback) {
  if (value === undefined) return fallback;
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) return value;
  return fallback;
}

/** Merge independently scanned executable regions without losing provenance. */
export function mergeProgramScans(scans = [], options = {}) {
  const callsLimit = strictLimit(options?.limits?.calls, PROGRAM_MERGE_LIMITS.calls);
  const refsLimit = strictLimit(options?.limits?.refs, PROGRAM_MERGE_LIMITS.refs);
  const kindWordsLimit = strictLimit(options?.limits?.kindWords, PROGRAM_MERGE_LIMITS.kindWords);
  const inputScans = (scans || []).filter(Boolean);
  const ordered = inputScans.filter((x) => !x.cancelled).slice().sort((a,b) => {
    const av=BigInt(a.vmAddr ?? 0), bv=BigInt(b.vmAddr ?? 0);
    return av < bv ? -1 : av > bv ? 1 : String(a.regionId||'').localeCompare(String(b.regionId||''));
  });
  const expectedRegionsSpecified = Array.isArray(options.regions);
  const expectedRegions = (expectedRegionsSpecified ? options.regions : []).map((r) => ({ id:r.id ?? null, vmAddr:BigInt(r.vmAddr ?? 0), size:BigInt(r.size ?? 0) }));
  const reasons = [...(options.reasons || [])];
  for (const scan of inputScans) if (scan.cancelled) reasons.push(`${scan.regionId || 'region'}:cancelled`);
  const scannedIds = new Set(ordered.map((x) => x.regionId).filter((x) => x != null));
  for (const region of expectedRegions) {
    let matched = false;
    if (region.id != null) {
      matched = scannedIds.has(region.id);
    } else {
      matched = ordered.some((s) => BigInt(s.vmAddr ?? 0) === region.vmAddr);
    }
    if (!matched) {
      reasons.push(region.id != null ? `program-region-unscanned:${region.id}` : `program-region-unscanned:0x${region.vmAddr.toString(16)}`);
    }
  }
  if (expectedRegionsSpecified) {
    for (const scan of ordered) {
      const sId = scan.regionId ?? null;
      const sAddr = BigInt(scan.vmAddr ?? 0);
      const matched = expectedRegions.some((r) => {
        if (sId != null && r.id != null) return sId === r.id;
        return r.vmAddr === sAddr;
      });
      if (!matched) {
        reasons.push(sId != null ? `program-unexpected-region:${sId}` : `program-unexpected-region:0x${sAddr.toString(16)}`);
      }
    }
  }
  for (const scan of ordered) {
    if (scan.unsupported) reasons.push('unsupported-program-analysis');
    if (scan.completeness?.complete === false || scan.complete === false) {
      const rs = scan.completeness?.reasons || (scan.truncationReason ? [scan.truncationReason] : ['program-region-incomplete']);
      for (const reason of rs) reasons.push(`${scan.regionId || 'region'}:${reason}`);
    }
  }

  const callAvailable = ordered.reduce((n,s) => n + boundedCount(s,'callCount',s.callFrom,s.callTo),0);
  const refAvailable = ordered.reduce((n,s) => n + boundedCount(s,'refCount',s.refFrom,s.refTo,s.refKind),0);
  const callCap = Math.max(0, Math.min(callsLimit, callAvailable));
  const refCap = Math.max(0, Math.min(refsLimit, refAvailable));
  const callFrom=new BigUint64Array(callCap), callTo=new BigUint64Array(callCap);
  const refFrom=new BigUint64Array(refCap), refTo=new BigUint64Array(refCap), refKind=new Uint8Array(refCap);
  let ci=0, ri=0;
  for (const scan of ordered) {
    const nc=boundedCount(scan,'callCount',scan.callFrom,scan.callTo), ct=Math.min(nc,callCap-ci);
    if (ct>0) { callFrom.set(scan.callFrom.subarray(0,ct),ci); callTo.set(scan.callTo.subarray(0,ct),ci); ci+=ct; }
    const nr=boundedCount(scan,'refCount',scan.refFrom,scan.refTo,scan.refKind), rt=Math.min(nr,refCap-ri);
    if (rt>0) { refFrom.set(scan.refFrom.subarray(0,rt),ri); refTo.set(scan.refTo.subarray(0,rt),ri); refKind.set(scan.refKind.subarray(0,rt),ri); ri+=rt; }
  }
  if (callAvailable > callCap) reasons.push('global-call-edge-budget');
  if (refAvailable > refCap) reasons.push('global-reference-budget');

  let remainingKinds=Math.max(0, kindWordsLimit), words=0, kindsCovered=0;
  const kindRegions=[];
  for (const scan of ordered) {
    const regionWords=Math.max(0,Number(scan.words)||0), src=scan.kinds || new Uint8Array(0);
    const sourceCovered=Math.max(0,Math.min(Number(scan.kindsCovered ?? src.length)||0,src.length,regionWords));
    const take=Math.min(sourceCovered,remainingKinds);
    const kinds=take>0 ? src.slice(0,take) : new Uint8Array(0);
    kindRegions.push({ regionId:scan.regionId ?? null, vmAddr:BigInt(scan.vmAddr ?? 0), words:regionWords, kinds, kindsCovered:take });
    words += regionWords; kindsCovered += take; remainingKinds -= take;
    if (take < sourceCovered || take < regionWords) reasons.push(`${scan.regionId || 'region'}:kind-stat-budget`);
  }

  const uniqueReasons=[...new Set(reasons.filter(Boolean))];
  const unsupported=ordered.length>0 && ordered.every((x)=>x.unsupported===true);
  const callsCapped=callAvailable>callCap || ordered.some((x)=>x.callsCapped);
  const refsCapped=refAvailable>refCap || ordered.some((x)=>x.refsCapped);
  const complete=!unsupported && uniqueReasons.length===0
    && (!expectedRegionsSpecified || expectedRegions.length===ordered.length);
  return {
    vmAddr: ordered.length ? BigInt(ordered[0].vmAddr ?? 0) : (expectedRegions[0]?.vmAddr ?? 0n),
    regions: expectedRegions,
    kindRegions,
    callFrom, callTo, callCount:ci,
    refFrom, refTo, refKind, refCount:ri,
    kinds:new Uint8Array(0), kindsCovered, words,
    callsCapped, refsCapped, unsupported,
    architecture: ordered.find((x)=>x.architecture || x.arch)?.architecture || ordered.find((x)=>x.arch)?.arch || null,
    complete, truncated:!complete,
    completeness:{ complete, reasons:uniqueReasons, regionCount:ordered.length,
      expectedRegionCount:expectedRegionsSpecified ? expectedRegions.length : null,
      limits:{calls:callCap,refs:refCap,kindWords:kindWordsLimit} },
  };
}

function completeness(array, capped, source, queryLimited = false, unavailableReason = null) {
  const sourceCapped = !!capped;
  const locallyLimited = !!queryLimited;
  const unavailable = unavailableReason || null;
  Object.defineProperties(array, {
    complete: { value: !unavailable && !sourceCapped && !locallyLimited, enumerable: false, configurable: true },
    capped: { value: sourceCapped, enumerable: false, configurable: true },
    queryLimited: { value: locallyLimited, enumerable: false, configurable: true },
    unsupported: { value: unavailable === 'unsupported-program-analysis', enumerable: false, configurable: true },
    completenessSource: { value: source, enumerable: false, configurable: true },
    incompleteReason: {
      value: unavailable || (sourceCapped ? `${source}-source-capped` : (locallyLimited ? 'query-limit' : null)),
      enumerable: false, configurable: true,
    },
  });
  return array;
}

function queryLimit(value, fallback) {
  if (value == null) return fallback;
  if (typeof value !== 'number' && !(typeof value === 'string' && value.trim() !== '')) return fallback;
  const n = Number(value);
  return Number.isSafeInteger(n) && n >= 0 ? n : fallback;
}

function transportCount(value, fallback, field) {
  if (value == null) return fallback;
  if (!Number.isSafeInteger(value) || value < 0) throw new TypeError(`${field}-invalid`);
  return value;
}

export class ProgramIndex {
  constructor(scan, symbols, region) {
    const s = scan || {};
    this.region = region || null;
    this.regions = Array.isArray(s.regions) && s.regions.length ? s.regions.map((r)=>({ ...r, vmAddr:BigInt(r.vmAddr ?? 0), size:BigInt(r.size ?? 0) })) : (region ? [region] : []);
    this.symbols = symbols || null;
    this.vmAddr = s.vmAddr != null ? s.vmAddr : (region ? region.vmAddr : 0n);
    const rawCallFrom = s.callFrom || new BigUint64Array(0);
    const rawCallTo = s.callTo || new BigUint64Array(0);
    const rawRefFrom = s.refFrom || new BigUint64Array(0);
    const rawRefTo = s.refTo || new BigUint64Array(0);
    const rawRefKind = s.refKind || new Uint8Array(0);
    const callCount = Math.min(transportCount(s.callCount, rawCallFrom.length, 'program-call-count'), rawCallFrom.length, rawCallTo.length);
    const refCount = Math.min(transportCount(s.refCount, rawRefFrom.length, 'program-ref-count'), rawRefFrom.length, rawRefTo.length, rawRefKind.length);
    this.callFrom = rawCallFrom.subarray(0, callCount);
    this.callTo = rawCallTo.subarray(0, callCount);
    this.refFrom = rawRefFrom.subarray(0, refCount);
    this.refTo = rawRefTo.subarray(0, refCount);
    this.refKind = rawRefKind.subarray(0, refCount);
    const singleKinds=s.kinds || new Uint8Array(0);
    this.kindRegions = Array.isArray(s.kindRegions) && s.kindRegions.length
      ? s.kindRegions.map((k)=>({ regionId:k.regionId ?? null, vmAddr:BigInt(k.vmAddr ?? 0), words:Math.max(0,Number(k.words)||0), kinds:k.kinds||new Uint8Array(0), kindsCovered:Math.max(0,Number(k.kindsCovered)||0) }))
      : (singleKinds.length || s.words ? [{ regionId:s.regionId ?? region?.id ?? null, vmAddr:BigInt(s.vmAddr ?? region?.vmAddr ?? 0), words:Math.max(0,Number(s.words)||0), kinds:singleKinds, kindsCovered:Math.max(0,Number(s.kindsCovered)||0) }] : []);
    this.kinds = this.kindRegions.length===1 ? this.kindRegions[0].kinds : singleKinds;
    this.kindsCovered = this.kindRegions.length ? this.kindRegions.reduce((n,k)=>n+k.kindsCovered,0) : (s.kindsCovered || 0);
    this.callsCapped = !!s.callsCapped;
    this.refsCapped = !!s.refsCapped;
    this.words = this.kindRegions.length ? this.kindRegions.reduce((n,k)=>n+k.words,0) : (s.words || 0);
    this.unsupported = !!s.unsupported;
    this.architecture = s.architecture || s.arch || null;
    const suppliedCompleteness = s.completeness && typeof s.completeness === 'object' ? s.completeness : null;
    const reasons = [...new Set([
      ...(Array.isArray(suppliedCompleteness?.reasons) ? suppliedCompleteness.reasons : []),
      ...(this.unsupported ? ['unsupported-program-analysis'] : []),
    ])];
    this.completeness = {
      ...(suppliedCompleteness || {}),
      complete: !this.unsupported && (suppliedCompleteness ? suppliedCompleteness.complete === true : (!this.callsCapped && !this.refsCapped)),
      reasons,
    };
    this.queryIncompleteReason = this.unsupported ? 'unsupported-program-analysis'
      : (this.completeness.complete === false ? (reasons[0] || 'program-analysis-incomplete') : null);
    this.gen = symbols && symbols.gen != null ? symbols.gen : 0;
    this._byCallTo = null;
    this._byRefTo = null;
  }
  get callCount() { return this.callFrom.length; }
  get refCount() { return this.refFrom.length; }
  get statsComplete() {
    if (this.unsupported || this.completeness.complete === false) return false;
    return this.kindRegions.length ? this.kindRegions.every((k)=>k.kindsCovered>=k.words) : this.kindsCovered>=this.words;
  }
  get graphCompleteness() {
    const sourceComplete = !this.unsupported && this.completeness.complete !== false;
    return Object.freeze({
      supported: !this.unsupported,
      unsupported: this.unsupported,
      architecture: this.architecture,
      reasons: [...(this.completeness.reasons || [])],
      callsComplete: sourceComplete && !this.callsCapped,
      refsComplete: sourceComplete && !this.refsCapped,
      statsComplete: this.statsComplete,
    });
  }

  _callToOrder() {
    if (!this._byCallTo) {
      const n = this.callTo.length, order = new Int32Array(n), to = this.callTo;
      for (let i = 0; i < n; i++) order[i] = i;
      order.sort((a, b) => (to[a] < to[b] ? -1 : to[a] > to[b] ? 1 : a - b));
      this._byCallTo = order;
    }
    return this._byCallTo;
  }
  _refToOrder() {
    if (!this._byRefTo) {
      const n = this.refTo.length, order = new Int32Array(n), to = this.refTo;
      for (let i = 0; i < n; i++) order[i] = i;
      order.sort((a, b) => (to[a] < to[b] ? -1 : to[a] > to[b] ? 1 : a - b));
      this._byRefTo = order;
    }
    return this._byRefTo;
  }
  functionStartOf(addr) {
    if (!this.symbols || !this.symbols.functionCount) return null;
    if (this.symbols.functionStartAt) return this.symbols.functionStartAt(addr);
    const fn = this.symbols.functionAt(addr);
    return fn && !(fn.end != null && addr >= fn.end) ? fn.start : null;
  }
  _regionFor(addr) {
    const a=BigInt(addr);
    return this.regions.find((r)=>a>=BigInt(r.vmAddr) && a<BigInt(r.vmAddr)+BigInt(r.size)) || null;
  }
  functionRange(addr) {
    if (!this.symbols || !this.symbols.functionCount) return null;
    const fn = this.symbols.functionAt(addr);
    if (!fn) return null;
    const owner=this._regionFor(fn.start) || this.region;
    return { start: fn.start, end: fn.end != null ? fn.end : null, region:owner };
  }
  callSitesTo(target, limit = 500) {
    limit = queryLimit(limit, 500);
    const order = this._callToOrder(), out = [];
    let i = lowerBound(this.callTo, order, target), queryLimited = false;
    for (; i < order.length; i++) {
      const k = order[i];
      if (this.callTo[k] !== target) break;
      if (out.length >= limit) { queryLimited = true; break; }
      out.push({ site: this.callFrom[k], caller: this.functionStartOf(this.callFrom[k]) });
    }
    return completeness(out, this.callsCapped, 'calls', queryLimited, this.queryIncompleteReason);
  }
  callersOf(target, limit = 200) {
    limit = queryLimit(limit, 200);
    const seen = new Map();
    const sites = this.callSitesTo(target, Math.max(0, limit * 4));
    let queryLimited = sites.complete !== true;
    for (const c of sites) {
      const key = c.caller != null ? c.caller.toString() : 's' + c.site.toString();
      if (!seen.has(key)) {
        if (seen.size >= limit) { queryLimited = true; break; }
        seen.set(key, { addr: c.caller, site: c.site, count: 0 });
      }
      seen.get(key).count++;
    }
    return completeness(Array.from(seen.values()), this.callsCapped, 'calls', queryLimited, this.queryIncompleteReason);
  }
  calleesOf(start, end, limit = 200) {
    limit = queryLimit(limit, 200);
    const out = new Map(); let i = lowerBoundDirect(this.callFrom, start), queryLimited = false;
    for (; i < this.callFrom.length; i++) {
      const from = this.callFrom[i]; if (end != null && from >= end) break;
      const to = this.callTo[i], key = to.toString();
      if (!out.has(key)) {
        if (out.size >= limit) { queryLimited = true; break; }
        out.set(key, { addr: to, site: from, count: 0 });
      }
      out.get(key).count++;
    }
    return completeness(Array.from(out.values()), this.callsCapped, 'calls', queryLimited, this.queryIncompleteReason);
  }
  callCountOf(target) {
    const order = this._callToOrder(); let i = lowerBound(this.callTo, order, target), n = 0;
    for (; i < order.length && this.callTo[order[i]] === target; i++) n++;
    return n;
  }
  refSitesTo(addr, span = 1n, limit = 500) {
    limit = queryLimit(limit, 500);
    const order = this._refToOrder(), out = []; let i = lowerBound(this.refTo, order, addr), queryLimited = false;
    const hi = addr + (span > 0n ? span : 1n);
    for (; i < order.length; i++) {
      const k = order[i]; if (this.refTo[k] >= hi) break;
      if (out.length >= limit) { queryLimited = true; break; }
      out.push({ site: this.refFrom[k], target: this.refTo[k], kind: this.refKind[k] });
    }
    return completeness(out, this.refsCapped, 'refs', queryLimited, this.queryIncompleteReason);
  }
  functionsReferencing(addr, span = 1n, limit = 200) {
    limit = queryLimit(limit, 200);
    const seen = new Map();
    const refs = this.refSitesTo(addr, span, Math.max(0, limit * 4));
    let queryLimited = refs.complete !== true;
    for (const r of refs) {
      const fn = this.functionStartOf(r.site), key = fn != null ? fn.toString() : 's' + r.site.toString();
      if (!seen.has(key)) {
        if (seen.size >= limit) { queryLimited = true; break; }
        seen.set(key, { addr: fn, site: r.site, kind: r.kind, count: 0 });
      }
      seen.get(key).count++;
    }
    return completeness(Array.from(seen.values()), this.refsCapped, 'refs', queryLimited, this.queryIncompleteReason);
  }
  refsFrom(start, end, limit = 400) {
    limit = queryLimit(limit, 400);
    const out = []; let i = lowerBoundDirect(this.refFrom, start), queryLimited = false;
    for (; i < this.refFrom.length; i++) {
      const from = this.refFrom[i]; if (end != null && from >= end) break;
      if (out.length >= limit) { queryLimited = true; break; }
      out.push({ site: from, target: this.refTo[i], kind: this.refKind[i] });
    }
    return completeness(out, this.refsCapped, 'refs', queryLimited, this.queryIncompleteReason);
  }
  statsOf(start, end) {
    const stats = { total: 0, covered: true, arith: 0, mul: 0, div: 0, logic: 0, shift: 0, farith: 0, fmul: 0, fconv: 0, simd: 0, load: 0, store: 0, cmp: 0, condbr: 0, branch: 0, call: 0, indcall: 0, ret: 0, csel: 0, atomic: 0, movimm: 0, adrp: 0, trap: 0, other: 0 };
    if (this.unsupported) { stats.covered = false; stats.unsupported = true; stats.incompleteReason = 'unsupported-program-analysis'; return stats; }
    const lastAddr=end!=null?BigInt(end):BigInt(start)+4n;
    const spans=this.kindRegions.length?this.kindRegions:[{vmAddr:BigInt(this.vmAddr||0),words:this.words,kinds:this.kinds,kindsCovered:this.kindsCovered}];
    const span=spans.find((k)=>BigInt(start)>=k.vmAddr && BigInt(start)<k.vmAddr+BigInt(k.words)*4n);
    if(!span || !span.kinds.length){stats.covered=false;return stats;}
    const spanEnd=span.vmAddr+BigInt(span.words)*4n;
    const boundedEnd=lastAddr>spanEnd?spanEnd:lastAddr;
    if(lastAddr>spanEnd)stats.covered=false;
    const first=Number((BigInt(start)-span.vmAddr)/4n);
    let last=Number((boundedEnd-span.vmAddr+3n)/4n);
    if(!(first>=0)){stats.covered=false;return stats;}
    if(last>span.kindsCovered){last=span.kindsCovered;stats.covered=false;}
    for (let i = first; i < last; i++) {
      const k = span.kinds[i]; stats.total++;
      switch (k) {
        case KIND.ARITH: stats.arith++; break; case KIND.MUL: stats.mul++; break; case KIND.DIV: stats.div++; break;
        case KIND.LOGIC: stats.logic++; break; case KIND.SHIFT: stats.shift++; break; case KIND.FARITH: stats.farith++; break;
        case KIND.FMUL: stats.fmul++; break; case KIND.FCONV: stats.fconv++; break; case KIND.SIMD: stats.simd++; break;
        case KIND.LOAD: stats.load++; break; case KIND.STORE: stats.store++; break; case KIND.CMP: stats.cmp++; break;
        case KIND.CONDBR: stats.condbr++; break; case KIND.BRANCH: stats.branch++; break; case KIND.CALL: stats.call++; break;
        case KIND.INDCALL: stats.indcall++; break; case KIND.RET: stats.ret++; break; case KIND.CSEL: stats.csel++; break;
        case KIND.ATOMIC: stats.atomic++; break; case KIND.MOVIMM: stats.movimm++; break; case KIND.ADRP: stats.adrp++; break;
        case KIND.TRAP: stats.trap++; break; case KIND.OTHER: stats.other++; break; default: break;
      }
    }
    stats.numeric = stats.mul + stats.div + stats.fmul + stats.farith;
    stats.memory = stats.load + stats.store;
    return stats;
  }
  mostCalled(limit = 20) {
    limit = queryLimit(limit, 20);
    const counts = new Map();
    for (let i = 0; i < this.callTo.length; i++) { const key = this.callTo[i].toString(); counts.set(key, (counts.get(key) || 0) + 1); }
    const out = []; for (const [key, n] of counts) out.push({ addr: BigInt(key), count: n });
    out.sort((a, b) => b.count - a.count);
    return completeness(out.slice(0, limit), this.callsCapped, 'calls', out.length > limit, this.queryIncompleteReason);
  }
}

export const EMPTY_PROGRAM = new ProgramIndex(null, null, null);
