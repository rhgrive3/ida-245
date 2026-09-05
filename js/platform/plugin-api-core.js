import { validatePluginManifest, checkManifestCompatibility, PluginCompatibilityError } from './plugin-manifest.js';

const TYPES = new Set(['format', 'architecture', 'analyzer', 'knowledgeProvider', 'signatureProvider', 'recognitionProvider', 'viewContribution', 'goalProvider']);
const DEFAULT_TIMEOUT_MS = 15_000;
const DEFAULT_READ_CALL_BYTES = 1024 * 1024;
const DEFAULT_READ_TOTAL_BYTES = 8 * 1024 * 1024;

function deepFreeze(value, seen = new WeakSet()) {
  if (!value || typeof value !== 'object' || seen.has(value)) return value;
  seen.add(value);
  if (value instanceof Map) for (const [k, v] of value) { deepFreeze(k, seen); deepFreeze(v, seen); }
  else if (value instanceof Set) for (const v of value) deepFreeze(v, seen);
  else for (const key of Reflect.ownKeys(value)) { const desc = Object.getOwnPropertyDescriptor(value, key); if (desc && 'value' in desc) deepFreeze(desc.value, seen); }
  try { Object.freeze(value); } catch { /* typed arrays may reject freeze */ }
  return value;
}

function fallbackClone(value, seen = new WeakMap(), depth = 0) {
  if (value == null || typeof value !== 'object') return value;
  if (depth > 32) throw new Error('plugin context nesting exceeds safety limit');
  if (seen.has(value)) return seen.get(value);
  if (value instanceof Date) return new Date(value.getTime());
  if (value instanceof ArrayBuffer) return value.slice(0);
  if (ArrayBuffer.isView(value)) { if (value instanceof DataView) return new DataView(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength)); return value.slice ? value.slice() : new value.constructor(value); }
  if (value instanceof Map) { const out = new Map(); seen.set(value, out); for (const [k, v] of value) out.set(fallbackClone(k, seen, depth + 1), fallbackClone(v, seen, depth + 1)); return out; }
  if (value instanceof Set) { const out = new Set(); seen.set(value, out); for (const v of value) out.add(fallbackClone(v, seen, depth + 1)); return out; }
  if (Array.isArray(value)) { const out = []; seen.set(value, out); for (const v of value) out.push(fallbackClone(v, seen, depth + 1)); return out; }
  const out = Object.create(null); seen.set(value, out);
  for (const [key, v] of Object.entries(value)) { if (typeof v === 'function') continue; out[key] = fallbackClone(v, seen, depth + 1); }
  return out;
}

function safeSnapshot(value) {
  if (value == null) return null;
  let clone;
  if (typeof structuredClone === 'function') { try { clone = structuredClone(value); } catch { clone = fallbackClone(value); } }
  else clone = fallbackClone(value);
  return deepFreeze(clone);
}

function strictPositiveInteger(value, fallback) {
  if (value == null) return fallback;
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) return fallback;
  return value;
}
function strictIntegerBigInt(value, message = 'integer value is invalid') {
  if (typeof value === 'bigint') return value;
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new TypeError(message);
    return BigInt(value);
  }
  if (typeof value === 'string') {
    const text = value.trim();
    if (!text || !/^[+-]?(?:0[xX][0-9a-fA-F]+|[0-9]+)$/.test(text)) throw new TypeError(message);
    try { return BigInt(text); } catch { throw new TypeError(message); }
  }
  throw new TypeError(message);
}
function normalizeRanges(value) {
  if (!Array.isArray(value)) return [];
  const out = [];
  for (const range of value) {
    try {
      const start = strictIntegerBigInt(range.start ?? range.address ?? range.vmAddr, 'plugin read range start must be an integer');
      const size = strictIntegerBigInt(range.size ?? range.length ?? 0, 'plugin read range size must be an integer');
      if (size > 0n) out.push({ start, end: start + size });
    } catch { /* malformed ranges grant nothing */ }
  }
  return out;
}

function makeReadCapability(context, pluginScope = null, record = null) {
  if (typeof context.read !== 'function') return undefined;
  const policy = context.pluginPolicy || context.pluginPermissions || {};
  let manifestPerm = true;
  if (record?.manifest?.permissions) {
    manifestPerm = Boolean(record.manifest.permissions.binaryRead);
  }
  const allowed = manifestPerm && (policy.binaryRead === true || policy.readBinary === true);
  const ranges = normalizeRanges(policy.readRanges || policy.ranges || context.binary?.readRanges);
  if (!allowed && !ranges.length) return async () => { throw new Error('plugin binary read permission denied'); };
  const perCall = strictPositiveInteger(policy.maxReadBytes, DEFAULT_READ_CALL_BYTES);
  const totalLimit = strictPositiveInteger(policy.maxTotalReadBytes, DEFAULT_READ_TOTAL_BYTES);
  let total = 0;
  return async (address, length) => {
    const at = strictIntegerBigInt(address, 'plugin read address must be an integer');
    if (typeof length !== 'number' || !Number.isSafeInteger(length)) {
      throw new TypeError('plugin read length must be an integer');
    }
    const bytes = length;
    if (bytes < 0 || bytes > perCall) throw new RangeError(`plugin read exceeds per-call limit (${perCall} bytes)`);
    if (total + bytes > totalLimit) throw new RangeError(`plugin read exceeds total budget (${totalLimit} bytes)`);
    if (ranges.length && !ranges.some((r) => at >= r.start && at + BigInt(bytes) <= r.end)) throw new RangeError('plugin read is outside permitted ranges');
    if (pluginScope && typeof pluginScope.consume === 'function') {
      pluginScope.consume('bytesRead', bytes);
    }
    total += bytes;
    const value = await context.read(at, bytes);
    return safeSnapshot(value);
  };
}

function settleWithin(promise, timeoutMs, signal) {
  return new Promise((resolve, reject) => {
    let done = false;
    const finish = (fn, value) => { if (done) return; done = true; clearTimeout(timer); signal?.removeEventListener?.('abort', onAbort); fn(value); };
    const onAbort = () => finish(reject, signal.reason instanceof Error ? signal.reason : new Error('plugin invocation aborted'));
    const timer = setTimeout(() => finish(reject, new Error(`plugin invocation timed out after ${timeoutMs}ms`)), timeoutMs);
    if (signal?.aborted) return onAbort();
    signal?.addEventListener?.('abort', onAbort, { once: true });
    Promise.resolve(promise).then((v) => finish(resolve, v), (e) => finish(reject, e));
  });
}

function validateContributionId(id) {
  if (typeof id !== 'string' || !/^[a-z0-9][a-z0-9._-]{1,127}$/i.test(id)) {
    throw new TypeError('plugin contribution id must be stable and non-empty');
  }
  return id;
}

export class PlatformPluginRegistry {
  constructor(options = {}) {
    this.entries = new Map([...TYPES].map((type) => [type, new Map()]));
    this.plugins = new Map();
    this.failures = [];
    this.timeoutMs = strictPositiveInteger(options.timeoutMs, DEFAULT_TIMEOUT_MS);
  }

  registerFormat(id, contribution) { return this.#register('format', id, contribution); }
  registerArchitecture(id, contribution) { return this.#register('architecture', id, contribution); }

  registerAnalyzer(id, contribution) {
    if (!contribution || typeof contribution !== 'object') throw new TypeError('plugin contribution must be an object');
    const validId = validateContributionId(id);
    const legacyManifest = {
      id: `legacy.analyzer.${validId}`,
      name: `Legacy analyzer ${validId}`,
      version: '1.0.0',
      apiVersion: '2.0.0',
      isLegacy: true,
      permissions: { binaryRead: true },
      supportedTargets: ['*'],
      contributions: [{
        type: 'analyzer',
        id: validId,
        contractVersion: '1.0.0',
        capabilities: [],
      }],
    };
    return this.registerPlugin(legacyManifest, { [validId]: contribution });
  }

  registerKnowledgeProvider(id, contribution) { return this.#register('knowledgeProvider', id, contribution); }
  registerSignatureProvider(id, contribution) { return this.#register('signatureProvider', id, contribution); }
  registerRecognitionProvider(id, contribution) { return this.#register('recognitionProvider', id, contribution); }
  registerViewContribution(id, contribution) { return this.#register('viewContribution', id, contribution); }
  registerGoalProvider(id, contribution) { return this.#register('goalProvider', id, contribution); }

  registerPlugin(rawManifest, implementations = {}) {
    const manifest = validatePluginManifest(rawManifest);
    checkManifestCompatibility(manifest);

    if (this.plugins.has(manifest.id)) {
      throw new Error(`plugin already registered: ${manifest.id}`);
    }

    for (const contrib of manifest.contributions) {
      if (this.entries.get(contrib.type)?.has(contrib.id)) {
        throw new Error(`plugin contribution already registered: ${contrib.type}:${contrib.id}`);
      }
      const impl = implementations[contrib.id];
      if (!impl || typeof impl !== 'object') {
        throw new TypeError(`missing implementation for contribution: ${contrib.id}`);
      }
      if (contrib.type === 'analyzer' && typeof impl.analyze !== 'function') {
        throw new TypeError(`analyzer implementation must have analyze(): ${contrib.id}`);
      }
    }

    const registered = [];
    for (const contrib of manifest.contributions) {
      const impl = implementations[contrib.id];
      const record = Object.freeze({
        id: contrib.id,
        type: contrib.type,
        contribution: Object.freeze({ ...impl }),
        pluginId: manifest.id,
        manifest,
        contractVersion: contrib.contractVersion,
        capabilities: contrib.capabilities,
      });
      this.entries.get(contrib.type).set(contrib.id, record);
      registered.push({ type: contrib.type, id: contrib.id });
    }

    const pluginRecord = Object.freeze({
      id: manifest.id,
      name: manifest.name,
      version: manifest.version,
      apiVersion: manifest.apiVersion,
      contributionIds: Object.freeze(manifest.contributions.map((c) => c.id)),
      manifest,
    });
    this.plugins.set(manifest.id, pluginRecord);

    return () => {
      for (const { type, id } of registered) {
        this.entries.get(type)?.delete(id);
      }
      this.plugins.delete(manifest.id);
    };
  }

  listPlugins() {
    return [...this.plugins.values()]
      .sort((a, b) => a.id.localeCompare(b.id))
      .map((p) => Object.freeze({
        id: p.id,
        name: p.name,
        version: p.version,
        apiVersion: p.apiVersion,
        contributionIds: p.contributionIds,
      }));
  }

  #register(type, id, contribution) {
    if (!TYPES.has(type)) throw new Error(`unsupported plugin contribution type: ${type}`);
    const key = validateContributionId(id);
    if (!contribution || typeof contribution !== 'object') throw new TypeError('plugin contribution must be an object');
    const bucket = this.entries.get(type);
    if (bucket.has(key)) throw new Error(`plugin contribution already registered: ${type}:${key}`);
    const record = Object.freeze({ id: key, type, contribution: Object.freeze({ ...contribution }) });
    bucket.set(key, record);
    return () => bucket.delete(key);
  }

  list(type) { if (!TYPES.has(type)) return []; return [...this.entries.get(type).values()]; }

  async invoke(type, id, method, context = {}, ...args) {
    const record = this.entries.get(type)?.get(id);
    if (!record) return { ok: false, error: `unknown contribution ${type}:${id}` };
    const fn = record.contribution[method];
    if (typeof fn !== 'function') return { ok: false, error: `contribution ${type}:${id} has no ${method}()` };
    const rawOptions = args.at(-1) && typeof args.at(-1) === 'object' ? args.at(-1) : {};
    const timeoutMs = strictPositiveInteger(rawOptions.timeoutMs, this.timeoutMs);
    const signal = rawOptions.signal;

    let pluginScope = null;
    if (context.resourceBudget && typeof context.resourceBudget.scope === 'function') {
      const sanitized = `${type}.${id}.${method}`.replace(/[^a-zA-Z0-9_\-\.]/g, '_');
      try {
        pluginScope = context.resourceBudget.scope(sanitized);
      } catch {
        pluginScope = context.resourceBudget;
      }
    }

    try {
      const safeContext = Object.freeze({
        binary: safeSnapshot(context.binary), capability: safeSnapshot(context.capability), project: safeSnapshot(context.project),
        read: makeReadCapability(context, pluginScope, record),
        resourceBudget: pluginScope || context.resourceBudget,
        reportProgress: typeof context.reportProgress === 'function' ? (...progressArgs) => context.reportProgress(...progressArgs.map((x) => safeSnapshot(x))) : undefined,
      });
      const safeArgs = args.map((arg) => safeSnapshot(arg));
      const value = await settleWithin(Promise.resolve().then(() => fn(safeContext, ...safeArgs)), timeoutMs, signal);
      return { ok: true, value: safeSnapshot(value) };
    } catch (error) {
      const failure = { type, id, method, error: error?.message || String(error), at: Date.now() };
      this.failures.push(failure); if (this.failures.length > 100) this.failures.shift();
      return { ok: false, error: failure.error, isolated: true, timeout: /timed out/i.test(failure.error) };
    }
  }

  async runAnalyzers(context, options = {}) {
    const out = [];
    for (const record of this.list('analyzer')) { if (options.signal?.aborted) break; const result = await this.invoke('analyzer', record.id, 'analyze', context, options); out.push({ id: record.id, ...result }); }
    return out;
  }

  async runProviders(type, method, context = {}, options = {}) {
    if (!['knowledgeProvider', 'signatureProvider', 'recognitionProvider'].includes(type)) throw new TypeError('unsupported provider type');
    const out = [];
    for (const record of this.list(type)) { if (options.signal?.aborted) break; const result = await this.invoke(type, record.id, method, context, options); out.push({ id: record.id, ...result }); }
    return out;
  }
}

export const platformPlugins = new PlatformPluginRegistry();
export const registerFormat = (...args) => platformPlugins.registerFormat(...args);
export const registerArchitecture = (...args) => platformPlugins.registerArchitecture(...args);
export const registerAnalyzer = (...args) => platformPlugins.registerAnalyzer(...args);
export const registerKnowledgeProvider = (...args) => platformPlugins.registerKnowledgeProvider(...args);
export const registerSignatureProvider = (...args) => platformPlugins.registerSignatureProvider(...args);
export const registerRecognitionProvider = (...args) => platformPlugins.registerRecognitionProvider(...args);
export const registerViewContribution = (...args) => platformPlugins.registerViewContribution(...args);
export const registerGoalProvider = (...args) => platformPlugins.registerGoalProvider(...args);
export { PluginCompatibilityError };

