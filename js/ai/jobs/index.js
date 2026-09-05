const CHECKPOINT_VERSION = 1;
let fallbackRandomSequence = 0n;

export class AgentJobManager {
  constructor({ runtime, persistence = null, maxSlices = 8, maxElapsedMs = 30 * 60 * 1000 } = {}) {
    if (!runtime || typeof runtime.turn !== 'function') throw new TypeError('AgentJobManager requires an AIRuntime');
    this.runtime = runtime; this.persistence = persistence; this.maxSlices = bounded(maxSlices, 1, 32); this.maxElapsedMs = bounded(maxElapsedMs, 1000, 4 * 60 * 60 * 1000);
    this.jobs = new Map(); this.creatingIds = new Set(); this.runningJobIds = new Set(); this.loadingPromises = new Map();
  }

  async create(input = {}) {
    const now = new Date().toISOString();
    const goal = String(input.goal || '');
    if (!goal) throw new TypeError('Agent job goal is required');
    const explicitId = input.jobId == null || input.jobId === '' ? null : requireIdentityString(input.jobId, 'Agent job id');
    let id = explicitId || autoJobId();
    while (true) {
      if (this.creatingIds.has(id)) {
        if (explicitId) throw new Error(`Agent job id already exists: ${id}`);
        id = autoJobId();
        continue;
      }
      this.creatingIds.add(id);
      let existing;
      try {
        existing = await this.get(id);
      } catch (error) {
        this.creatingIds.delete(id);
        throw error;
      }
      if (!existing) break;
      this.creatingIds.delete(id);
      if (explicitId) throw new Error(`Agent job id already exists: ${id}`);
      id = autoJobId();
    }
    try {
      const job = {
        version: CHECKPOINT_VERSION, id,
        status: 'ready', goal, effectiveScope: input.scope || 'auto',
        conversationId: input.conversationId == null ? null : String(input.conversationId), sessionId: input.sessionId || null,
        provider: input.provider || null, model: input.model || null, reasoning: input.reasoning || null,
        evidenceIds: [], hypothesisIds: [], completedTools: [], continuationRefs: [], unresolvedWork: [],
        budgetUsage: { slices: 0, modelCalls: 0, toolCalls: 0, elapsedMs: 0, contextBytes: 0 },
        limits: { maxSlices: bounded(input.maxSlices || this.maxSlices, 1, 32), maxElapsedMs: bounded(input.maxElapsedMs || this.maxElapsedMs, 1000, 4 * 60 * 60 * 1000) },
        request: safeRequest(input), lastResult: null, createdAt: now, updatedAt: now,
      };
      this.jobs.set(job.id, job); await this.save(job); return checkpoint(job);
    } finally {
      this.creatingIds.delete(id);
    }
  }

  async runSlice(jobOrId, options = {}) {
    const job = await this.require(jobOrId);
    const id = job.id;
    if (this.runningJobIds.has(id)) throw new Error('Agent job already has an active slice');
    this.runningJobIds.add(id);
    try {
      if (job.status === 'complete' || job.status === 'hard-limit') return checkpoint(job);
      if (job.status === 'running') throw new Error('Agent job already has an active slice');
      if (hardLimit(job)) {
        const prevStatus = job.status;
        job.status = 'hard-limit';
        job.updatedAt = new Date().toISOString();
        try {
          await this.save(job);
        } catch (saveError) {
          job.status = prevStatus;
          throw saveError;
        }
        return checkpoint(job);
      }
      const prevStatus = job.status;
      job.status = 'running';
      try {
        await this.save(job);
      } catch (saveError) {
        job.status = prevStatus;
        throw saveError;
      }
      let result;
      try {
        result = await this.runtime.turn({
          ...job.request, goal: job.goal, mode: 'agent', scope: job.effectiveScope,
          sessionId: job.sessionId, conversationId: job.conversationId,
          provider: job.provider, model: job.model, reasoning: job.reasoning,
        }, options);
      } catch (error) {
        job.status = options.signal?.aborted ? 'checkpointed' : 'failed';
        job.unresolvedWork = unique([...job.unresolvedWork, String(error?.message || error)]).slice(-32);
        job.updatedAt = new Date().toISOString();
        try {
          await this.save(job);
        } catch {}
        throw error;
      }
      mergeResult(job, result);
      if (!result?.limits?.exhausted) job.status = 'complete';
      else if (hardLimit(job)) job.status = 'hard-limit';
      else job.status = 'checkpointed';
      job.updatedAt = new Date().toISOString();
      try {
        await this.save(job);
      } catch (saveError) {
        job.unresolvedWork = unique([...job.unresolvedWork, `checkpoint-save-failed:${String(saveError?.message || saveError)}`]).slice(-32);
        throw saveError;
      }
      return checkpoint(job);
    } finally {
      this.runningJobIds.delete(id);
    }
  }

  async resume(id, options = {}) { return this.runSlice(id, options); }
  async get(id) {
    if (typeof id !== 'string') return null;
    return this.jobs.get(id) || await this.load(id);
  }
  list() { return [...this.jobs.values()].map(checkpoint); }

  async require(value) {
    let id;
    if (value && typeof value === 'object') {
      id = value.id;
    } else {
      id = value;
    }
    if (typeof id !== 'string' || !id) throw new Error(`Unknown agent job: ${value}`);
    let job = await this.get(id);
    if (!job && value && typeof value === 'object' && validateCheckpoint(value, id)) {
      this.jobs.set(id, value);
      job = value;
    }
    if (!job) throw new Error(`Unknown agent job: ${id}`);
    return job;
  }
  async load(id) {
    if (typeof id !== 'string' || !id) return null;
    if (this.loadingPromises.has(id)) return this.loadingPromises.get(id);
    const promise = (async () => {
      let value;
      try {
        value = await this.persistence?.load?.(id);
      } catch {
        return null;
      }
      if (validateCheckpoint(value, id)) {
        this.jobs.set(id, value);
        return value;
      }
      return null;
    })();
    this.loadingPromises.set(id, promise);
    try {
      return await promise;
    } finally {
      this.loadingPromises.delete(id);
    }
  }
  async save(job) { await this.persistence?.save?.(checkpoint(job)); }
}

function mergeResult(job, result) {
  job.sessionId = result?.sessionId || job.sessionId;
  job.effectiveScope = result?.scope?.effective || job.effectiveScope;
  job.evidenceIds = unique([...job.evidenceIds, ...(result?.evidence || []).map((item) => identityString(item?.id)).filter(Boolean)]);
  job.hypothesisIds = unique([...job.hypothesisIds, ...(result?.hypotheses || []).map((item) => identityString(item?.id)).filter(Boolean)]);
  job.completedTools = unique([...job.completedTools, ...(result?.activity || []).filter((item) => item.type === 'tool-result').map((item) => identityString(item?.tool) || identityString(item?.label)).filter(Boolean)]);
  job.continuationRefs = unique([...job.continuationRefs, ...collectRefs(result)]);
  job.unresolvedWork = unique([...(result?.followups || []), ...(result?.limits?.exhausted ? [`resume-after:${result.limits.reason || 'slice-budget'}`] : [])]).slice(-32);
  const usage = result?.usage || {};
  job.budgetUsage.slices += 1; job.budgetUsage.modelCalls += Number(usage.modelCalls || 0); job.budgetUsage.toolCalls += Number(usage.toolCalls || 0);
  job.budgetUsage.elapsedMs += Number(usage.elapsedMs || 0); job.budgetUsage.contextBytes += Number(usage.contextBytes || 0);
  job.lastResult = compactResult(result);
}
function collectRefs(result) {
  const refs = [];
  for (const item of result?.evidence || []) {
    for (const key of ['detailRef', 'continuationRef', 'cursor']) {
      const ref = identityString(item?.[key]);
      if (ref) refs.push(ref);
    }
  }
  return refs;
}
function identityString(value) { return typeof value === 'string' && value ? value : null; }
function requireIdentityString(value, label) {
  if (typeof value !== 'string' || !value) throw new TypeError(`${label} must be a non-empty string`);
  return value;
}
function hardLimit(job) { return job.budgetUsage.slices >= job.limits.maxSlices || job.budgetUsage.elapsedMs >= job.limits.maxElapsedMs; }
function compactResult(result) { return { answer: result?.answer || '', confidence: result?.confidence ?? null, limits: result?.limits || { exhausted: false }, usage: result?.usage || {}, sessionId: result?.sessionId || null }; }
function checkpoint(job) { return JSON.parse(JSON.stringify(job)); }
function unique(values) { return [...new Set(values)]; }
function bounded(value, min, max) { const n = Number(value); return Number.isFinite(n) ? Math.max(min, Math.min(max, Math.floor(n))) : min; }
const VALID_STATUSES = new Set(['ready', 'running', 'checkpointed', 'complete', 'failed', 'hard-limit']);
function isValidNumber(n, min = 0) { return typeof n === 'number' && Number.isFinite(n) && n >= min; }
function validateCheckpoint(value, expectedId = null) {
  if (!value || typeof value !== 'object') return false;
  if (value.version !== CHECKPOINT_VERSION) return false;
  if (typeof value.id !== 'string' || !value.id) return false;
  if (expectedId !== null && value.id !== expectedId) return false;
  if (!VALID_STATUSES.has(value.status)) return false;
  if (typeof value.goal !== 'string' || !value.goal) return false;
  const bu = value.budgetUsage;
  if (!bu || typeof bu !== 'object') return false;
  if (!isValidNumber(bu.slices) || !isValidNumber(bu.modelCalls) || !isValidNumber(bu.toolCalls) || !isValidNumber(bu.elapsedMs) || !isValidNumber(bu.contextBytes)) return false;
  const lim = value.limits;
  if (!lim || typeof lim !== 'object') return false;
  if (!isValidNumber(lim.maxSlices, 1) || !isValidNumber(lim.maxElapsedMs, 1000)) return false;
  if (!Array.isArray(value.evidenceIds) || !Array.isArray(value.hypothesisIds) || !Array.isArray(value.completedTools) || !Array.isArray(value.continuationRefs) || !Array.isArray(value.unresolvedWork)) return false;
  return true;
}
function autoJobId() { return `agent_job_${Date.now().toString(36)}_${randomId()}`; }
function randomId() {
  const bytes = new Uint8Array(6);
  if (typeof globalThis.crypto?.getRandomValues === 'function') globalThis.crypto.getRandomValues(bytes);
  else {
    const sequence = fallbackRandomSequence++ & 0xffffffffffffn;
    for (let i = 0; i < bytes.length; i++) bytes[bytes.length - 1 - i] = Number((sequence >> BigInt(i * 8)) & 0xffn);
  }
  return Array.from(bytes, (v) => v.toString(16).padStart(2, '0')).join('');
}
function safeRequest(input) {
  const out = {};
  for (const key of ['style', 'task', 'intent', 'budget', 'maxSearchResults', 'plannerTimeoutMs']) if (input[key] != null) out[key] = input[key];
  return out;
}

export function createAgentJobManager(options) { return new AgentJobManager(options); }
