import { EVIDENCE_COMPLETENESS } from '../core/evidence/index.js';
import { deepFreeze, jsonSafe, stableDigest, stableStringify } from '../core/identity/index.js';
import { DebugAdapterError } from '../debug/adapter.js';

export const RUNTIME_OBSERVATION_MODES = Object.freeze(['observed', 'intervened', 'synthetic']);
export const RUNTIME_EVENT_KINDS = Object.freeze([
  'session-open', 'session-close',
  'process-start', 'process-exit',
  'thread-start', 'thread-exit',
  'module-load', 'module-unload',
  'paused', 'resumed',
  'breakpoint-hit', 'watchpoint-hit',
  'exception', 'signal',
  'call', 'return', 'basic-block',
  'memory-read', 'memory-write', 'register-snapshot',
  'instrumentation-observation', 'instrumentation-intervention',
  'emulator-checkpoint', 'trace-marker',
  'gap', 'dropped-events', 'provider-warning', 'provider-error',
]);

const COMPLETENESS_RANK = Object.freeze({ unsupported: 0, truncated: 1, partial: 2, bounded: 3, complete: 4 });
const UTF8_ENCODER = new TextEncoder();

function encodedByteLength(value) { return UTF8_ENCODER.encode(value).byteLength; }

function required(value, code, message) {
  if (typeof value !== 'string') throw new DebugAdapterError(code, message || code);
  const text = value.trim();
  if (!text) throw new DebugAdapterError(code, message || code);
  return text;
}

function safeInteger(value, fallback, name, { min = 0 } = {}) {
  if (value == null) return fallback;
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < min) {
    throw new DebugAdapterError('runtime-invalid-event-integer', `${name} must be a safe integer >= ${min}`);
  }
  return value;
}

function optionalText(value) { return value == null ? null : String(value); }

function optionalIdentity(value, name) {
  if (value == null) return null;
  if (typeof value !== 'string' || value.trim().length === 0) throw new DebugAdapterError('runtime-invalid-event-identity', `${name} must be a non-empty string`);
  return value;
}

function arrayOfStrings(value, name) {
  if (value == null) return Object.freeze([]);
  if (!Array.isArray(value)) throw new DebugAdapterError('runtime-invalid-event-array', `${name} must be an array`);
  for (const item of value) {
    if (typeof item !== 'string' || item.trim().length === 0) throw new DebugAdapterError('runtime-invalid-event-array', `${name} must contain only non-empty strings`);
  }
  return Object.freeze([...new Set(value)]);
}

function normalizeCompleteness(value, fallback = 'partial') {
  const completeness = value == null ? fallback : value;
  if (typeof completeness !== 'string' || !EVIDENCE_COMPLETENESS.includes(completeness)) {
    throw new DebugAdapterError('runtime-invalid-completeness', `invalid runtime completeness type: ${typeof completeness}`);
  }
  return completeness;
}

function normalizeKind(value) {
  const kind = required(value, 'runtime-event-kind-required', 'runtime event kind is required');
  if (!RUNTIME_EVENT_KINDS.includes(kind)) throw new DebugAdapterError('runtime-invalid-event-kind', `invalid runtime event kind: ${kind}`);
  return kind;
}

function normalizeMode(value) {
  const mode = value == null ? 'observed' : value;
  if (typeof mode !== 'string' || !RUNTIME_OBSERVATION_MODES.includes(mode)) {
    throw new DebugAdapterError('runtime-invalid-observation-mode', `invalid runtime observation mode type: ${typeof mode}`);
  }
  return mode;
}

function dedupeIdentity(input) {
  if (input.providerEventId != null) return `provider:${input.providerEventId}`;
  if (input.streamId != null && input.sequence != null) return `stream:${input.streamId}:${input.sequence}`;
  return null;
}

export function createRuntimeEvent(input = {}) {
  const runtimeSessionId = required(input.runtimeSessionId, 'runtime-session-id-required', 'runtime event requires runtimeSessionId');
  const providerId = required(input.providerId, 'runtime-provider-required', 'runtime event requires providerId');
  const providerVersion = input.providerVersion ?? '1';
  if (typeof providerVersion !== 'string') throw new DebugAdapterError('runtime-invalid-provider-version', 'providerVersion must be a string');
  const sessionEpoch = safeInteger(input.sessionEpoch, 1, 'sessionEpoch', { min: 1 });
  const sequence = input.sequence == null ? null : safeInteger(input.sequence, null, 'sequence');
  const moduleGeneration = input.moduleGeneration == null ? null : safeInteger(input.moduleGeneration, null, 'moduleGeneration', { min: 1 });
  const kind = normalizeKind(input.kind);
  const observationMode = normalizeMode(input.observationMode);
  const completeness = normalizeCompleteness(input.completeness, kind === 'gap' || kind === 'dropped-events' ? 'truncated' : 'partial');
  const payload = jsonSafe(input.payload ?? {});
  const identity = {
    runtimeSessionId,
    providerId,
    providerVersion,
    sessionEpoch,
    streamId: optionalIdentity(input.streamId, 'streamId'),
    sequence,
    providerEventId: optionalIdentity(input.providerEventId, 'providerEventId'),
    kind,
    processKey: optionalText(input.processKey),
    threadKey: optionalText(input.threadKey),
    moduleBindingKey: optionalText(input.moduleBindingKey),
    moduleGeneration,
    payload,
  };
  const eventId = input.eventId == null
    ? `runtimeevent_${stableDigest(identity)}`
    : required(input.eventId, 'runtime-event-id-invalid', 'runtime event id must be a non-empty string');
  return deepFreeze({
    eventId,
    runtimeSessionId,
    providerId,
    providerVersion,
    sessionEpoch,
    streamId: optionalIdentity(input.streamId, 'streamId'),
    sequence,
    predecessorIds: arrayOfStrings(input.predecessorIds, 'predecessorIds'),
    providerEventId: optionalIdentity(input.providerEventId, 'providerEventId'),
    timestamp: input.timestamp == null ? null : String(input.timestamp),
    processKey: optionalText(input.processKey),
    threadKey: optionalText(input.threadKey),
    moduleBindingKey: optionalText(input.moduleBindingKey),
    moduleGeneration,
    kind,
    payload,
    observationMode,
    completeness,
    interventionIds: arrayOfStrings(input.interventionIds, 'interventionIds'),
  });
}

export function normalizeLegacyRuntimeEvent(input, context = {}) {
  const protocolEnvelope = input && input.type === 'event' && typeof input.event === 'string';
  const source = protocolEnvelope
    ? (input.data && typeof input.data === 'object' && !Array.isArray(input.data) ? input.data : {})
    : (input && input.type === 'event' && input.event ? input.event : input);
  if (!source || typeof source !== 'object') throw new DebugAdapterError('runtime-invalid-event', 'legacy runtime event must be an object');
  const rawLegacyType = protocolEnvelope ? input.event : (source.kind ?? source.type ?? 'trace-marker');
  const legacyType = typeof rawLegacyType === 'string' ? rawLegacyType : 'trace-marker';
  const kindMap = {
    branch: 'basic-block',
    trace: 'trace-marker',
    warning: 'provider-warning',
    error: 'provider-error',
    'stream-truncated': 'gap',
  };
  const kind = RUNTIME_EVENT_KINDS.includes(legacyType) ? legacyType : (kindMap[legacyType] || 'trace-marker');
  const truncated = input?.truncated === true || source.truncated === true || legacyType === 'stream-truncated';
  const envelopeValue = (key) => protocolEnvelope && input[key] != null ? input[key] : source[key];
  return createRuntimeEvent({
    runtimeSessionId: context.runtimeSessionId,
    providerId: context.providerId,
    providerVersion: context.providerVersion,
    sessionEpoch: envelopeValue('epoch') ?? context.sessionEpoch ?? 1,
    streamId: envelopeValue('streamId') ?? context.streamId,
    sequence: envelopeValue('sequence'),
    providerEventId: envelopeValue('providerEventId') ?? envelopeValue('id'),
    timestamp: envelopeValue('timestamp'),
    processKey: envelopeValue('processKey') ?? context.processKey,
    threadKey: envelopeValue('threadKey'),
    moduleBindingKey: envelopeValue('moduleBindingKey'),
    moduleGeneration: envelopeValue('moduleGeneration'),
    kind,
    payload: protocolEnvelope ? (input.data ?? {}) : (source.payload ?? source),
    observationMode: envelopeValue('observationMode') ?? context.observationMode ?? 'observed',
    completeness: envelopeValue('completeness') ?? (truncated ? 'truncated' : context.completeness ?? 'partial'),
    predecessorIds: envelopeValue('predecessorIds'),
    interventionIds: envelopeValue('interventionIds'),
  });
}

export function createRuntimeEventBatch(input = {}) {
  const rawEvents = input.events == null ? [] : input.events;
  if (!Array.isArray(rawEvents)) throw new DebugAdapterError('runtime-invalid-event-array', 'events must be an array');
  const events = rawEvents.map((event) => createRuntimeEvent(event));
  const dropped = safeInteger(input.dropped, 0, 'dropped');
  const runtimeSessionId = required(input.runtimeSessionId ?? events[0]?.runtimeSessionId, 'runtime-session-id-required', 'runtime event batch requires runtimeSessionId');
  const providerId = required(input.providerId ?? events[0]?.providerId, 'runtime-provider-required', 'runtime event batch requires providerId');
  const sessionEpoch = safeInteger(input.sessionEpoch ?? events[0]?.sessionEpoch, 1, 'sessionEpoch', { min: 1 });

  for (const event of events) {
    if (event.runtimeSessionId !== runtimeSessionId || event.providerId !== providerId || event.sessionEpoch !== sessionEpoch) {
      throw new DebugAdapterError('runtime-event-batch-identity-mismatch', 'All events in a batch must match batch runtimeSessionId, providerId, and sessionEpoch');
    }
  }

  const hasLoss = dropped > 0 || events.some((event) => event.kind === 'gap' || event.kind === 'dropped-events' || event.completeness === 'truncated');
  const requested = normalizeCompleteness(input.completeness, hasLoss ? 'truncated' : 'partial');
  let strongestAllowed = hasLoss ? 'truncated' : 'complete';
  for (const event of events) {
    if (COMPLETENESS_RANK[event.completeness] < COMPLETENESS_RANK[strongestAllowed]) strongestAllowed = event.completeness;
  }
  if (COMPLETENESS_RANK[requested] > COMPLETENESS_RANK[strongestAllowed]) {
    throw new DebugAdapterError('runtime-completeness-upgrade', `event batch cannot upgrade ${strongestAllowed} source evidence to ${requested}`);
  }
  return deepFreeze({
    runtimeSessionId,
    providerId,
    sessionEpoch,
    events: Object.freeze(events),
    completeness: requested,
    dropped,
  });
}

export class RuntimeEventNormalizer {
  #queue = [];
  #seen = new Set();
  #dropped = 0;

  constructor(context = {}, options = {}) {
    this.context = { ...context };
    this.maxEvents = safeInteger(options.maxEvents, 4096, 'maxEvents', { min: 1 });
    this.maxBytes = safeInteger(options.maxBytes, 4 * 1024 * 1024, 'maxBytes', { min: 1024 });
    this.maxDedupeEntries = safeInteger(options.maxDedupeEntries, Math.max(8192, this.maxEvents * 2), 'maxDedupeEntries', { min: 16 });
    this.queuedBytes = 0;
  }

  push(input) {
    const hasDirectIdentity = input && typeof input === 'object'
      && ['runtimeSessionId', 'providerId', 'sessionEpoch'].some((key) => Object.hasOwn(input, key));
    const event = hasDirectIdentity ? createRuntimeEvent(input) : normalizeLegacyRuntimeEvent(input, this.context);
    const contextRuntimeSessionId = required(this.context.runtimeSessionId, 'runtime-session-id-required', 'runtime event batch requires runtimeSessionId');
    const contextProviderId = required(this.context.providerId, 'runtime-provider-required', 'runtime event batch requires providerId');
    const contextEpoch = safeInteger(this.context.sessionEpoch, event.sessionEpoch, 'sessionEpoch', { min: 1 });
    if (event.runtimeSessionId !== contextRuntimeSessionId || event.providerId !== contextProviderId || event.sessionEpoch !== contextEpoch) return null;
    const dedupe = dedupeIdentity(event);
    const scoped = dedupe ? `${event.sessionEpoch}:${dedupe}` : null;
    if (scoped && this.#seen.has(scoped)) return null;
    const bytes = encodedByteLength(stableStringify(event));
    if (this.#queue.length >= this.maxEvents || this.queuedBytes + bytes > this.maxBytes) {
      this.#dropped++;
      return null;
    }
    if (scoped) {
      if (this.#seen.size >= this.maxDedupeEntries) {
        const first = this.#seen.values().next().value;
        if (first !== undefined) this.#seen.delete(first);
      }
      this.#seen.add(scoped);
    }
    this.#queue.push(event);
    this.queuedBytes += bytes;
    return event;
  }

  flush() {
    const events = this.#queue;
    this.#queue = [];
    this.queuedBytes = 0;
    const dropped = this.#dropped;
    this.#dropped = 0;
    if (dropped > 0) {
      events.unshift(createRuntimeEvent({
        ...this.context,
        kind: 'dropped-events',
        payload: { dropped },
        observationMode: 'observed',
        completeness: 'truncated',
      }));
    }
    return createRuntimeEventBatch({
      runtimeSessionId: this.context.runtimeSessionId,
      providerId: this.context.providerId,
      sessionEpoch: this.context.sessionEpoch ?? 1,
      events,
      completeness: dropped > 0 ? 'truncated' : (events.length ? 'partial' : 'bounded'),
      dropped,
    });
  }

  resetEpoch(epoch) {
    this.context.sessionEpoch = safeInteger(epoch, null, 'sessionEpoch', { min: 1 });
    this.#queue = [];
    this.queuedBytes = 0;
    this.#dropped = 0;
    this.#seen.clear();
  }
}
