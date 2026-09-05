import { DebugAdapterError } from '../debug/adapter.js';
import { DebugAdapterRuntimeProvider } from './provider.js';
import { RuntimeEventNormalizer } from './events.js';
import { createInterventionRecord, InterventionLedger } from './evidence-bridge.js';
import { RuntimeModuleBindingTable } from './provider-identity.js';
import { normalizeRuntimeModuleBinding } from './module-binding.js';

function moduleFields(event) {
  const payload = event?.payload && typeof event.payload === 'object' ? event.payload : {};
  const module = payload.module && typeof payload.module === 'object' ? payload.module : payload;
  return module;
}

function validateInterventionDraft(ledger, input) {
  const record = createInterventionRecord(input);
  for (const parent of record.parentInterventionIds) {
    if (!ledger.get(parent)) throw new DebugAdapterError('runtime-intervention-parent-missing', `intervention parent not found: ${parent}`);
  }
  return record;
}

function moduleBindingKey(module, index) {
  return module?.bindingKey ?? module?.moduleKey ?? module?.id ?? module?.uuid ?? module?.name ?? `module:${index}`;
}

function sameStructuredIdentity(left, right) {
  if (Object.is(left, right)) return true;
  if (left == null || right == null || typeof left !== 'object' || typeof right !== 'object') return false;
  try {
    const encode = (value) => JSON.stringify(value, (_key, item) => typeof item === 'bigint' ? `${item}n` : item);
    return encode(left) === encode(right);
  } catch {
    return false;
  }
}

function sameModuleBinding(current, next) {
  if (!current || !next) return false;
  // Module identity fields are authority-bearing scalars. Structured values do
  // not get a string sentinel: a legitimate provider string such as
  // "malformed:object" must never compare equal to a malformed object. A fresh
  // Symbol also ensures two malformed snapshots are never treated as stable
  // trusted identity and will be revalidated by the load path.
  const scalar = (value) => {
    if (value == null) return null;
    if (!['string', 'number', 'bigint'].includes(typeof value)) return Symbol('malformed-module-binding');
    return String(value);
  };
  const currentEvidence = current.identityEvidenceIds ?? [];
  const nextEvidence = next.identityEvidenceIds ?? [];
  return scalar(current.runtimeBase) === scalar(next.runtimeBase)
    && scalar(current.runtimeSize) === scalar(next.runtimeSize)
    && scalar(current.staticBase) === scalar(next.staticBase)
    && scalar(current.pathHint) === scalar(next.pathHint)
    && scalar(current.binaryId) === scalar(next.binaryId)
    && scalar(current.sliceId) === scalar(next.sliceId)
    && scalar(current.imageId) === scalar(next.imageId)
    && scalar(current.identityState) === scalar(next.identityState)
    && sameStructuredIdentity(current.buildIdentity, next.buildIdentity)
    && currentEvidence.length === nextEvidence.length
    && currentEvidence.every((value, index) => value === nextEvidence[index]);
}

export class DebuggerProvider extends DebugAdapterRuntimeProvider {
  constructor(adapter, options = {}) {
    super(adapter, { ...options, kind: options.kind ?? adapter?.kind ?? 'debugger' });
    this.eventOptions = options.events || {};
  }

  async openSession(request = {}, options = {}) {
    const session = await super.openSession(request, options);
    const normalizer = new RuntimeEventNormalizer({
      runtimeSessionId: session.runtimeSessionId,
      providerId: session.providerId,
      providerVersion: session.providerVersion,
      sessionEpoch: session.epoch,
      processKey: session.target.processKey,
    }, this.eventOptions);
    const interventions = new InterventionLedger();
    let unsubscribe = null;

    const ingest = (raw) => {
      const event = normalizer.push(raw);
      if (!event) return null;
      const module = moduleFields(event);
      if (event.kind === 'module-load' && (module.runtimeBase ?? module.base) != null && (module.runtimeSize ?? module.size) != null) {
        const bindingKey = module.bindingKey ?? module.moduleKey ?? module.id ?? module.uuid ?? module.name;
        if (bindingKey) {
          const existing = session.modules.get(bindingKey);
          if (!existing) {
            session.modules.load(normalizeRuntimeModuleBinding(module, {
              bindingKey,
              loadedSequence: event.sequence,
            }));
          }
        }
      } else if (event.kind === 'module-unload') {
        const bindingKey = module.bindingKey ?? module.moduleKey ?? module.id ?? module.uuid ?? module.name;
        if (bindingKey) session.modules.unload(bindingKey, event.sequence);
      } else if (event.kind === 'paused' || event.kind === 'breakpoint-hit' || event.kind === 'watchpoint-hit') {
        session.setState('paused');
      } else if (event.kind === 'resumed') {
        session.setState('running');
      } else if (event.kind === 'provider-error') {
        session.setState('degraded');
      }
      return event;
    };

    try {
      if (typeof this.adapter.onEvent === 'function') {
        const maybe = this.adapter.onEvent(ingest);
        if (maybe != null && typeof maybe !== 'function') throw new DebugAdapterError('event-subscription', 'debugger adapter onEvent must return an unsubscribe function');
        unsubscribe = maybe || null;
      }
    } catch (error) {
      try { await session.close(); } catch {}
      throw error;
    }

    const originalDebugger = session.facets.debugger;
    const debuggerFacet = Object.freeze({
      ...originalDebugger,
      writeRegister: async (name, value, callOptions = {}) => {
        const draft = validateInterventionDraft(interventions, {
          runtimeSessionId: session.runtimeSessionId,
          providerId: session.providerId,
          kind: 'register-write',
          target: { register: String(name) },
          requestedChange: { value },
          parentInterventionIds: callOptions.parentInterventionIds ?? [],
        });
        const raw = await this.adapter.writeRegister(name, value, callOptions);
        const intervention = interventions.add({ ...draft, acknowledgedResult: raw });
        return { result: raw, intervention };
      },
      writeMemory: async (address, bytes, callOptions = {}) => {
        const draft = validateInterventionDraft(interventions, {
          runtimeSessionId: session.runtimeSessionId,
          providerId: session.providerId,
          kind: 'memory-write',
          target: { address },
          requestedChange: { bytes },
          parentInterventionIds: callOptions.parentInterventionIds ?? [],
        });
        const raw = await this.adapter.writeMemory(address, bytes, callOptions);
        const intervention = interventions.add({ ...draft, acknowledgedResult: raw });
        return { result: raw, intervention };
      },
      events: Object.freeze({
        ingest,
        flush: () => normalizer.flush(),
      }),
      interventions,
      resolveAddress: (runtimeAddress, resolutionOptions = {}) => session.modules.resolve(runtimeAddress, resolutionOptions),
      refreshModules: async () => {
        if (!this.adapter.capabilities?.modules || typeof this.adapter.getModules !== 'function') return session.modules.active();
        const modules = await this.adapter.getModules();
        if (!Array.isArray(modules)) throw new DebugAdapterError('runtime-invalid-modules', 'debugger adapter getModules must return an array');

        // Transactional commit: validate every canonical binding in a scratch
        // table before mutating the active table. Loading before Map insertion
        // is essential: duplicate normalized keys must reject rather than let a
        // later entry overwrite the earlier authority in `next`.
        const next = new Map();
        const scratch = new RuntimeModuleBindingTable(session.runtimeSessionId);
        const staged = new Map();
        for (let i = 0; i < modules.length; i++) {
          const module = modules[i] || {};
          if ((module.runtimeBase ?? module.base) == null || (module.runtimeSize ?? module.size) == null) continue;
          const bindingKey = moduleBindingKey(module, i);
          const normalized = normalizeRuntimeModuleBinding(module, { bindingKey });
          const validated = scratch.load({ ...normalized, bindingKey: normalized.bindingKey });
          next.set(normalized.bindingKey, normalized);
          staged.set(normalized.bindingKey, validated);
        }

        for (const active of session.modules.active()) {
          if (!next.has(active.bindingKey)) session.modules.unload(active.bindingKey);
        }
        for (const [bindingKey, normalized] of staged) {
          const active = session.modules.get(bindingKey);
          if (active && sameModuleBinding(active, normalized)) continue;
          if (active) session.modules.unload(bindingKey);
          session.modules.load(normalized);
        }
        return modules;
      },
    });
    session.facets = Object.freeze({ ...session.facets, debugger: debuggerFacet });

    const originalClose = session.close.bind(session);
    session.close = async () => {
      if (typeof unsubscribe === 'function') { try { unsubscribe(); } catch {} }
      unsubscribe = null;
      return originalClose();
    };
    session.newProviderEpoch = (reason = 'debugger-provider-epoch-changed') => {
      if (session.closed) throw new DebugAdapterError('runtime-session-closed', 'runtime provider session is closed');
      const next = session.epoch + 1;
      if (typeof this.adapter.setEpoch === 'function') this.adapter.setEpoch(next);
      else if (typeof this.adapter.nextEpoch === 'function') this.adapter.nextEpoch();
      const committed = session.newEpoch(reason);
      normalizer.resetEpoch(committed);
      return committed;
    };
    return session;
  }
}

export function createDebuggerProvider(adapter, options = {}) {
  return new DebuggerProvider(adapter, options);
}