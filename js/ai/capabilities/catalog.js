const HUMAN_ONLY_REASONS = Object.freeze({
  FILE_PICKER: 'browser-security-user-gesture: opening a system file picker requires a trusted human gesture',
  OS_DEBUG_TRANSPORT: 'external-os-facility-unavailable: the browser cannot create an OS debugger transport by itself',
  VISUAL_SETTING: 'inherently-visual-only-setting: this appearance choice has no deterministic analysis effect',
});

const READ_SCOPES = Object.freeze(['auto', 'selection', 'function', 'neighborhood', 'binary', 'project']);
const MUTATION_SCOPES = Object.freeze(['function', 'binary', 'project']);

// Executor-facing input contracts for the built-in capabilities. The executor
// runs assertSchema(args, entry.inputSchema) before any mutation, so each
// schema must require exactly what executeBuiltIn reads; missing fields are
// rejected as invalid_tool_call instead of surfacing as native TypeError from
// BigInt(undefined) deeper in the executor (#6257).
const ADDRESS_FIELD = Object.freeze({ type: ['string', 'integer'] });
const VALUE_FIELD = Object.freeze({ type: 'string' });
const BINARY_ID_FIELD = Object.freeze({ type: 'string' });
const RUNTIME_SESSION_FIELD = Object.freeze({ type: 'string' });
const BYTE_ARRAY_FIELD = Object.freeze({ type: 'array', items: { type: 'integer', minimum: 0, maximum: 255 } });
const ADDRESS_VALUE_SCHEMA = Object.freeze({
  type: 'object', additionalProperties: false,
  properties: { address: ADDRESS_FIELD, value: VALUE_FIELD, binaryId: BINARY_ID_FIELD },
  required: ['address', 'value'],
});

function schema(extra = {}) {
  return {
    type: 'object', additionalProperties: false, properties: {}, required: [], ...extra,
  };
}

const RUNTIME_BINDING_PROPERTIES = Object.freeze({ runtimeSessionId: RUNTIME_SESSION_FIELD, binaryId: BINARY_ID_FIELD });
function runtimeSchema(extra = {}) {
  return schema({
    ...extra,
    properties: { ...RUNTIME_BINDING_PROPERTIES, ...(extra.properties || {}) },
    required: Array.from(new Set(['runtimeSessionId', ...(extra.required || [])])),
  });
}

const BREAKPOINT_FIELDS = Object.freeze({
  kind: Object.freeze({ type: 'string', enum: ['address', 'function', 'conditional', 'memory'] }),
  id: VALUE_FIELD,
  address: ADDRESS_FIELD,
  function: VALUE_FIELD,
  condition: VALUE_FIELD,
  size: Object.freeze({ type: 'integer', minimum: 1, maximum: 4096 }),
  access: Object.freeze({ type: 'string', enum: ['read', 'write', 'readwrite'] }),
  enabled: Object.freeze({ type: 'boolean' }),
});
const BREAKPOINT_SPEC_SCHEMA = Object.freeze({ anyOf: [
  schema({ properties: { ...BREAKPOINT_FIELDS, kind: { const: 'address' } }, required: ['address'] }),
  schema({ properties: { ...BREAKPOINT_FIELDS, kind: { const: 'function' } }, required: ['function'] }),
  schema({ properties: { ...BREAKPOINT_FIELDS, kind: { const: 'conditional' } }, required: ['kind', 'address', 'condition'] }),
  schema({ properties: { ...BREAKPOINT_FIELDS, kind: { const: 'memory' } }, required: ['kind', 'address'] }),
] });
const BREAKPOINT_CREATE_SCHEMA = Object.freeze({ anyOf: [
  runtimeSchema({ properties: { breakpoint: BREAKPOINT_SPEC_SCHEMA }, required: ['breakpoint'] }),
  runtimeSchema({ properties: { ...BREAKPOINT_FIELDS, kind: { const: 'address' } }, required: ['address'] }),
  runtimeSchema({ properties: { ...BREAKPOINT_FIELDS, kind: { const: 'function' } }, required: ['function'] }),
  runtimeSchema({ properties: { ...BREAKPOINT_FIELDS, kind: { const: 'conditional' } }, required: ['kind', 'address', 'condition'] }),
  runtimeSchema({ properties: { ...BREAKPOINT_FIELDS, kind: { const: 'memory' } }, required: ['kind', 'address'] }),
] });
const WATCHPOINT_SPEC_SCHEMA = Object.freeze(schema({
  properties: BREAKPOINT_FIELDS,
  required: ['address'],
}));
const WATCHPOINT_CREATE_SCHEMA = Object.freeze({ anyOf: [
  runtimeSchema({ properties: { watchpoint: WATCHPOINT_SPEC_SCHEMA }, required: ['watchpoint'] }),
  runtimeSchema({ properties: BREAKPOINT_FIELDS, required: ['address'] }),
] });
const EXPERIMENT_SCHEMA = Object.freeze({
  type: 'object', additionalProperties: true,
  properties: { cases: { type: 'array' } },
  required: ['cases'],
});

// Default runtime-mutation schema: the executor reads runtimeSessionId (and
// optionally binaryId) for every runtime-bound mutation.
const RUNTIME_SESSION_SCHEMA = Object.freeze(runtimeSchema());

function capability(id, category, description, extra = {}) {
  return Object.freeze({
    id, category, description,
    mutability: 'read-only', risk: 'low', reversible: false, requiresApproval: false,
    scopeSupport: READ_SCOPES, inputSchema: { type: 'object', additionalProperties: true },
    humanSurface: id, agentExposed: true, ...extra,
  });
}

const ANALYSIS_TOOLS = [
  ['analysis.search-functions', 'search_functions'], ['analysis.search-strings', 'search_strings'],
  ['analysis.get-function', 'get_function'], ['analysis.decompile-function', 'decompile_function'], ['analysis.semantic-facts', 'get_semantic_facts'],
  ['analysis.cfg', 'get_cfg'], ['analysis.callers', 'get_callers'], ['analysis.callees', 'get_callees'],
  ['analysis.xrefs', 'get_xrefs'], ['analysis.value-trace', 'trace_value'],
  ['analysis.backward-slice', 'slice_backward'], ['analysis.forward-slice', 'slice_forward'],
  ['analysis.symbolic-execution', 'symbolic_execute'], ['analysis.known-function', 'lookup_known_function'],
  ['analysis.binary-diff', 'get_binary_diff'], ['analysis.runtime-observations', 'get_runtime_observations'],
  ['analysis.verify-runtime-hypothesis', 'verify_runtime_hypothesis'],
].map(([id, agentTool]) => capability(id, 'analysis', `Deterministic ${id.slice(9).replaceAll('-', ' ')} operation.`, { agentTool }));

const NAVIGATION = [
  ['navigation.open-function', 'open-function'], ['navigation.open-address', 'open-address'],
  ['navigation.show-xrefs', 'show-xrefs'], ['navigation.show-callers', 'show-callers'],
  ['navigation.show-callees', 'show-callees'], ['navigation.show-cfg', 'show-cfg'],
  ['navigation.show-pseudocode', 'show-pseudocode'], ['navigation.trace-value', 'trace-value'],
  ['navigation.open-evidence', 'open-evidence'],
].map(([id, actionKind]) => capability(id, 'navigation', `Navigate the workbench using ${actionKind}.`, {
  actionKind, mutability: 'navigation', reversible: true,
  inputSchema: { type: 'object', additionalProperties: false, properties: { address: { type: ['string', 'integer'] }, target: { type: 'string' } } },
}));

const CATALOG = Object.freeze([
  ...ANALYSIS_TOOLS, ...NAVIGATION,
  capability('annotation.rename', 'annotation', 'Rename a symbol after an approved proposal.', mutation({ reversible: true, inputSchema: ADDRESS_VALUE_SCHEMA })),
  capability('annotation.comment', 'annotation', 'Set a disassembly comment after an approved proposal.', mutation({ reversible: true, inputSchema: ADDRESS_VALUE_SCHEMA })),
  capability('annotation.set-type', 'annotation', 'Set a recovered or manual type after an approved proposal.', mutation({
    reversible: true,
    inputSchema: schema({
      properties: { address: ADDRESS_FIELD, key: VALUE_FIELD, value: VALUE_FIELD, binaryId: BINARY_ID_FIELD },
      required: ['address', 'value'],
    }),
  })),
  capability('annotation.struct-field', 'annotation', 'Define or update a structure field after an approved proposal.', mutation({
    reversible: true,
    inputSchema: schema({
      properties: {
        struct: VALUE_FIELD, name: VALUE_FIELD, offset: { type: 'integer', minimum: 0 },
        field: VALUE_FIELD, fieldName: VALUE_FIELD, type: VALUE_FIELD, binaryId: BINARY_ID_FIELD,
      },
      required: ['offset'],
    }),
  })),
  capability('annotation.project', 'annotation', 'Persist an analysis annotation in the project.', mutation({ reversible: true, scopeSupport: ['project'], inputSchema: schema({
    properties: { id: VALUE_FIELD, kind: VALUE_FIELD, value: {} },
  }) })),
  capability('patch.create', 'patch', 'Create a byte patch only after target and original-byte verification.', mutation({
    reversible: true, risk: 'high',
    inputSchema: schema({
      properties: {
        address: ADDRESS_FIELD, before: BYTE_ARRAY_FIELD, after: BYTE_ARRAY_FIELD, label: VALUE_FIELD, reason: VALUE_FIELD, instruction: { type: 'boolean' },
      },
      required: ['address', 'before', 'after'],
    }),
  })),
  capability('patch.preview', 'patch', 'Preview a validated patch without changing the patch set.', {
    inputSchema: schema({
      properties: { address: ADDRESS_FIELD, before: BYTE_ARRAY_FIELD, after: BYTE_ARRAY_FIELD, instruction: { type: 'boolean' } },
      required: ['address', 'before', 'after'],
    }),
  }),
  capability('patch.apply', 'patch', 'Apply the current verified patch set to an in-memory output Blob.', mutation({ reversible: true, risk: 'high', inputSchema: schema({
    properties: { file: {} },
  }) })),
  capability('patch.revert', 'patch', 'Remove a patch while preserving its revert metadata.', mutation({ reversible: true, risk: 'medium', inputSchema: schema({
    properties: { fileOffset: ADDRESS_FIELD },
    required: ['fileOffset'],
  }) })),
  capability('patch.inspect', 'patch', 'Inspect the current ordered patch set.'),
  capability('runtime.status', 'runtime', 'Read active runtime adapter and session status.'),
  capability('runtime.connect', 'runtime', 'Connect a known runtime adapter with an explicit binary binding.', { mutability: 'runtime-dangerous', risk: 'high', requiresApproval: true, scopeSupport: ['binary'], inputSchema: schema({
    properties: { adapter: VALUE_FIELD, binaryId: BINARY_ID_FIELD, trace: { type: 'object' } },
  }) }),
  capability('runtime.attach', 'runtime', 'Attach the active runtime adapter to a target.', runtimeMutation('high', false, runtimeSchema({
    properties: { target: { type: 'object' } },
  }))),
  capability('runtime.detach', 'runtime', 'Disconnect the bound runtime session.', runtimeMutation('medium', true)),
  capability('runtime.breakpoint-create', 'runtime', 'Create a bound runtime breakpoint.', runtimeMutation('medium', true, BREAKPOINT_CREATE_SCHEMA)),
  capability('runtime.breakpoint-remove', 'runtime', 'Remove a bound runtime breakpoint.', runtimeMutation('medium', true, runtimeSchema({
    properties: { id: ADDRESS_FIELD }, required: ['id'],
  }))),
  capability('runtime.watchpoint-create', 'runtime', 'Create a bound runtime memory watchpoint.', runtimeMutation('high', true, WATCHPOINT_CREATE_SCHEMA)),
  capability('runtime.watchpoint-remove', 'runtime', 'Remove a bound runtime watchpoint.', runtimeMutation('medium', true, runtimeSchema({
    properties: { id: ADDRESS_FIELD }, required: ['id'],
  }))),
  capability('runtime.continue', 'runtime', 'Continue the bound runtime session.', runtimeMutation('high')),
  capability('runtime.pause', 'runtime', 'Pause the bound runtime session.', runtimeMutation('medium', true)),
  capability('runtime.step-in', 'runtime', 'Step into one instruction in the bound runtime session.', runtimeMutation('medium')),
  capability('runtime.step-over', 'runtime', 'Step over one instruction in the bound runtime session.', runtimeMutation('medium')),
  capability('runtime.step-out', 'runtime', 'Step out of the current frame in the bound runtime session.', runtimeMutation('medium')),
  capability('runtime.registers', 'runtime', 'Read registers from the bound runtime session.', {
    runtimeBound: true, scopeSupport: ['function', 'binary'],
    inputSchema: runtimeSchema({ properties: { threadId: ADDRESS_FIELD } }),
  }),
  capability('runtime.memory-read', 'runtime', 'Read a bounded memory range from the bound runtime session.', {
    runtimeBound: true, scopeSupport: ['function', 'binary'],
    inputSchema: runtimeSchema({
      properties: { address: ADDRESS_FIELD, size: { type: 'integer', minimum: 1, maximum: 262144 } },
      required: ['address'],
    }),
  }),
  capability('runtime.memory-write', 'runtime', 'Write bounded runtime memory with expected-before and postcondition checks.', runtimeMutation('high', true, runtimeSchema({
    properties: {
      address: ADDRESS_FIELD, bytes: BYTE_ARRAY_FIELD, expectedBefore: BYTE_ARRAY_FIELD,
    },
    required: ['address', 'bytes', 'expectedBefore'],
  }))),
  capability('runtime.experiment', 'runtime', 'Run a deterministic runtime experiment and capture evidence.', runtimeMutation('high', false, runtimeSchema({
    properties: { experiment: EXPERIMENT_SCHEMA },
    required: ['experiment'],
  }))),
  capability('project.save', 'project', 'Autosave the current bound Hex project.', { mutability: 'reversible', reversible: true, scopeSupport: ['project'] }),
  capability('project.snapshot', 'project', 'Create an in-memory deterministic project snapshot.', { scopeSupport: ['project'] }),
  capability('project.restore-known', 'project', 'Restore a previously parsed, binary-matched project state.', mutation({ reversible: true, scopeSupport: ['project'], inputSchema: schema({
    properties: { project: { type: 'string' } },
    required: ['project'],
  }) })),
  capability('project.binary-diff', 'project', 'Run a binary diff against the already-loaded baseline.', { scopeSupport: ['project'], inputSchema: schema({
    properties: { options: { type: 'object' } },
  }) }),
  capability('project.export-report', 'project', 'Export deterministic analysis/report data without a file picker.', { scopeSupport: ['project'], inputSchema: schema({
    properties: {},
  }) }),
  capability('human.open-binary-file', 'human-only', 'Open a new binary through the browser file picker.', { agentExposed: false, humanOnlyReason: HUMAN_ONLY_REASONS.FILE_PICKER }),
  capability('human.create-debug-transport', 'human-only', 'Create an OS debugger transport outside the browser.', { agentExposed: false, humanOnlyReason: HUMAN_ONLY_REASONS.OS_DEBUG_TRANSPORT }),
  capability('human.appearance', 'human-only', 'Change theme or visual density.', { agentExposed: false, humanOnlyReason: HUMAN_ONLY_REASONS.VISUAL_SETTING }),
]);

function mutation(extra = {}) {
  return { mutability: 'mutation', risk: 'medium', reversible: false, requiresApproval: true, scopeSupport: MUTATION_SCOPES, ...extra };
}
function runtimeMutation(risk, reversible = false, inputSchema = RUNTIME_SESSION_SCHEMA) {
  return { mutability: 'runtime-dangerous', risk, reversible, requiresApproval: true, scopeSupport: ['function', 'binary'], runtimeBound: true, inputSchema };
}

function normalizeCapabilityId(value) {
  if (typeof value !== 'string') return null;
  const id = value.trim();
  return id || null;
}

function snapshotCapabilityEntry(entry, id) {
  const snapshot = {};
  for (const key of Reflect.ownKeys(entry)) {
    if (key === 'id') continue;
    const descriptor = Object.getOwnPropertyDescriptor(entry, key);
    if (descriptor?.enumerable) snapshot[key] = entry[key];
  }
  snapshot.id = id;
  return Object.freeze(snapshot);
}

export class CapabilityCatalog {
  constructor(entries = CATALOG) {
    const normalizedEntries = entries.map((entry) => {
      const rawId = entry?.id;
      const id = normalizeCapabilityId(rawId);
      if (!id) throw new Error('invalid capability id');
      return [id, snapshotCapabilityEntry(entry, id)];
    });
    this.entries = new Map(normalizedEntries);
    if (this.entries.size !== normalizedEntries.length) throw new Error('duplicate capability id');
  }
  get(id) { const normalized = normalizeCapabilityId(id); return normalized ? this.entries.get(normalized) || null : null; }
  has(id) { const normalized = normalizeCapabilityId(id); return normalized ? this.entries.has(normalized) : false; }
  list(context = null) {
    return [...this.entries.values()].map((entry) => {
      let scopeSupport = entry.scopeSupport;
      if (entry.agentTool && context?.toolRegistry?.get) {
        const tool = context.toolRegistry.get(entry.agentTool);
        if (tool?.scopeSupport) scopeSupport = tool.scopeSupport;
      }
      return { ...entry, scopeSupport, available: availability(entry, context) };
    });
  }
  agent(context = null) { return this.list(context).filter((entry) => entry.agentExposed && entry.available.ok); }
}

export function availability(entry, context) {
  if (!entry.agentExposed) return { ok: false, reason: entry.humanOnlyReason };
  if (typeof entry.available === 'function') return normalizeAvailability(entry.available(context));
  if (entry.agentTool && !context?.toolRegistry?.has?.(entry.agentTool)) return { ok: false, reason: `analysis-tool-unavailable:${entry.agentTool}` };
  if (entry.category === 'runtime' && entry.id !== 'runtime.status' && !context?.runtimePlatform) return { ok: false, reason: 'runtime-adapter-unavailable' };
  return { ok: true };
}
function normalizeAvailability(value) { return value === true ? { ok: true } : value === false ? { ok: false, reason: 'capability-unavailable' } : value || { ok: true }; }

export function createCapabilityCatalog(entries) { return new CapabilityCatalog(entries); }
export { CATALOG as HEX_CAPABILITIES, HUMAN_ONLY_REASONS };