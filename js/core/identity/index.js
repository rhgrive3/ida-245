const ID_SCHEMA_VERSION = 1;
const HEX_RE = /^[0-9a-f]+$/i;

function fail(code) {
  throw new TypeError(code);
}

function nonEmpty(value, code) {
  if (typeof value !== 'string') fail(code);
  const text = value.trim();
  if (!text) fail(code);
  return text;
}

function nonNegativeInteger(value, fallback, code) {
  if (value == null) return fallback;
  if (typeof value !== 'number' && !(typeof value === 'string' && value.trim() !== '')) fail(code);
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 0) fail(code);
  return number;
}

function sortedStrings(value, code) {
  if (value == null) return [];
  if (!Array.isArray(value)) fail(code);
  const out = [];
  for (const item of value) {
    if (typeof item !== 'string') fail(code);
    const text = item.trim();
    if (!text) fail(code);
    out.push(text);
  }
  return [...new Set(out)].sort();
}

function compareCanonicalText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

export function jsonSafe(value, seen = new WeakSet()) {
  if (typeof value === 'bigint') return value.toString();
  if (value == null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (typeof value === 'undefined' || typeof value === 'function' || typeof value === 'symbol') return null;
  if (ArrayBuffer.isView(value)) return Array.from(new Uint8Array(value.buffer, value.byteOffset, value.byteLength));
  if (value instanceof ArrayBuffer) return Array.from(new Uint8Array(value));
  if (value instanceof Date) return value.toISOString();
  if (typeof value !== 'object') return String(value);
  if (seen.has(value)) fail('identity-cyclic-value');
  seen.add(value);
  let out;
  if (value instanceof Map) {
    const entries = [...value.entries()].map(([k, v]) => [jsonSafe(k, seen), jsonSafe(v, seen)]);
    entries.sort((a, b) => compareCanonicalText(stableStringify(a[0]), stableStringify(b[0])) || compareCanonicalText(stableStringify(a[1]), stableStringify(b[1])));
    out = { $map: entries };
  } else if (value instanceof Set) {
    const values = [...value].map((v) => jsonSafe(v, seen));
    values.sort((a, b) => compareCanonicalText(stableStringify(a), stableStringify(b)));
    out = { $set: values };
  } else if (Array.isArray(value)) out = value.map((item) => jsonSafe(item, seen));
  else {
    out = {};
    for (const key of Object.keys(value).sort()) {
      const normalized = jsonSafe(value[key], seen);
      if (normalized !== null || value[key] === null) {
        Object.defineProperty(out, key, {
          value: normalized,
          enumerable: true,
          configurable: true,
          writable: true,
        });
      }
    }
  }
  seen.delete(value);
  return out;
}

export function stableStringify(value) {
  return JSON.stringify(jsonSafe(value));
}

function fnv64(text, seed) {
  let hash = BigInt.asUintN(64, seed);
  for (let i = 0; i < text.length; i++) {
    hash ^= BigInt(text.charCodeAt(i));
    hash = BigInt.asUintN(64, hash * 0x100000001b3n);
  }
  return hash.toString(16).padStart(16, '0');
}

export function stableDigest(value) {
  const text = stableStringify(value);
  return fnv64(text, 0xcbf29ce484222325n) + fnv64(text, 0x84222325cbf29ce4n);
}

function typedId(prefix, payload) {
  return `${prefix}_${stableDigest({ schema: ID_SCHEMA_VERSION, payload })}`;
}

function bytesOf(value) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  fail('binary-id-bytes-required');
}

function exactArrayBuffer(value) {
  const bytes = bytesOf(value);
  if (bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength && bytes.buffer instanceof ArrayBuffer) return bytes.buffer;
  const exact = new Uint8Array(bytes.byteLength);
  exact.set(bytes);
  return exact.buffer;
}

function hex(bytes) {
  let out = '';
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0');
  return out;
}

export function createBinaryIdFromDigest(digest) {
  const normalized = nonEmpty(digest, 'binary-id-digest-required').toLowerCase().replace(/^sha256:/, '');
  if (normalized.length !== 64 || !HEX_RE.test(normalized)) fail('binary-id-invalid-sha256');
  return `bin_sha256_${normalized}`;
}

export async function createBinaryId(content) {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) fail('binary-id-sha256-unavailable');
  const digest = await subtle.digest('SHA-256', exactArrayBuffer(content));
  return createBinaryIdFromDigest(hex(new Uint8Array(digest)));
}

export function createSliceId(input = {}) {
  const sourceRange = input.sourceRange == null ? null : input.sourceRange;
  if (sourceRange != null) validateCanonicalIdentityNumbers(sourceRange);
  const sourceRangeTypes = sourceRange == null ? null : lossyTypeWitness(sourceRange);
  return typedId('slice', {
    binaryId: nonEmpty(input.binaryId, 'slice-binary-id-required'),
    containerId: input.containerId == null ? null : nonEmpty(input.containerId, 'slice-container-id-invalid'),
    index: nonNegativeInteger(input.index, 0, 'slice-index-invalid'),
    architecture: input.architecture == null ? null : nonEmpty(input.architecture, 'slice-architecture-invalid'),
    sourceRange: sourceRange == null ? null : jsonSafe(sourceRange),
    ...(sourceRangeTypes ? { sourceRangeTypes } : {}),
  });
}

export function createImageId(input = {}) {
  return typedId('image', {
    binaryId: nonEmpty(input.binaryId, 'image-binary-id-required'),
    sliceId: input.sliceId == null ? null : nonEmpty(input.sliceId, 'image-slice-id-invalid'),
    loaderId: nonEmpty(input.loaderId ?? 'unknown', 'image-loader-id-required'),
    imageBase: input.imageBase == null ? null : canonicalAddress(input.imageBase),
  });
}

export function createArtifactId(input = {}) {
  return typedId('artifact', {
    binaryId: nonEmpty(input.binaryId, 'artifact-binary-id-required'),
    sliceId: input.sliceId == null ? null : nonEmpty(input.sliceId, 'artifact-slice-id-invalid'),
    loaderVersion: nonEmpty(input.loaderVersion, 'artifact-loader-version-required'),
    architectureSemanticVersion: nonEmpty(input.architectureSemanticVersion, 'artifact-architecture-semantic-version-required'),
    abiSemanticVersion: nonEmpty(input.abiSemanticVersion, 'artifact-abi-semantic-version-required'),
    semanticSchemaVersion: nonEmpty(input.semanticSchemaVersion, 'artifact-semantic-schema-version-required'),
    entityId: input.entityId == null ? null : nonEmpty(input.entityId, 'artifact-entity-id-invalid'),
    passId: nonEmpty(input.passId, 'artifact-pass-id-required'),
    passVersion: nonEmpty(input.passVersion ?? '1', 'artifact-pass-version-required'),
    optionsHash: input.optionsHash == null ? null : nonEmpty(input.optionsHash, 'artifact-options-hash-invalid'),
    inputArtifactIds: sortedStrings(input.inputArtifactIds, 'artifact-input-ids-invalid'),
  });
}

export function lossyTypeWitness(value, path = '', seen = new WeakSet(), out = []) {
  const type = typeof value;
  if (type === 'bigint') out.push([path, 'bigint']);
  else if (type === 'number') {
    if (Number.isNaN(value)) out.push([path, 'number:nan']);
    else if (value === Infinity) out.push([path, 'number:+infinity']);
    else if (value === -Infinity) out.push([path, 'number:-infinity']);
    else if (Object.is(value, -0)) out.push([path, 'number:-0']);
  } else if (type === 'undefined') out.push([path, 'undefined']);
  else if (type === 'function') out.push([path, 'function']);
  else if (type === 'symbol') out.push([path, 'symbol']);
  else if (value !== null && type === 'object') {
    if (seen.has(value)) return out.length ? out : null;
    seen.add(value);
    if (value instanceof Map) {
      out.push([path, 'map']);
      for (const [k, v] of value.entries()) {
        lossyTypeWitness(k, `${path}.<key>`, seen, out);
        lossyTypeWitness(v, `${path}.<val>`, seen, out);
      }
    } else if (value instanceof Set) {
      out.push([path, 'set']);
      for (const v of value.values()) {
        lossyTypeWitness(v, `${path}[]`, seen, out);
      }
    } else if (ArrayBuffer.isView(value)) out.push([path, 'bytes']);
    else if (value instanceof ArrayBuffer) out.push([path, 'bytes']);
    else if (value instanceof Date) out.push([path, 'date']);
    else if (Array.isArray(value)) value.forEach((item, index) => lossyTypeWitness(item, `${path}[${index}]`, seen, out));
    else for (const key of Object.keys(value).sort()) lossyTypeWitness(value[key], `${path}.${key}`, seen, out);
    seen.delete(value);
  }
  return path === '' ? (out.length ? out : null) : out;
}

export function createEntityId(input = {}) {
  const witness = lossyTypeWitness(input.identity);
  return typedId('entity', {
    binaryId: nonEmpty(input.binaryId, 'entity-binary-id-required'),
    sliceId: input.sliceId == null ? null : nonEmpty(input.sliceId, 'entity-slice-id-invalid'),
    kind: nonEmpty(input.kind, 'entity-kind-required'),
    identity: jsonSafe(input.identity),
    ...(witness ? { identityTypes: witness } : {}),
  });
}

export function createFunctionId(input = {}) {
  return typedId('function', {
    binaryId: nonEmpty(input.binaryId, 'function-binary-id-required'),
    sliceId: nonEmpty(input.sliceId, 'function-slice-id-required'),
    canonicalStartIdentity: normalizeIdentity(input.canonicalStartIdentity, 'function-start-identity-required'),
  });
}

export function createInstructionId(input = {}) {
  return typedId('instruction', {
    domain: 'native',
    binaryId: nonEmpty(input.binaryId, 'instruction-binary-id-required'),
    sliceId: nonEmpty(input.sliceId, 'instruction-slice-id-required'),
    virtualAddress: canonicalAddress(input.virtualAddress),
    decodeMode: nonEmpty(input.decodeMode ?? 'default', 'instruction-decode-mode-required'),
    decoderSemanticVersion: nonEmpty(input.decoderSemanticVersion, 'instruction-semantic-version-required'),
  });
}

export function createVmOperationId(input = {}) {
  return typedId('operation', {
    domain: 'vm',
    binaryId: nonEmpty(input.binaryId, 'operation-binary-id-required'),
    sliceId: input.sliceId == null ? null : nonEmpty(input.sliceId, 'operation-slice-id-invalid'),
    vm: nonEmpty(input.vm, 'operation-vm-required'),
    methodId: nonEmpty(input.methodId, 'operation-method-id-required'),
    operationOffset: normalizeIdentity(input.operationOffset, 'operation-offset-required'),
    semanticVersion: nonEmpty(input.semanticVersion, 'operation-semantic-version-required'),
  });
}

export function createBlockId(input = {}) {
  return typedId('block', {
    functionId: nonEmpty(input.functionId, 'block-function-id-required'),
    canonicalBlockIdentity: normalizeIdentity(input.canonicalBlockIdentity, 'block-canonical-identity-required'),
  });
}

export function createValueId(input = {}) {
  return typedId('value', {
    functionId: nonEmpty(input.functionId, 'value-function-id-required'),
    canonicalDefinitionIdentity: normalizeIdentity(input.canonicalDefinitionIdentity, 'value-definition-identity-required'),
  });
}

export function createMemoryRegionId(input = {}) {
  const functionId = input.functionId == null ? null : nonEmpty(input.functionId, 'memory-region-function-id-required');
  const binaryId = input.binaryId == null ? null : nonEmpty(input.binaryId, 'memory-region-binary-id-required');
  if (functionId == null && binaryId == null) fail('memory-region-scope-required');
  return typedId('memoryregion', {
    functionId,
    binaryId,
    regionKind: nonEmpty(input.regionKind, 'memory-region-kind-required'),
    canonicalRegionIdentity: normalizeIdentity(input.canonicalRegionIdentity, 'memory-region-identity-required'),
  });
}

export function createEvidenceId(input = {}) {
  const witness = lossyTypeWitness(input.identity);
  return typedId('evidence', {
    binaryId: input.binaryId == null ? null : nonEmpty(input.binaryId, 'evidence-binary-id-invalid'),
    kind: nonEmpty(input.kind ?? 'evidence', 'evidence-kind-required'),
    sourceId: input.sourceId == null ? null : nonEmpty(input.sourceId, 'evidence-source-id-invalid'),
    identity: jsonSafe(input.identity),
    ...(witness ? { identityTypes: witness } : {}),
  });
}

export function createRuntimeSessionId(input = {}) {
  return typedId('runtime', {
    binaryId: nonEmpty(input.binaryId, 'runtime-binary-id-required'),
    provider: nonEmpty(input.provider, 'runtime-provider-required'),
    targetIdentity: normalizeIdentity(input.targetIdentity, 'runtime-target-required'),
    sessionNonce: nonEmpty(input.sessionNonce ?? input.startedAt, 'runtime-session-nonce-required'),
  });
}

export function canonicalAddress(value) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) fail('identity-unsafe-number-address');
  } else if (typeof value === 'string') {
    const text = value.trim();
    if (!text || !/^(?:0x[0-9a-fA-F]+|[0-9]+)$/.test(text)) {
      fail('identity-invalid-address-string');
    }
    value = text;
  } else if (typeof value !== 'bigint') {
    fail('identity-invalid-address');
  }
  try {
    const n = typeof value === 'bigint' ? value : BigInt(value);
    if (n < 0n) fail('identity-negative-address');
    return `0x${n.toString(16)}`;
  } catch (error) {
    if (error instanceof TypeError && (error.message === 'identity-negative-address' || error.message === 'identity-unsafe-number-address' || error.message === 'identity-invalid-address-string')) throw error;
    fail('identity-invalid-address');
  }
}

export function validateCanonicalIdentityNumbers(value, seen = new WeakSet()) {
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) fail('identity-non-finite-number');
    if (Number.isInteger(value) && !Number.isSafeInteger(value)) fail('identity-unsafe-number');
    return;
  }
  if (value == null || typeof value !== 'object' || ArrayBuffer.isView(value) || value instanceof ArrayBuffer || value instanceof Date) return;
  if (seen.has(value)) return;
  seen.add(value);
  if (value instanceof Map) {
    for (const [k, v] of value.entries()) {
      validateCanonicalIdentityNumbers(k, seen);
      validateCanonicalIdentityNumbers(v, seen);
    }
  } else if (value instanceof Set) {
    for (const v of value.values()) {
      validateCanonicalIdentityNumbers(v, seen);
    }
  } else if (Array.isArray(value)) {
    for (const item of value) validateCanonicalIdentityNumbers(item, seen);
  } else {
    for (const key of Object.keys(value)) validateCanonicalIdentityNumbers(value[key], seen);
  }
  seen.delete(value);
}

function normalizeIdentity(value, code) {
  if (value == null) fail(code);
  validateCanonicalIdentityNumbers(value);
  if (typeof value === 'bigint' || typeof value === 'number') return String(value);
  if (typeof value === 'string') return nonEmpty(value, code);
  const witness = lossyTypeWitness(value);
  const normalized = jsonSafe(value);
  return witness ? { identity: normalized, identityTypes: witness } : normalized;
}

export function deepFreeze(value, seen = new WeakSet()) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value) || ArrayBuffer.isView(value) || value instanceof ArrayBuffer) return value;
  if (seen.has(value)) return value;
  seen.add(value);
  for (const child of Object.values(value)) deepFreeze(child, seen);
  return Object.freeze(value);
}

export const IDENTITY_SCHEMA_VERSION = ID_SCHEMA_VERSION;
