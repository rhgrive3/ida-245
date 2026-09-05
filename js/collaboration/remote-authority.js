import { deepFreeze, jsonSafe, stableDigest } from '../core/identity/index.js';
import { isValidatedStage2CapabilityProof } from '../platform/stage2-profile-evidence.js';
import { CHANGELOG_SCHEMA_VERSION, ChangeLog, createProjectOperation, canonicalizeProjectOperation, isCanonicalProjectOperation } from './index.js';
import { applyRemoteEnvelopeQueued } from './remote-delivery.js';

export const REMOTE_COLLAB_SCHEMA = 'hex-remote-collaboration-envelope/v1';
export const REMOTE_GATE_SCHEMA = 'hex-remote-collaboration-gate/v1';
export const REMOTE_SECURITY_PROFILE_ID = 'collaboration:remote-security-v1';
const VALID_REMOTE_COLLABORATION_SUPPORT = new WeakSet();
const VERIFIED_TRANSPORT_PROOFS = new WeakMap();
const MAX_MESSAGE_ID_LENGTH = 512;

function validMessageId(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= MAX_MESSAGE_ID_LENGTH && value.trim().length > 0;
}

function required(value, code) {
  if (typeof value !== 'string') throw new TypeError(code);
  const text = value.trim();
  if (!text) throw new TypeError(code);
  return text;
}

function validRawIdentity(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function positive(value, fallback, max, code) {
  const n = value == null ? fallback : Number(value);
  if (!Number.isSafeInteger(n) || n < 1 || n > max) throw new TypeError(code);
  return n;
}

function validSequence(value) {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function list(value) {
  return [...new Set((Array.isArray(value) ? value : []).map(String).filter(Boolean))].sort();
}

function identityList(value, code) {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.map((identity) => required(identity, code)))].sort();
}

function permissionList(value) {
  if (!Array.isArray(value)) return [];
  const permissions = [];
  for (const permission of value) {
    if (typeof permission !== 'string' || permission.length === 0) {
      throw new TypeError('remote-gate-permission-invalid');
    }
    permissions.push(permission);
  }
  return [...new Set(permissions)].sort();
}

function byteLength(value) {
  const text = JSON.stringify(jsonSafe(value));
  return typeof TextEncoder !== 'undefined' ? new TextEncoder().encode(text).length : text.length;
}

function normalizePermissions(value) {
  const entries = value instanceof Map
    ? [...value.entries()]
    : (!value || typeof value !== 'object' || Array.isArray(value) ? [] : Object.entries(value));
  const normalized = Object.create(null);
  for (const [actor, permissions] of entries) {
    const identity = required(actor, 'remote-gate-actor-identity-invalid');
    if (Object.hasOwn(normalized, identity)) throw new TypeError('remote-gate-actor-identity-duplicate');
    normalized[identity] = permissionList(permissions);
  }
  return normalized;
}

function authorized(permissions, operation) {
  if (permissions.includes('*')) return true;
  const fact = `fact:${operation.factKind}`;
  const action = `action:${operation.action}`;
  const combined = `${fact}:action:${operation.action}`;
  return permissions.includes(combined) || (permissions.includes(fact) && permissions.includes(action));
}

export function envelopeIdentity(envelope) {
  const { envelopeId, ...payload } = envelope;
  return `remote-envelope:${stableDigest(payload)}`;
}

export function createRemoteCollaborationEnvelope(input = {}) {
  const projectIdentity = required(input.projectIdentity, 'remote-project-identity-required');
  const binaryIdentity = input.binaryIdentity == null ? null : required(input.binaryIdentity, 'remote-binary-identity-invalid');
  const sessionIdentity = required(input.sessionIdentity, 'remote-session-identity-required');
  const actorIdentity = required(input.actorIdentity, 'remote-actor-identity-required');
  const deviceIdentity = required(input.deviceIdentity, 'remote-device-identity-required');
  const messageId = required(input.messageId, 'remote-message-id-required');
  const sequence = input.sequence;
  if (!validSequence(sequence)) throw new TypeError('remote-sequence-invalid');
  if (!Array.isArray(input.operations) || input.operations.length === 0) throw new TypeError('remote-operations-required');
  const operations = input.operations.map((operation) => createProjectOperation({
    ...operation,
    projectIdentity,
    binaryIdentity,
    authorIdentity: actorIdentity,
    deviceIdentity,
    provenance: { ...(operation.provenance || {}), source: 'collaborator', transport: 'remote', actorIdentity, deviceIdentity },
  }));
  const envelope = {
    schemaVersion: REMOTE_COLLAB_SCHEMA,
    operationSchemaVersion: CHANGELOG_SCHEMA_VERSION,
    projectIdentity,
    binaryIdentity,
    sessionIdentity,
    actorIdentity,
    deviceIdentity,
    messageId,
    sequence,
    operations,
    transportProof: {
      authenticated: input.transportProof?.authenticated === true,
      confidentiality: input.transportProof?.confidentiality === 'verified' ? 'verified' : 'unverified',
      integrity: input.transportProof?.integrity === 'verified' ? 'verified' : 'unverified',
      proofIdentity: input.transportProof?.proofIdentity == null
        ? null
        : required(input.transportProof.proofIdentity, 'remote-transport-proof-identity-invalid'),
    },
    egress: {
      userAuthorized: input.egress?.userAuthorized === true,
      rawBinaryBytes: input.egress?.rawBinaryBytes === true,
      derivedDataOnly: input.egress?.derivedDataOnly !== false,
    },
  };
  return deepFreeze({ ...envelope, envelopeId: envelopeIdentity(envelope) });
}

export class RemoteCollaborationGate {
  constructor(input = {}) {
    this.schemaVersion = REMOTE_GATE_SCHEMA;
    this.projectIdentity = required(input.projectIdentity, 'remote-gate-project-required');
    this.binaryIdentity = input.binaryIdentity == null ? null : required(input.binaryIdentity, 'remote-gate-binary-invalid');
    this.sessionIdentity = required(input.sessionIdentity, 'remote-gate-session-required');
    this.allowedActors = normalizePermissions(input.allowedActors);
    this.revokedActors = new Set(identityList(input.revokedActors, 'remote-gate-revoked-actor-invalid'));
    this.supportedEnvelopeSchemas = new Set(list(input.supportedEnvelopeSchemas || [REMOTE_COLLAB_SCHEMA]));
    this.supportedOperationSchemas = new Set(list(input.supportedOperationSchemas || [CHANGELOG_SCHEMA_VERSION]));
    this.maxBatch = positive(input.maxBatch, 256, 4096, 'remote-gate-max-batch-invalid');
    this.maxMessageBytes = positive(input.maxMessageBytes, 1024 * 1024, 32 * 1024 * 1024, 'remote-gate-max-message-invalid');
    this.seenMessages = new Set();
    this.seenEnvelopeIds = new Set();
    this.lastSequenceByActor = new Map();
    this.verifyTransportProof = typeof input.verifyTransportProof === 'function' ? input.verifyTransportProof : null;
    this.transportVerifierIdentity = input.transportVerifierIdentity == null
      ? null
      : required(input.transportVerifierIdentity, 'remote-gate-transport-verifier-identity-invalid');
  }

  validate(envelope) {
    VERIFIED_TRANSPORT_PROOFS.delete(this);
    if (!envelope || !this.supportedEnvelopeSchemas.has(envelope.schemaVersion)) return { ok: false, reason: 'remote-envelope-schema-unsupported' };
    if (!this.supportedOperationSchemas.has(envelope.operationSchemaVersion)) return { ok: false, reason: 'remote-operation-schema-unsupported' };
    if (!validRawIdentity(envelope.projectIdentity)) return { ok: false, reason: 'remote-project-identity-required' };
    if (envelope.binaryIdentity != null && !validRawIdentity(envelope.binaryIdentity)) return { ok: false, reason: 'remote-binary-identity-invalid' };
    if (!validRawIdentity(envelope.sessionIdentity)) return { ok: false, reason: 'remote-session-identity-required' };
    if (!validRawIdentity(envelope.actorIdentity)) return { ok: false, reason: 'remote-actor-identity-required' };
    if (!validRawIdentity(envelope.deviceIdentity)) return { ok: false, reason: 'remote-device-identity-required' };
    if (!validRawIdentity(envelope.messageId)) return { ok: false, reason: 'remote-message-id-required' };
    if (envelope.projectIdentity !== this.projectIdentity) return { ok: false, reason: 'remote-wrong-project' };
    if ((envelope.binaryIdentity ?? null) !== this.binaryIdentity) return { ok: false, reason: 'remote-wrong-binary' };
    if (envelope.sessionIdentity !== this.sessionIdentity) return { ok: false, reason: 'remote-wrong-session' };
    if (!validSequence(envelope.sequence)) return { ok: false, reason: 'remote-sequence-invalid' };
    // Replay authority rests on `messageId`, so untrusted ingress must verify
    // its raw shape itself: a missing or structured value would otherwise be
    // accepted as a Set key (compared by object identity) or skipped entirely.
    if (!validMessageId(envelope.messageId)) return { ok: false, reason: 'remote-message-id-invalid' };
    if (typeof envelope.envelopeId !== 'string' || envelope.envelopeId !== envelopeIdentity(envelope)) return { ok: false, reason: 'remote-envelope-identity-mismatch' };
    if (this.revokedActors.has(envelope.actorIdentity)) return { ok: false, reason: 'remote-actor-revoked' };
    const permissions = Object.hasOwn(this.allowedActors, envelope.actorIdentity) ? this.allowedActors[envelope.actorIdentity] : null;
    if (!permissions) return { ok: false, reason: 'remote-actor-unauthorized' };
    if (this.seenMessages.has(envelope.messageId) || this.seenEnvelopeIds.has(envelope.envelopeId)) return { ok: false, reason: 'remote-replay-or-duplicate' };
    const previous = this.lastSequenceByActor.get(envelope.actorIdentity);
    if (previous != null && envelope.sequence <= previous) return { ok: false, reason: 'remote-stale-sequence' };
    if (!Array.isArray(envelope.operations) || envelope.operations.length === 0 || envelope.operations.length > this.maxBatch) return { ok: false, reason: 'remote-batch-budget-exceeded' };
    if (byteLength(envelope) > this.maxMessageBytes) return { ok: false, reason: 'remote-message-budget-exceeded' };
    if (envelope.transportProof?.authenticated !== true || envelope.transportProof?.confidentiality !== 'verified' || envelope.transportProof?.integrity !== 'verified') {
      return { ok: false, reason: 'remote-transport-security-unverified' };
    }
    if (!this.verifyTransportProof) return { ok: false, reason: 'remote-transport-proof-verifier-required' };
    let verified = false;
    try { verified = this.verifyTransportProof(envelope.transportProof, envelope) === true; }
    catch { return { ok: false, reason: 'remote-transport-proof-rejected' }; }
    if (!verified) return { ok: false, reason: 'remote-transport-proof-rejected' };
    if (envelope.egress?.userAuthorized !== true) return { ok: false, reason: 'remote-egress-user-authorization-required' };
    if (envelope.egress?.rawBinaryBytes === true || envelope.egress?.derivedDataOnly !== true) return { ok: false, reason: 'remote-raw-binary-egress-forbidden' };
    for (const operation of envelope.operations) {
      if (!isCanonicalProjectOperation(canonicalizeProjectOperation(operation))) return { ok: false, reason: 'remote-operation-shape-invalid' };
      if (operation.projectIdentity !== this.projectIdentity || (operation.binaryIdentity ?? null) !== this.binaryIdentity) return { ok: false, reason: 'remote-operation-scope-mismatch' };
      if (operation.authorIdentity !== envelope.actorIdentity || operation.deviceIdentity !== envelope.deviceIdentity) return { ok: false, reason: 'remote-operation-actor-binding-mismatch' };
      if (operation.provenance?.transport !== 'remote') return { ok: false, reason: 'remote-operation-provenance-invalid' };
      if (!authorized(permissions, operation)) return { ok: false, reason: 'remote-operation-not-authorized', factKind: operation.factKind, action: operation.action };
    }
    VERIFIED_TRANSPORT_PROOFS.set(this, Object.freeze({
      envelopeId: envelope.envelopeId,
      verifier: this.verifyTransportProof,
      verifierIdentity: this.transportVerifierIdentity,
    }));
    return { ok: true };
  }

  accept(envelope) {
    const checked = this.validate(envelope);
    if (!checked.ok) return Object.freeze({ status: 'rejected', reason: checked.reason });
    this.seenMessages.add(envelope.messageId);
    this.seenEnvelopeIds.add(envelope.envelopeId);
    this.lastSequenceByActor.set(envelope.actorIdentity, envelope.sequence);
    return Object.freeze({ status: 'accepted', envelopeId: envelope.envelopeId, operationCount: envelope.operations.length });
  }

  revoke(actorIdentity) {
    this.revokedActors.add(required(actorIdentity, 'remote-revoke-actor-required'));
  }

  snapshot() {
    return deepFreeze({
      schemaVersion: this.schemaVersion,
      projectIdentity: this.projectIdentity,
      binaryIdentity: this.binaryIdentity,
      sessionIdentity: this.sessionIdentity,
      actors: Object.keys(this.allowedActors).sort(),
      revokedActors: [...this.revokedActors].sort(),
      seenMessageCount: this.seenMessages.size,
      transportVerifierIdentity: this.transportVerifierIdentity,
    });
  }
}

export function applyRemoteEnvelope(log, gate, envelope) {
  return applyRemoteEnvelopeQueued(log, gate, envelope);
}

export class RemoteCollaborationChannel {
  constructor({ gate, log, transport } = {}) {
    if (!(gate instanceof RemoteCollaborationGate)) throw new TypeError('RemoteCollaborationGate required');
    if (!(log instanceof ChangeLog)) throw new TypeError('ChangeLog required');
    if (!transport || typeof transport.send !== 'function') throw new TypeError('remote-transport-send-required');
    this.gate = gate;
    this.log = log;
    this.transport = transport;
  }

  async send(envelope) {
    const checked = this.gate.validate(envelope);
    if (!checked.ok) return { status: 'rejected', reason: checked.reason };
    await this.transport.send(envelope);
    return { status: 'sent', envelopeId: envelope.envelopeId };
  }

  receive(envelope) {
    return applyRemoteEnvelopeQueued(this.log, this.gate, envelope);
  }
}

export function remoteCollaborationSupport({
  gate,
  profileProof = null,
  expectedCommitSha = null,
  expectedTreeSha = null,
} = {}) {
  const commitSha = String(expectedCommitSha || '').toLowerCase();
  const treeSha = String(expectedTreeSha || '').toLowerCase();
  const exactIdentity = /^[0-9a-f]{40}$/.test(commitSha) && /^[0-9a-f]{40}$/.test(treeSha);
  const brandedProfile = isValidatedStage2CapabilityProof(profileProof, {
    itemId: 'S2-P12-COLLAB-REMOTE',
    profileIds: [REMOTE_SECURITY_PROFILE_ID],
  });
  const transportVerifierIdentity = gate instanceof RemoteCollaborationGate ? gate.transportVerifierIdentity : null;
  const transportVerifierBound = typeof transportVerifierIdentity === 'string'
    && Array.isArray(profileProof?.independentOracleIdentities)
    && profileProof.independentOracleIdentities.includes(transportVerifierIdentity);
  const activeTransportProof = gate instanceof RemoteCollaborationGate ? VERIFIED_TRANSPORT_PROOFS.get(gate) : null;
  const activeVerificationBound = !!activeTransportProof
    && activeTransportProof.verifier === gate.verifyTransportProof
    && activeTransportProof.verifierIdentity === transportVerifierIdentity;
  const ready = gate instanceof RemoteCollaborationGate
    && typeof gate.verifyTransportProof === 'function'
    && transportVerifierBound
    && activeVerificationBound
    && exactIdentity
    && brandedProfile
    && profileProof.commitSha === commitSha
    && profileProof.treeSha === treeSha;
  const result = Object.freeze({
    status: ready ? 'supported-for-exact-security-profile' : 'unsupported',
    securityProfileId: ready ? REMOTE_SECURITY_PROFILE_ID : null,
    authority: ready ? 'remote-authorized-canonical-operations' : 'none',
    evidenceId: ready ? profileProof.evidenceId : null,
  });
  if (ready) VALID_REMOTE_COLLABORATION_SUPPORT.add(result);
  return result;
}

export function isValidatedRemoteCollaborationSupport(value) {
  return !!value && VALID_REMOTE_COLLABORATION_SUPPORT.has(value) && value.status === 'supported-for-exact-security-profile';
}
