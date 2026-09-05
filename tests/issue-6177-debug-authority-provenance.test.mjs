/**
 * #6177 regression: debug record authority requires provenance coherence with
 * the matched source identity.
 *
 * Audit baseline `main@60980a3c` promoted any record on a
 * `matched-authoritative` result to hard authority without checking that the
 * record actually came from the provider/version/build the identity matched,
 * so a canonical record from a foreign provider/build could be laundered into
 * an exact type constraint. Authority is now gated by
 * `record.providerId === identity.providerId`,
 * `record.providerVersion === identity.providerVersion`, and record build
 * provenance coherence (fail-closed), for both verdict branches.
 */
import assert from 'node:assert/strict';
import test from 'node:test';

import {
  createDebugProviderResult,
  createDebugRecord,
  createDebugPage,
  isDebugRecordAuthoritative,
  applyDebugTypesToGraph,
  debugFunctionEvidence,
  DebugInfoProvider,
} from '../js/analysis/debug/provider.js';

function authoritativeResult(overrides = {}) {
  return createDebugProviderResult({
    ecosystem: 'dwarf',
    identity: {
      verdict: 'matched-authoritative',
      providerId: 'provider-A',
      providerVersion: '1',
      expected: 'BUILD-A',
      observed: 'BUILD-A',
      method: 'build-id',
      ...overrides,
    },
    status: { snapshotId: 's1', analyzerId: 'provider-A', analyzerVersion: '1', completeness: 'complete' },
  });
}

function typeRecord(overrides = {}) {
  return createDebugRecord({
    kind: 'type',
    entityId: 'entity:1',
    descriptor: { layer: 'nominal', claim: { kind: 'struct', name: 'T' } },
    providerId: 'provider-A',
    providerVersion: '1',
    buildIdentity: 'BUILD-A',
    evidenceIds: ['e1'],
    ...overrides,
  });
}

test('issue #6177 - same source/build canonical record stays authoritative', () => {
  const result = authoritativeResult();
  assert.equal(isDebugRecordAuthoritative(result, typeRecord()), true);
  assert.equal(isDebugRecordAuthoritative(result, typeRecord({ buildIdentity: null })), true);
});

test('issue #6177 - matched-authoritative rejects foreign provider, version, and build records', () => {
  const result = authoritativeResult();
  assert.equal(isDebugRecordAuthoritative(result, typeRecord({ providerId: 'provider-B' })), false);
  assert.equal(isDebugRecordAuthoritative(result, typeRecord({ providerVersion: '9' })), false);
  assert.equal(isDebugRecordAuthoritative(result, typeRecord({ buildIdentity: 'BUILD-B' })), false);
});

test('issue #6177 - foreign record cannot become a hard type constraint', () => {
  const result = authoritativeResult();
  const foreign = typeRecord({ providerId: 'provider-B', providerVersion: '9', buildIdentity: 'BUILD-B' });
  const hard = [];
  const graph = {
    addHardConstraint(value) { hard.push(value); },
    addSoftEvidence() {},
  };
  const applied = applyDebugTypesToGraph(graph, result, createDebugPage({ records: [foreign] }));
  assert.equal(hard.length, 0, 'foreign-provenance record must be downgraded to soft evidence');
  assert.equal(applied.hard, 0);
  assert.equal(applied.soft, 1);
});

test('issue #6177 - authoritativeRecords page filter drops foreign provenance', () => {
  const result = authoritativeResult();
  class ForeignPagedProvider extends DebugInfoProvider {
    constructor(records) {
      super({ id: 'provider-A', version: '1', ecosystem: 'dwarf' });
      this.records = records;
    }
    probe() {}
    types() { return createDebugPage({ records: this.records }); }
  }
  const own = typeRecord({ entityId: 'entity:own' });
  const foreign = typeRecord({ entityId: 'entity:foreign', providerId: 'provider-B', providerVersion: '9', buildIdentity: 'BUILD-B' });
  const provider = new ForeignPagedProvider([own, foreign]);
  const page = provider.authoritativeRecords(result, provider.types, undefined);
  assert.deepEqual(page.records.map((record) => record.entityId), ['entity:own']);
});

test('issue #6177 - foreign symbol evidence is heuristic, never exact', () => {
  const result = authoritativeResult();
  const record = (overrides) => typeRecord({ kind: 'symbol', entityId: 'fn:1', address: '0x1000', name: 'fn', descriptor: { isFunction: true }, ...overrides });
  const [own] = debugFunctionEvidence(result, createDebugPage({ records: [record({})] }));
  assert.equal(own.confidence, 'exact');
  const [foreign] = debugFunctionEvidence(result, createDebugPage({ records: [record({ providerId: 'provider-B', providerVersion: '9', buildIdentity: 'BUILD-B' })] }));
  assert.equal(foreign.confidence, 'heuristic');
});

test('issue #6177 - matched-partial requires both source coherence and coverage', () => {
  const partial = authoritativeResult({
    verdict: 'matched-partial',
    coverage: { recordKinds: ['type'] },
  });
  assert.equal(isDebugRecordAuthoritative(partial, typeRecord()), true, 'coherent covered record stays hard');
  assert.equal(isDebugRecordAuthoritative(partial, typeRecord({ providerId: 'provider-B' })), false, 'foreign provider stays soft even when covered');
  assert.equal(isDebugRecordAuthoritative(partial, typeRecord({ providerVersion: '9' })), false);
  assert.equal(isDebugRecordAuthoritative(partial, typeRecord({ buildIdentity: 'BUILD-B' })), false);

  const buildScoped = authoritativeResult({
    verdict: 'matched-partial',
    coverage: { buildIdentities: ['BUILD-A'] },
  });
  assert.equal(isDebugRecordAuthoritative(buildScoped, typeRecord()), true);
  assert.equal(isDebugRecordAuthoritative(buildScoped, typeRecord({ buildIdentity: 'BUILD-B' })), false);

  const uncovered = authoritativeResult({
    verdict: 'matched-partial',
    coverage: { recordKinds: ['symbol'] },
  });
  assert.equal(isDebugRecordAuthoritative(uncovered, typeRecord()), false, 'uncovered kind stays soft');
});

test('issue #6177 - unmatched source keeps soft-evidence-only policy', () => {
  const mismatch = createDebugProviderResult({
    ecosystem: 'dwarf',
    identity: {
      verdict: 'identity-mismatch',
      providerId: 'provider-A',
      providerVersion: '1',
      expected: 'BUILD-A',
      observed: 'BUILD-B',
      method: 'build-id',
    },
    status: { snapshotId: 's1', analyzerId: 'provider-A', analyzerVersion: '1', completeness: 'complete' },
  });
  const hard = [];
  const graph = {
    addHardConstraint(value) { hard.push(value); },
    addSoftEvidence() {},
  };
  const applied = applyDebugTypesToGraph(graph, mismatch, createDebugPage({ records: [typeRecord()] }));
  assert.equal(hard.length, 0);
  assert.equal(applied.soft, 1);
  assert.equal(applied.hard, 0);
});
