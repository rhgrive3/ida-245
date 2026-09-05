import assert from 'node:assert/strict';
import test from 'node:test';

import {
  createPassDescriptor,
  createPassResult,
} from '../../../js/decompiler/phase8/contract.js';
import {
  createAnalysisState,
  runPassTransaction,
  transactionDigest,
} from '../../../js/decompiler/phase8/transaction.js';

const descriptor = createPassDescriptor({
  id: 'issue-3875-pass-a',
  version: '1',
  stage: 'scalar-optimization',
  consumes: [],
  preserves: ['cfg'],
  invalidates: [],
  produces: ['ranges'],
});

function canonicalResult() {
  return createPassResult({
    descriptor,
    status: 'changed',
    changed: true,
    completeness: 'complete',
    produced: ['ranges'],
  });
}

function runWithResult(result) {
  const state = createAnalysisState({ cfg: Object.freeze({ blocks: [] }) });
  const before = state.snapshot();
  const outcome = runPassTransaction(state, {
    descriptor,
    run(_context, _budget, area) {
      area.stage('ranges', Object.freeze({ source: 'issue-3875-pass-a' }));
      return result;
    },
  });
  return { state, before, outcome };
}

function assertRefusedIdentity(overrides) {
  const result = Object.freeze({ ...canonicalResult(), ...overrides });
  const { state, before, outcome } = runWithResult(result);
  assert.equal(outcome.committed, false);
  assert.equal(outcome.result, null);
  assert.equal(outcome.stopReason, `result-descriptor-mismatch:${descriptor.id}`);
  assert.deepEqual(outcome.invalidated, []);
  assert.deepEqual(outcome.staged, []);
  assert.deepEqual(state.snapshot(), before);
  assert.equal(state.get('ranges'), null);
}

test('exact descriptor identity retains transaction authority', () => {
  const { state, outcome } = runWithResult(canonicalResult());

  assert.equal(outcome.committed, true);
  assert.equal(outcome.stopReason, null);
  assert.equal(outcome.result.passId, descriptor.id);
  assert.equal(outcome.result.passVersion, descriptor.version);
  assert.equal(outcome.result.stage, descriptor.stage);
  assert.equal(outcome.result.contractVersion, descriptor.contractVersion);
  assert.deepEqual(state.get('ranges'), { source: 'issue-3875-pass-a' });
  assert.equal(typeof transactionDigest(outcome), 'string');
});

test('result passId is bound to the invoked descriptor', () => {
  assertRefusedIdentity({ passId: 'issue-3875-pass-b' });
});

test('result passVersion is bound to the invoked descriptor', () => {
  assertRefusedIdentity({ passVersion: '99' });
});

test('result stage is bound to the invoked descriptor', () => {
  assertRefusedIdentity({ stage: 'providers' });
});

test('result contractVersion is bound to the invoked descriptor', () => {
  assertRefusedIdentity({ contractVersion: descriptor.contractVersion + 1 });
});
