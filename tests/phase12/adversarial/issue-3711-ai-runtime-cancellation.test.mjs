import assert from 'node:assert/strict';
import test from 'node:test';
import { createHexToolRegistry } from '../../../js/ai/tools/registry.js';

function runtimeContext(verifyHypothesis) {
  return {
    binaryId: 'issue-3711-runtime-cancellation',
    analysisRevision: 'rev-1',
    addressExists: () => true,
    runtime: { verifyHypothesis },
  };
}

function waitFor(check, timeoutMs = 250) {
  return new Promise((resolve, reject) => {
    const started = Date.now();
    const poll = () => {
      if (check()) return resolve();
      if (Date.now() - started >= timeoutMs) return reject(new Error('wait-timeout'));
      setTimeout(poll, 1);
    };
    poll();
  });
}

test('Issue #3711: parent cancellation reaches runtime verifier and cannot be replaced by model options', async () => {
  let observedOptions = null;
  let aborted = false;
  let ingests = 0;
  const registry = createHexToolRegistry(runtimeContext(async (_hypothesis, options = {}) => {
    observedOptions = options;
    await new Promise((resolve, reject) => {
      const onAbort = () => {
        aborted = true;
        reject(new Error('cancelled'));
      };
      options.signal?.addEventListener('abort', onAbort, { once: true });
      if (options.signal?.aborted) onAbort();
    });
    return { verified: true };
  }), {
    evidenceStore: {
      setObservationStore() {},
      ingest() { ingests += 1; return []; },
    },
  });
  const parent = new AbortController();
  const execution = registry.execute('verify_runtime_hypothesis', {
    hypothesis: { claim: 'x' },
    options: { marker: 7, signal: 'model-controlled' },
  }, { scope: 'runtime', signal: parent.signal });

  await waitFor(() => observedOptions !== null);
  assert.equal(observedOptions.marker, 7);
  assert.notEqual(observedOptions.signal, 'model-controlled');
  assert.equal(observedOptions.signal?.aborted, false);

  parent.abort('user-stop');
  await assert.rejects(execution, (error) => error?.type === 'cancelled');
  await waitFor(() => aborted);
  assert.equal(observedOptions.signal.aborted, true);
  assert.equal(ingests, 0, 'cancelled verifier results must not become evidence');
});

test('Issue #3711: tool timeout aborts the runtime verifier execution signal', async () => {
  let observedSignal = null;
  let aborted = false;
  const registry = createHexToolRegistry(runtimeContext(async (_hypothesis, options = {}) => {
    observedSignal = options.signal;
    await new Promise((resolve, reject) => {
      const onAbort = () => {
        aborted = true;
        reject(new Error('cancelled'));
      };
      options.signal?.addEventListener('abort', onAbort, { once: true });
      if (options.signal?.aborted) onAbort();
    });
    return { verified: true };
  }));

  await assert.rejects(
    registry.execute('verify_runtime_hypothesis', { hypothesis: { claim: 'x' } }, { scope: 'runtime', toolTimeoutMs: 20 }),
    (error) => error?.type === 'tool_failed' && /timed out/i.test(error.message),
  );
  assert.ok(observedSignal, 'runtime verifier must receive an execution signal');
  assert.equal(observedSignal.aborted, true);
  assert.equal(aborted, true);
});
