import assert from 'node:assert/strict';
import { awaitCancellableProducer } from '../../../js/cache/artifact-orchestration.js';

function resolvedOperation(value = 'done') {
  let cancels = 0;
  const operation = Promise.resolve(value);
  operation.cancel = () => { cancels++; };
  return { operation, cancelCount:() => cancels };
}

// Reproduce the check->subscribe race deterministically: abort becomes visible
// during listener registration, after the helper's initial signal.aborted check,
// without a past abort event being replayed to the newly registered listener.
{
  let aborted = false;
  let removes = 0;
  const reason = new DOMException('registration-race', 'AbortError');
  const signal = {
    reason,
    get aborted() { return aborted; },
    addEventListener(type) {
      assert.equal(type, 'abort');
      aborted = true;
    },
    removeEventListener(type) {
      assert.equal(type, 'abort');
      removes++;
    },
  };
  const op = resolvedOperation();
  await assert.rejects(
    awaitCancellableProducer(op.operation, signal),
    (error) => error === reason,
  );
  assert.equal(op.cancelCount(), 1, 'registration-race abort must cancel the producer once');
  assert.equal(removes, 1, 'registration-race abort must clean up its listener');
}

// If a real abort notification is delivered during registration, the
// post-registration recheck must not double-cancel or double-settle.
{
  let aborted = false;
  let removes = 0;
  const reason = new DOMException('registration-event', 'AbortError');
  const signal = {
    reason,
    get aborted() { return aborted; },
    addEventListener(type, listener) {
      assert.equal(type, 'abort');
      aborted = true;
      listener();
    },
    removeEventListener(type) {
      assert.equal(type, 'abort');
      removes++;
    },
  };
  const op = resolvedOperation();
  await assert.rejects(
    awaitCancellableProducer(op.operation, signal),
    (error) => error === reason,
  );
  assert.equal(op.cancelCount(), 1, 'event plus recheck must cancel the producer at most once');
  assert.equal(removes, 1, 'event plus recheck must settle and clean up once');
}

// Existing boundaries remain unchanged: pre-abort cancels before subscription,
// while a live non-aborted signal resolves normally and removes its listener.
{
  const reason = new DOMException('already-aborted', 'AbortError');
  let subscribed = 0;
  const signal = {
    reason,
    aborted:true,
    addEventListener() { subscribed++; },
    removeEventListener() {},
  };
  const op = resolvedOperation();
  await assert.rejects(
    awaitCancellableProducer(op.operation, signal),
    (error) => error === reason,
  );
  assert.equal(op.cancelCount(), 1);
  assert.equal(subscribed, 0);
}

{
  let listener = null;
  let removes = 0;
  const signal = {
    aborted:false,
    reason:undefined,
    addEventListener(type, value) {
      assert.equal(type, 'abort');
      listener = value;
    },
    removeEventListener(type, value) {
      assert.equal(type, 'abort');
      assert.equal(value, listener);
      removes++;
    },
  };
  const op = resolvedOperation('ok');
  assert.equal(await awaitCancellableProducer(op.operation, signal), 'ok');
  assert.equal(op.cancelCount(), 0);
  assert.equal(removes, 1);
}

console.log('issue-4213 cancellable producer abort registration race: PASS');
