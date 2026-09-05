/**
 * #6163 regression: `DebuggerProvider.refreshModules()` must be transactional.
 *
 * Audit baseline `main@60980a3c` unloaded each replaced binding before the
 * replacement passed the binding table's strict validation, so a malformed
 * snapshot left the module table partially updated (old mapping retired, new
 * generation missing) even though the refresh rejected. The whole snapshot is
 * now staged through strict validation before any active binding changes.
 */
import assert from 'node:assert/strict';
import test from 'node:test';

import { DebugAdapter, DebugAdapterError } from '../js/debug/adapter.js';
import { DebuggerProvider } from '../js/runtime/debugger-provider.js';

function adapterWithPhases(snapshots) {
  let phase = 0;
  class PhasedAdapter extends DebugAdapter {
    constructor() {
      super({ id: 'transactional-adapter', kind: 'test', capabilities: { modules: true } });
    }
    async getModules() {
      return snapshots[Math.min(phase, snapshots.length - 1)];
    }
    advance() { phase += 1; }
  }
  return new PhasedAdapter();
}

test('issue #6163 - invalid replacement base rejects refresh and preserves the old active binding', async () => {
  const adapter = adapterWithPhases([
    [{ id: 'm1', base: 0x1000n, size: 0x100n, staticBase: 0x4000n, binaryId: 'bin-A', identityState: 'exact' }],
    [{ id: 'm1', runtimeBase: 1.5, runtimeSize: 0x100, staticBase: 0x4000, binaryId: 'bin-A', identityState: 'exact' }],
  ]);
  const provider = new DebuggerProvider(adapter);
  const session = await provider.openSession({ binaryId: 'bin-A', sessionNonce: 's1' }, { connect: false });
  const before = session.modules.get('m1');
  assert.equal(before.generation, 1);

  adapter.advance();
  await assert.rejects(
    () => session.facets.debugger.refreshModules(),
    (error) => error instanceof DebugAdapterError && error.code === 'invalid-address',
  );

  const after = session.modules.get('m1');
  assert.ok(after, 'old validated binding must survive a failed refresh');
  assert.equal(after.generation, 1, 'failed refresh must not advance generations');
  assert.equal(after.runtimeBase, 0x1000n);
  assert.equal(session.facets.debugger.resolveAddress(0x1010n, { binaryId: 'bin-A' }).state, 'exact');
  await session.close();
});

test('issue #6163 - mid-snapshot failure must not partially commit earlier modules', async () => {
  const adapter = adapterWithPhases([
    [
      { id: 'a', base: 0x1000n, size: 0x100n },
      { id: 'b', base: 0x2000n, size: 0x100n },
    ],
    [
      { id: 'a', base: 0x3000n, size: 0x100n },
      { id: 'b', base: 0x4000n, size: 0n },
    ],
  ]);
  const provider = new DebuggerProvider(adapter);
  const session = await provider.openSession({ binaryId: 'bin-A', sessionNonce: 's2' }, { connect: false });

  adapter.advance();
  await assert.rejects(
    () => session.facets.debugger.refreshModules(),
    (error) => error.code === 'invalid-size',
  );

  assert.equal(session.modules.get('a')?.generation, 1, 'module before the failure must keep its generation');
  assert.equal(session.modules.get('a')?.runtimeBase, 0x1000n);
  assert.equal(session.modules.get('b')?.generation, 1, 'failing module must keep its generation');
  assert.equal(session.modules.get('b')?.runtimeBase, 0x2000n);
  await session.close();
});

test('issue #6163 - zero-size, negative address, and invalid staticBase snapshots all roll back', async () => {
  for (const [code, malformed] of [
    ['invalid-size', { id: 'm1', base: 0x1000n, size: 0 }],
    ['invalid-address', { id: 'm1', base: -4, size: 0x100 }],
    ['invalid-address', { id: 'm1', base: 0x1000n, size: 0x100, staticBase: 'not-an-address' }],
  ]) {
    const adapter = adapterWithPhases([
      [{ id: 'm1', base: 0x1000n, size: 0x100n }],
      [malformed],
    ]);
    const provider = new DebuggerProvider(adapter);
    const session = await provider.openSession({ binaryId: 'bin-A', sessionNonce: 's3' }, { connect: false });

    adapter.advance();
    await assert.rejects(() => session.facets.debugger.refreshModules(), (error) => error.code === code);
    const binding = session.modules.get('m1');
    assert.ok(binding, `old binding must survive ${code}`);
    assert.equal(binding.generation, 1);
    await session.close();
  }
});

test('issue #6163 - fully valid snapshot still applies add/remove/change atomically', async () => {
  const adapter = adapterWithPhases([
    [
      { id: 'a', base: 0x1000n, size: 0x100n },
      { id: 'b', base: 0x2000n, size: 0x100n },
    ],
    [
      { id: 'a', base: 0x5000n, size: 0x100n },
      { id: 'c', base: 0x6000n, size: 0x100n },
    ],
  ]);
  const provider = new DebuggerProvider(adapter);
  const session = await provider.openSession({ binaryId: 'bin-A', sessionNonce: 's4' }, { connect: false });
  assert.deepEqual([...session.modules.active().map((m) => m.bindingKey)].sort(), ['a', 'b']);

  adapter.advance();
  const result = await session.facets.debugger.refreshModules();
  assert.equal(result.length, 2);
  assert.equal(session.modules.get('a').generation, 2, 'changed binding advances generation');
  assert.equal(session.modules.get('a').runtimeBase, 0x5000n);
  assert.equal(session.modules.get('b'), null, 'removed binding is unloaded');
  assert.equal(session.modules.get('c').generation, 1, 'added binding loads at generation 1');
  await session.close();
});
