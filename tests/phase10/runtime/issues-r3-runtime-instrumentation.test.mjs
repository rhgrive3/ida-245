// Required Phase 10 denominator wiring for the runtime/instrumentation R3 lane.
// The root regressions stay independently runnable while `npm run check`
// executes them through the recursive Phase 10 runner.
import '../../issue-6163-transactional-module-refresh.mjs';
import '../../issue-6177-debug-authority-provenance.test.mjs';
import '../../issue-6185-nonarray-modules-schema.mjs';

import assert from 'node:assert/strict';
import test from 'node:test';
import { DebugAdapter, DebugAdapterError } from '../../../js/debug/adapter.js';
import { DebuggerProvider } from '../../../js/runtime/debugger-provider.js';

function adapterWithPhases(snapshots) {
  let phase = 0;
  class PhasedAdapter extends DebugAdapter {
    constructor() {
      super({ id: 'duplicate-binding-adapter', kind: 'test', capabilities: { modules: true } });
    }
    async getModules() {
      return snapshots[Math.min(phase, snapshots.length - 1)];
    }
    advance() { phase += 1; }
  }
  return new PhasedAdapter();
}

async function assertDuplicateSnapshotRejected(duplicateSnapshot, sessionNonce) {
  const adapter = adapterWithPhases([
    [{ id: 'stable', base: 0x1000n, size: 0x100n, staticBase: 0x4000n, binaryId: 'bin-A', identityState: 'exact' }],
    duplicateSnapshot,
  ]);
  const provider = new DebuggerProvider(adapter);
  const session = await provider.openSession({ binaryId: 'bin-A', sessionNonce }, { connect: false });
  const before = session.modules.get('stable');
  assert.ok(before);
  assert.equal(before.generation, 1);
  assert.equal(before.runtimeBase, 0x1000n);

  adapter.advance();
  await assert.rejects(
    () => session.facets.debugger.refreshModules(),
    (error) => error instanceof DebugAdapterError && error.code === 'module-binding-already-loaded',
  );

  const after = session.modules.get('stable');
  assert.ok(after, 'active binding must survive duplicate-snapshot rejection');
  assert.equal(after.generation, 1, 'duplicate rejection must not advance active generations');
  assert.equal(after.runtimeBase, 0x1000n);
  assert.equal(session.modules.get('dup'), null, 'duplicate snapshot must not publish a replacement binding');
  assert.equal(session.facets.debugger.resolveAddress(0x1010n, { binaryId: 'bin-A' }).state, 'exact');
  await session.close();
}

test('issue #6163 - duplicate canonical module IDs reject before active-table mutation', async () => {
  await assertDuplicateSnapshotRejected([
    { id: 'dup', base: 0x2000n, size: 0x100n },
    { id: 'dup', base: 0x3000n, size: 0x100n },
  ], 'duplicate-id');
});

test('issue #6163 - whitespace-normalized module IDs reject before active-table mutation', async () => {
  await assertDuplicateSnapshotRejected([
    { id: ' dup ', base: 0x2000n, size: 0x100n },
    { id: 'dup', base: 0x3000n, size: 0x100n },
  ], 'duplicate-normalized-id');
});
