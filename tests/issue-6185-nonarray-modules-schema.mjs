/**
 * #6185 regression: `modules` capability adapters must strictly validate that
 * `getModules()` returns an array.
 *
 * Audit baseline `main@60980a3c` accepted non-array snapshots as success:
 * `DebugAdapterRuntimeProvider.openSession()` treated them as zero modules and
 * still promoted the session to `ready`, while
 * `DebuggerProvider.refreshModules()` returned `[]` as a success value and left
 * the previous active mappings in the table. Both production paths must
 * reject the schema violation with `runtime-invalid-modules` instead.
 */
import assert from 'node:assert/strict';
import test from 'node:test';

import { DebugAdapter } from '../js/debug/adapter.js';
import { DebugAdapterError } from '../js/debug/adapter.js';
import { DebugAdapterRuntimeProvider } from '../js/runtime/provider.js';
import { DebuggerProvider } from '../js/runtime/debugger-provider.js';

const VALID_MODULE = {
  id: 'm1',
  base: 0x1000n,
  size: 0x100n,
  staticBase: 0x4000n,
  binaryId: 'bin-A',
  identityState: 'exact',
};

function adapterWithModules(getModulesImplementation) {
  class ModulesAdapter extends DebugAdapter {
    constructor() {
      super({ id: 'schema-adapter', kind: 'test', capabilities: { modules: true } });
    }
    async getModules() {
      return getModulesImplementation();
    }
  }
  return new ModulesAdapter();
}

test('issue #6185 - initial empty array getModules is a valid ready session', async () => {
  const provider = new DebuggerProvider(adapterWithModules(() => []));
  const session = await provider.openSession({ binaryId: 'bin-A', sessionNonce: 's1' }, { connect: false });
  assert.equal(session.state, 'ready');
  assert.deepEqual(session.modules.active(), []);
  await session.close();
});

for (const malformed of [
  { id: 'm1', base: 0x1000n, size: 0x100n },
  'modules',
  42,
  null,
  false,
]) {
  test(`issue #6185 - initial non-array getModules (${malformed === null ? 'null' : typeof malformed}) must reject and not reach ready`, async () => {
    const provider = new DebuggerProvider(adapterWithModules(() => malformed));
    await assert.rejects(
      () => provider.openSession({ binaryId: 'bin-A', sessionNonce: 's1' }, { connect: false }),
      (error) => error instanceof DebugAdapterError && error.code === 'runtime-invalid-modules',
    );
  });
}

test('issue #6185 - refresh with valid array keeps existing diff-update semantics', async () => {
  let phase = 0;
  const provider = new DebuggerProvider(adapterWithModules(() => (phase === 0 ? [VALID_MODULE] : [])));
  const session = await provider.openSession({ binaryId: 'bin-A', sessionNonce: 's1' }, { connect: false });
  assert.ok(session.modules.get('m1'));

  phase = 1;
  const result = await session.facets.debugger.refreshModules();
  assert.deepEqual(result, []);
  assert.equal(session.modules.get('m1'), null, 'valid empty snapshot must unload retired modules');
  await session.close();
});

test('issue #6185 - refresh with non-array getModules must reject, never return [] success', async () => {
  let phase = 0;
  const provider = new DebuggerProvider(adapterWithModules(() => (phase === 0 ? [VALID_MODULE] : { malformed: true })));
  const session = await provider.openSession({ binaryId: 'bin-A', sessionNonce: 's1' }, { connect: false });
  assert.ok(session.modules.get('m1'));

  phase = 1;
  await assert.rejects(
    () => session.facets.debugger.refreshModules(),
    (error) => error instanceof DebugAdapterError && error.code === 'runtime-invalid-modules',
  );
  await session.close();
});

test('issue #6185 - rejected refresh must keep the previous active table (no partial state)', async () => {
  let phase = 0;
  const provider = new DebuggerProvider(adapterWithModules(() => (phase === 0 ? [VALID_MODULE] : { malformed: true })));
  const session = await provider.openSession({ binaryId: 'bin-A', sessionNonce: 's1' }, { connect: false });
  assert.ok(session.modules.get('m1'));

  phase = 1;
  await assert.rejects(() => session.facets.debugger.refreshModules());

  const binding = session.modules.get('m1');
  assert.ok(binding, 'stale mapping must remain explicitly, not laundered as a successful refresh');
  assert.equal(binding.generation, 1, 'failed refresh must not advance module generations');
  assert.equal(session.facets.debugger.resolveAddress(0x1010n, { binaryId: 'bin-A' }).state, 'exact');
  await session.close();
});

test('issue #6185 - plain DebugAdapterRuntimeProvider rejects non-array modules on open', async () => {
  const provider = new DebugAdapterRuntimeProvider(adapterWithModules(() => ({ not: 'an array' })));
  await assert.rejects(
    () => provider.openSession({ binaryId: 'bin-A', sessionNonce: 's1' }, { connect: false }),
    (error) => error.code === 'runtime-invalid-modules',
  );
});
