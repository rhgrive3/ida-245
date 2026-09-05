import assert from 'node:assert/strict';
import { PlatformPluginRegistry } from '../js/platform/plugin-api.js';

{
  const registry = new PlatformPluginRegistry();
  const malformedIds = [
    ['format.demo'],
    { toString() { return 'format.demo'; } },
    12345,
    true,
    false,
    null,
    undefined,
    Symbol('format.demo'),
  ];

  for (const id of malformedIds) {
    assert.throws(
      () => registry.registerFormat(id, { detect: () => true }),
      /plugin contribution id must be stable and non-empty/,
    );
    assert.throws(
      () => registry.registerAnalyzer(id, { analyze: async () => ({}) }),
      /plugin contribution id must be stable and non-empty/,
    );
  }
  assert.equal(registry.list('format').length, 0);
  assert.equal(registry.list('analyzer').length, 0);

  const unregister = registry.registerFormat('format.demo', { detect: () => true });
  assert.equal(registry.list('format')[0].id, 'format.demo');
  unregister();
}

{
  assert.equal(new PlatformPluginRegistry().timeoutMs, 15_000);
  assert.equal(new PlatformPluginRegistry({ timeoutMs: null }).timeoutMs, 15_000);
  assert.equal(new PlatformPluginRegistry({ timeoutMs: 25 }).timeoutMs, 25);

  const malformed = [1.5, 0, -1, NaN, Infinity, '25', ['25'], true, { valueOf: () => 25 }];
  for (const timeoutMs of malformed) {
    assert.throws(
      () => new PlatformPluginRegistry({ timeoutMs }),
      /plugin timeoutMs must be a positive safe integer/,
    );
  }
}

{
  const registry = new PlatformPluginRegistry({ timeoutMs: 50 });
  let pluginCalls = 0;
  let hostReads = 0;
  registry.registerFormat('format.read-budget', {
    async detect(context, length = 1) {
      pluginCalls++;
      return context.read(0n, length);
    },
  });
  const context = (policy) => ({
    pluginPolicy: { binaryRead: true, ...policy },
    read: async (_at, length) => {
      hostReads++;
      return new Uint8Array(length);
    },
  });

  for (const value of [1.5, 0, -1, NaN, Infinity, '1', ['1'], true, { valueOf: () => 1 }]) {
    const result = await registry.invoke(
      'format',
      'format.read-budget',
      'detect',
      context({ maxReadBytes: value }),
    );
    assert.equal(result.ok, false);
    assert.match(result.error, /plugin maxReadBytes must be a positive safe integer/);
  }
  assert.equal(pluginCalls, 0, 'invalid explicit authority must fail before plugin execution');
  assert.equal(hostReads, 0, 'invalid explicit authority must fail before host reads');

  const inherited = await registry.invoke(
    'format',
    'format.read-budget',
    'detect',
    context({ maxReadBytes: null, maxTotalReadBytes: undefined }),
    32,
  );
  assert.equal(inherited.ok, true, 'nullish authority inherits the documented default');

  const valid = await registry.invoke(
    'format',
    'format.read-budget',
    'detect',
    context({ maxReadBytes: 64, maxTotalReadBytes: 128 }),
    64,
  );
  assert.equal(valid.ok, true);

  for (const length of [['1'], '1', true, { valueOf: () => 1 }, 1.5]) {
    const result = await registry.invoke(
      'format',
      'format.read-budget',
      'detect',
      context({ maxReadBytes: 64, maxTotalReadBytes: 128 }),
      length,
    );
    assert.equal(result.ok, false);
    assert.match(result.error, /plugin read length must be an integer/);
  }

  const negative = await registry.invoke(
    'format',
    'format.read-budget',
    'detect',
    context({ maxReadBytes: 64, maxTotalReadBytes: 128 }),
    -1,
  );
  assert.equal(negative.ok, false);
  assert.match(negative.error, /exceeds per-call limit/);
}

{
  const registry = new PlatformPluginRegistry({ timeoutMs: 30 });
  let calls = 0;
  registry.registerFormat('format.timeout', {
    async detect() {
      calls++;
      return true;
    },
  });

  for (const timeoutMs of [1.5, 0, -1, NaN, Infinity, '30', ['30'], true, { valueOf: () => 30 }]) {
    const result = await registry.invoke('format', 'format.timeout', 'detect', {}, { timeoutMs });
    assert.equal(result.ok, false);
    assert.match(result.error, /plugin timeoutMs must be a positive safe integer/);
  }
  assert.equal(calls, 0, 'invalid invocation timeout must fail before plugin execution');

  const valid = await registry.invoke('format', 'format.timeout', 'detect', {}, { timeoutMs: 30 });
  assert.equal(valid.ok, true);
}
