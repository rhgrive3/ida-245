import assert from 'node:assert/strict';
import { createHexAIContext } from '../../../js/ai/ui/hex-context-legacy.js';

function baseApp() {
  return {
    store: { get() { return null; } },
    async ensureRecognition() {},
  };
}

{
  const app = {
    ...baseApp(),
    recognition: { records: [] },
    async ensureStrings() {
      return [
        { text:'x0', addr:0x10n },
        { text:'other', addr:0x15n },
        { text:'x1', addr:0x20n },
        { text:'x2', addr:0x30n },
      ];
    },
  };
  const ctx = createHexAIContext(app);
  for (const [offset, expected] of [[0, 'x0'], [1, 'x1'], [2, 'x2']]) {
    const page = await ctx.searchStrings('x', { limit:1, offset });
    assert.deepEqual(page.map((row) => row.text), [expected], `string offset ${offset}`);
  }
  assert.deepEqual(await ctx.searchStrings('x', { limit:1, offset:3 }), []);
}

{
  const records = [
    { address:0x1000n, name:'f0', score:3 },
    { address:0x1100n, name:'other', score:2 },
    { address:0x1200n, name:'f1', score:1 },
    { address:0x1300n, name:'f2', score:0 },
  ];
  const app = {
    ...baseApp(),
    recognition: {
      records,
      complete:true,
      scannedCount:records.length,
      total:records.length,
    },
  };
  const ctx = createHexAIContext(app);
  for (const [offset, expected] of [[0, 'f0'], [1, 'f1'], [2, 'f2']]) {
    const page = await ctx.searchFunctions('f', { limit:1, offset });
    assert.deepEqual(page.map((row) => row.name), [expected], `recognition offset ${offset}`);
  }
  const last = await ctx.searchFunctions('f', { limit:1, offset:2 });
  assert.equal(last.complete, true);
  assert.equal(last.truncationReason, null);
  const exhausted = await ctx.searchFunctions('f', { limit:1, offset:3 });
  assert.deepEqual([...exhausted], []);
  assert.equal(exhausted.complete, true);
}

{
  const app = {
    ...baseApp(),
    recognition: { records: [] },
    symbols: {
      names:['f0', 'other', 'f1', 'f2'],
      addrs:[0x2000n, 0x2100n, 0x2200n, 0x2300n],
    },
  };
  const ctx = createHexAIContext(app);
  for (const [offset, expected] of [[0, 'f0'], [1, 'f1'], [2, 'f2']]) {
    const page = await ctx.searchFunctions('f', { limit:1, offset });
    assert.deepEqual(page.map((row) => row.name), [expected], `symbol offset ${offset}`);
  }
  const last = await ctx.searchFunctions('f', { limit:1, offset:2 });
  assert.equal(last.complete, true);
  assert.equal(last.truncationReason, null);
  const exhausted = await ctx.searchFunctions('f', { limit:1, offset:3 });
  assert.deepEqual([...exhausted], []);
  assert.equal(exhausted.complete, true);
}

console.log('issue-3707-ai-legacy-pagination: ok');
