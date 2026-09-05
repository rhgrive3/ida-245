import assert from 'node:assert/strict';
import { CapabilityExecutor } from '../../../js/ai/capabilities/executor.js';

const authorization = { kind: 'proposal', token: 'approved-token' };

function executorFor(app) {
  return new CapabilityExecutor({
    app,
    catalog: {
      get(id) {
        return {
          id,
          agentExposed: true,
          requiresApproval: true,
          inputSchema: { type: 'object' },
          category: 'annotation',
        };
      },
    },
  });
}

async function assertMissingSaveFailsClosed(notes, args) {
  const beforeStructs = structuredClone(notes.structs);
  const beforeDirty = notes.dirty;

  await assert.rejects(
    executorFor({ notes }).execute('annotation.struct-field', args, { authorization }),
    (error) => error?.type === 'tool_failed' && /adapter is unavailable/i.test(error.message),
  );

  assert.deepEqual(notes.structs, beforeStructs, 'missing persistence adapter must not mutate structure state');
  assert.equal(notes.dirty, beforeDirty, 'missing persistence adapter must preserve the previous dirty state');
}

await assertMissingSaveFailsClosed(
  {
    structs: [{ name: 'Pair', fields: [{ offset: 0, name: 'left', type: 'int' }] }],
    dirty: false,
  },
  { struct: 'Pair', offset: 4, field: 'right', type: 'int' },
);

await assertMissingSaveFailsClosed(
  { structs: [], dirty: false },
  { struct: 'Fresh', offset: 0, field: 'first', type: 'int' },
);

console.log('issue-3758 annotation save adapter regression: ok');
