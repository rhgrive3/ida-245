import assert from 'node:assert/strict';
import { CapabilityExecutor } from '../../../js/ai/capabilities/executor.js';
import { NoteStore } from '../../../js/names.js';

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

async function rejectsToolFailed(promise) {
  await assert.rejects(promise, (error) => error?.type === 'tool_failed');
}

class FailingStorage {
  constructor() {
    this.items = new Map();
    this.failWrites = false;
  }

  get length() { return this.items.size; }
  key(index) { return Array.from(this.items.keys())[index] ?? null; }
  getItem(key) { return this.items.get(String(key)) ?? null; }
  removeItem(key) { this.items.delete(String(key)); }
  setItem(key, value) {
    if (this.failWrites) {
      const error = new Error('storage quota exceeded');
      error.name = 'QuotaExceededError';
      throw error;
    }
    this.items.set(String(key), String(value));
  }
}

function installStorage(storage) {
  const previous = Object.getOwnPropertyDescriptor(globalThis, 'localStorage');
  Object.defineProperty(globalThis, 'localStorage', { configurable: true, value: storage });
  return () => {
    if (previous) Object.defineProperty(globalThis, 'localStorage', previous);
    else delete globalThis.localStorage;
  };
}

{
  let chromeUpdates = 0;
  let setCommentCalls = 0;
  let current = 'before';
  const executor = executorFor({
    notes: {
      setComment(_address, next) {
        setCommentCalls += 1;
        current = next;
        return false;
      },
    },
    updateChrome: () => { chromeUpdates += 1; },
  });
  await rejectsToolFailed(executor.execute(
    'annotation.comment',
    { address: '4096', value: 'approved note' },
    { authorization },
  ));
  assert.equal(setCommentCalls, 0, 'setter-only comment adapters must fail before mutation when rollback state cannot be captured');
  assert.equal(current, 'before', 'snapshot-unavailable comment adapters must not retain the rejected mutation');
  assert.equal(chromeUpdates, 0, 'failed comment persistence must not publish a UI success update');
}

{
  let symbolRenames = 0;
  const executor = executorFor({
    notes: {
      nameOf: () => 'before',
      setName: () => false,
    },
    symbols: { rename: () => { symbolRenames += 1; } },
  });
  await rejectsToolFailed(executor.execute(
    'annotation.rename',
    { address: '4096', value: 'after' },
    { authorization },
  ));
  assert.equal(symbolRenames, 0, 'failed name persistence must stop before the coupled symbol rename');
}

{
  let current = 'before';
  let setNameCalls = 0;
  let symbolRenames = 0;
  const executor = executorFor({
    notes: {
      nameOf: () => { throw new Error('snapshot unavailable'); },
      setName(_address, next) {
        setNameCalls += 1;
        current = next;
        return false;
      },
    },
    symbols: { rename: () => { symbolRenames += 1; } },
  });
  await rejectsToolFailed(executor.execute(
    'annotation.rename',
    { address: '4096', value: 'after' },
    { authorization },
  ));
  assert.equal(setNameCalls, 0, 'throwing name getters must fail before a stateful setter can mutate');
  assert.equal(current, 'before', 'throwing name getters must leave the previous state untouched');
  assert.equal(symbolRenames, 0, 'snapshot failure must stop before the coupled symbol rename');
}

{
  const notes = {
    structs: [],
    save: () => false,
  };
  const executor = executorFor({ notes });
  await rejectsToolFailed(executor.execute(
    'annotation.struct-field',
    { struct: 'Pair', offset: 0, field: 'left', type: 'int' },
    { authorization },
  ));
  assert.deepEqual(notes.structs, [], 'failed structure persistence must roll back the in-memory structure');
}

{
  const executor = executorFor({
    notes: { setType: () => false },
  });
  await rejectsToolFailed(executor.execute(
    'annotation.set-type',
    { address: '4096', key: 'return', value: 'int' },
    { authorization },
  ));
}

{
  let saved = 0;
  let renamed = 0;
  const app = {
    notes: {
      structs: [],
      comment: () => 'before',
      setComment: () => true,
      nameOf: () => 'before',
      setName: () => true,
      setType: () => true,
      save: () => { saved += 1; return true; },
    },
    symbols: { rename: () => { renamed += 1; } },
  };
  const executor = executorFor(app);
  assert.equal((await executor.execute(
    'annotation.comment',
    { address: '4096', value: 'ok' },
    { authorization },
  )).ok, true);
  assert.equal((await executor.execute(
    'annotation.rename',
    { address: '4096', value: 'renamed' },
    { authorization },
  )).ok, true);
  assert.equal((await executor.execute(
    'annotation.set-type',
    { address: '4096', key: 'return', value: 'int' },
    { authorization },
  )).ok, true);
  assert.equal((await executor.execute(
    'annotation.struct-field',
    { struct: 'Pair', offset: 0, field: 'left', type: 'int' },
    { authorization },
  )).ok, true);
  assert.equal(renamed, 1);
  assert.equal(saved, 1);
}

{
  let setNameCalls = 0;
  const executor = executorFor({
    notes: {
      nameOf: () => 'before',
      setName: () => {
        setNameCalls += 1;
        return setNameCalls === 1;
      },
    },
    symbols: {
      rename: () => { throw new Error('symbol rename failed'); },
    },
  });
  await assert.rejects(
    executor.execute(
      'annotation.rename',
      { address: '4096', value: 'after' },
      { authorization },
    ),
    (error) => error?.type === 'tool_failed' && /rolled back/i.test(error.message),
  );
  assert.equal(setNameCalls, 2, 'rename rollback must attempt to persist the previous note value');
}

{
  const storage = new FailingStorage();
  const restoreStorage = installStorage(storage);
  try {
    const notes = new NoteStore('issue-3758-comment');
    assert.equal(notes.setComment(4096n, 'before'), true);
    assert.equal(notes.dirty, false);

    storage.failWrites = true;
    await rejectsToolFailed(executorFor({ notes }).execute(
      'annotation.comment',
      { address: '4096', value: 'after' },
      { authorization },
    ));
    assert.equal(notes.comment(4096n), 'before', 'failed comment persistence must restore the previous in-memory value');
    assert.equal(notes.dirty, false, 'failed comment persistence must restore the previous dirty state');

    storage.failWrites = false;
    assert.equal(notes.save(), true);
    assert.equal(new NoteStore('issue-3758-comment').comment(4096n), 'before', 'later saves must not resurrect the rejected comment');
  } finally {
    restoreStorage();
  }
}

{
  const storage = new FailingStorage();
  const restoreStorage = installStorage(storage);
  try {
    const notes = new NoteStore('issue-3758-rename');
    assert.equal(notes.setName(4096n, 'before'), true);
    let symbolRenames = 0;

    storage.failWrites = true;
    await rejectsToolFailed(executorFor({
      notes,
      symbols: { rename: () => { symbolRenames += 1; } },
    }).execute(
      'annotation.rename',
      { address: '4096', value: 'after' },
      { authorization },
    ));
    assert.equal(notes.nameOf(4096n), 'before', 'failed rename persistence must restore the previous in-memory name');
    assert.equal(notes.dirty, false, 'failed rename persistence must restore the previous dirty state');
    assert.equal(symbolRenames, 0, 'failed NoteStore persistence must stop before symbol rename');

    storage.failWrites = false;
    assert.equal(notes.save(), true);
    assert.equal(new NoteStore('issue-3758-rename').nameOf(4096n), 'before', 'later saves must not resurrect the rejected name');
  } finally {
    restoreStorage();
  }
}

{
  const storage = new FailingStorage();
  const restoreStorage = installStorage(storage);
  try {
    const notes = new NoteStore('issue-3758-struct');
    notes.structs.push({ name: 'Pair', fields: [{ offset: 0, name: 'left', type: 'int' }] });
    notes.dirty = true;
    assert.equal(notes.save(), true);
    const executor = executorFor({ notes });

    storage.failWrites = true;
    for (const args of [
      { struct: 'Pair', offset: 0, field: 'right', type: 'long' },
      { struct: 'Pair', offset: 4, field: 'extra', type: 'int' },
      { struct: 'Fresh', offset: 0, field: 'first', type: 'int' },
    ]) {
      await rejectsToolFailed(executor.execute('annotation.struct-field', args, { authorization }));
      assert.deepEqual(
        notes.structs,
        [{ name: 'Pair', fields: [{ offset: 0, name: 'left', type: 'int' }] }],
        'failed structure persistence must restore replaced/added fields and newly-created structures',
      );
      assert.equal(notes.dirty, false, 'failed structure persistence must restore the previous dirty state');
    }

    storage.failWrites = false;
    assert.equal(notes.save(), true);
    assert.deepEqual(
      new NoteStore('issue-3758-struct').structs,
      [{ name: 'Pair', fields: [{ offset: 0, name: 'left', type: 'int' }] }],
      'later saves must not resurrect rejected structure mutations',
    );
  } finally {
    restoreStorage();
  }
}

console.log('issue-3758 AI annotation persistence regression: ok');
