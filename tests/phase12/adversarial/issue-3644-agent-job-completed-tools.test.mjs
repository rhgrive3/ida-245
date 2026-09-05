import assert from 'node:assert/strict';
import test from 'node:test';
import { AgentJobManager } from '../../../js/ai/jobs/index.js';

function memoryPersistence() {
  const records = new Map();
  return {
    async save(job) { records.set(job.id, structuredClone(job)); },
    async load(id) { return records.has(id) ? structuredClone(records.get(id)) : null; },
  };
}

function result(activity, { exhausted = true } = {}) {
  return {
    answer: '',
    activity,
    limits: { exhausted, reason: exhausted ? 'tool_failed' : null },
    usage: { modelCalls: 0, toolCalls: 0, elapsedMs: 0, contextBytes: 0 },
  };
}

test('AgentJobManager records only tool-result activity as completed', async () => {
  const runtime = {
    async turn() {
      return result([
        { type: 'tool-start', tool: 'failed_tool' },
        { type: 'error', errorType: 'tool_failed' },
        { type: 'tool-start', label: 'anonymous tool running' },
        { type: 'tool-start', tool: 'ok_tool' },
        { type: 'tool-result', tool: 'ok_tool', label: 'done' },
      ]);
    },
  };
  const manager = new AgentJobManager({ runtime });
  const job = await manager.create({ jobId: 'issue-3644-direct', goal: 'test' });
  const checkpoint = await manager.runSlice(job.id);

  assert.deepEqual(checkpoint.completedTools, ['ok_tool']);
  assert.equal(checkpoint.status, 'checkpointed');
});

test('completedTools semantics survive checkpoint reload and resume', async () => {
  const persistence = memoryPersistence();
  let turn = 0;
  const runtime = {
    async turn() {
      turn += 1;
      if (turn === 1) {
        return result([
          { type: 'tool-start', tool: 'retry_tool' },
          { type: 'error', errorType: 'tool_failed' },
        ]);
      }
      return result([
        { type: 'tool-start', tool: 'retry_tool' },
        { type: 'tool-result', tool: 'retry_tool', label: 'done' },
      ], { exhausted: false });
    },
  };

  const firstManager = new AgentJobManager({ runtime, persistence });
  const job = await firstManager.create({ jobId: 'issue-3644-resume', goal: 'test' });
  const interrupted = await firstManager.runSlice(job.id);
  assert.deepEqual(interrupted.completedTools, []);

  const resumedManager = new AgentJobManager({ runtime, persistence });
  const completed = await resumedManager.resume(job.id);
  assert.deepEqual(completed.completedTools, ['retry_tool']);
  assert.equal(completed.status, 'complete');
});
