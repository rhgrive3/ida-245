import assert from 'node:assert/strict';
import test from 'node:test';

import { stableStringify } from '../../../js/core/identity/index.js';
import {
  RuntimeEventNormalizer,
  createRuntimeEvent,
} from '../../../js/runtime/events.js';

const context = {
  runtimeSessionId: 'runtime-6176',
  providerId: 'provider-6176',
  providerVersion: '1',
  sessionEpoch: 1,
};

test('#6176 accounts for canonical event size in UTF-8 bytes', () => {
  const payload = { text:'€'.repeat(400) };
  const input = { ...context, kind:'trace-marker', payload, completeness:'partial' };
  const expectedBytes = new TextEncoder().encode(stableStringify(createRuntimeEvent(input))).byteLength;
  assert.ok(expectedBytes > 1024);

  const normalizer = new RuntimeEventNormalizer(context, { maxBytes:expectedBytes });
  assert.ok(normalizer.push(input));
  assert.equal(normalizer.queuedBytes, expectedBytes);

  const rejected = new RuntimeEventNormalizer(context, { maxBytes:expectedBytes - 1 }).push(input);
  assert.equal(rejected, null);
});

test('#6176 does not let a heuristic preflight reject an in-budget numeric payload', () => {
  const payload = { values:Array(120).fill(0) };
  const input = { ...context, kind:'trace-marker', payload, completeness:'partial' };
  const expectedBytes = new TextEncoder().encode(stableStringify(createRuntimeEvent(input))).byteLength;
  assert.ok(expectedBytes <= 1024);

  const normalizer = new RuntimeEventNormalizer(context, { maxBytes:1024 });
  assert.ok(normalizer.push(input));
  assert.equal(normalizer.queuedBytes, expectedBytes);
});
