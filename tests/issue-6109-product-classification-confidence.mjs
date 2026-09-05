import assert from 'node:assert/strict';
import { createProductSurfaceQueries } from '../js/analysis/query/product-surface.js';

const SNAPSHOT = Object.freeze({ snapshotId:'issue-6109', analysisEpoch:1 });

function appFor(confidence, local = null) {
  return {
    analysisQueries:{ snapshot:async () => SNAPSHOT },
    recognition:{ records:[{ address:0x1000n, classification:'APPLICATION', confidence, evidence:[] }] },
    analyzeFunctionAt:async () => local,
  };
}

async function classification(confidence, local = null) {
  const query = createProductSurfaceQueries(appFor(confidence, local));
  return query.classification(SNAPSHOT, 0x1000n);
}

for (const confidence of [0, 0.35, 1]) {
  const result = await classification(confidence);
  assert.equal(result.value.confidence, confidence);
  assert.equal(result.value.base.confidence, confidence);
}

for (const confidence of [true, '0.9', ['0.9'], {}, Infinity, NaN, 2, -1]) {
  const result = await classification(confidence);
  assert.equal(result.value.confidence, 0);
  assert.equal(result.value.base.confidence, 0);
}

// The sanitized base record must remain safe even when semantic refinement runs.
const refined = await classification(true, { model:{ instructions:[], blocks:[] }, semanticFacts:{} });
assert.equal(refined.value.base.confidence, 0);
assert.notEqual(refined.value.base.confidence, true);

console.log('issue #6109 product classification confidence validation: PASS');
