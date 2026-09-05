import assert from 'node:assert/strict';

import { KIND, ProgramIndex, mergeProgramScans } from '../js/program.js';

const scan = {
  regionId:'text',
  vmAddr:0x1000n,
  words:1,
  kinds:new Uint8Array([KIND.RET]),
  kindsCovered:1,
  callFrom:new BigUint64Array(0),
  callTo:new BigUint64Array(0),
  refFrom:new BigUint64Array(0),
  refTo:new BigUint64Array(0),
  refKind:new Uint8Array(0),
  completeness:{ complete:true, reasons:[] },
};

const inferred = mergeProgramScans([scan]);
assert.equal(inferred.complete, true);
assert.equal(inferred.truncated, false);
assert.deepEqual(inferred.completeness.reasons, []);
assert.equal(inferred.completeness.regionCount, 1);
assert.equal(inferred.completeness.expectedRegionCount, null);

const expected = mergeProgramScans([scan], {
  regions:[{ id:'text', vmAddr:0x1000n, size:4n }],
});
assert.equal(expected.complete, true);
assert.equal(expected.completeness.expectedRegionCount, 1);

const missing = mergeProgramScans([scan], {
  regions:[
    { id:'text', vmAddr:0x1000n, size:4n },
    { id:'cold', vmAddr:0x2000n, size:4n },
  ],
});
assert.equal(missing.complete, false);
assert.ok(missing.completeness.reasons.includes('program-region-unscanned:cold'));

// #3416: a cancelled regional scan is evidence that the aggregate is
// incomplete. It must not disappear just because cancelled scans contribute no
// edges/kinds to the merged payload.
const cancelledScan = {
  ...scan,
  regionId:'cold',
  vmAddr:0x2000n,
  cancelled:true,
};
const cancelled = mergeProgramScans([scan, cancelledScan]);
assert.equal(cancelled.complete, false);
assert.equal(cancelled.truncated, true);
assert.ok(cancelled.completeness.reasons.includes('cold:cancelled'));
assert.equal(cancelled.completeness.regionCount, 1, 'cancelled scan is not counted as successfully scanned');

// The expected-region route remains fail-closed for the same cancellation and
// retains the existing unscanned-region evidence in addition to cancellation.
const cancelledExpected = mergeProgramScans([scan, cancelledScan], {
  regions:[
    { id:'text', vmAddr:0x1000n, size:4n },
    { id:'cold', vmAddr:0x2000n, size:4n },
  ],
});
assert.equal(cancelledExpected.complete, false);
assert.ok(cancelledExpected.completeness.reasons.includes('cold:cancelled'));
assert.ok(cancelledExpected.completeness.reasons.includes('program-region-unscanned:cold'));

// #4546: expected regions with id:null must match actual address range rather than relying solely on counts.
const anonymousExpectedMismatch = mergeProgramScans([scan], {
  regions:[{ id:null, vmAddr:0n, size:4n }],
});
assert.equal(anonymousExpectedMismatch.complete, false, '#4546: mismatched anonymous address must not be complete');
assert.ok(anonymousExpectedMismatch.completeness.reasons.some((r) => r.startsWith('program-region-unscanned:')));

const anonymousExpectedMatch = mergeProgramScans([scan], {
  regions:[{ id:null, vmAddr:0x1000n, size:4n }],
});
assert.equal(anonymousExpectedMatch.complete, true, '#4546: matching anonymous address must be complete');

// #4934: structured / boolean / string values in options.limits must not coerce to numbers.
const scanWithEdges = {
  ...scan,
  callCount: 10,
  callFrom: new BigUint64Array(10),
  callTo: new BigUint64Array(10),
  refCount: 10,
  refFrom: new BigUint64Array(10),
  refTo: new BigUint64Array(10),
  refKind: new Uint8Array(10),
};
const structuredLimits = mergeProgramScans([scanWithEdges], {
  limits: {
    calls: true,
    refs: ['2'],
    kindWords: '3',
  },
});
assert.equal(structuredLimits.completeness.limits.calls, 10, '#4934: calls:true must fallback to default limits and retain available edges');
assert.equal(structuredLimits.completeness.limits.refs, 10, '#4934: refs:["2"] must fallback to default limits and retain available edges');
assert.equal(structuredLimits.completeness.limits.kindWords, 16 * 1024 * 1024, '#4934: kindWords:"3" must fallback to default');

const validLimits = mergeProgramScans([scanWithEdges], {
  limits: {
    calls: 5,
    refs: 5,
    kindWords: 100,
  },
});
assert.equal(validLimits.completeness.limits.calls, 5, '#4934: safe integer limits are respected');
assert.equal(validLimits.completeness.limits.refs, 5, '#4934: safe integer limits are respected');

// #3633: explicit transport counts must never flow into TypedArray.subarray
// as negative end offsets. Invalid explicit counts fail closed before graph
// cardinality can be silently rewritten while preserving complete:true.
const indexedScan = {
  callFrom: new BigUint64Array([0x1000n, 0x2000n, 0x3000n]),
  callTo: new BigUint64Array([0x4000n, 0x5000n, 0x6000n]),
  refFrom: new BigUint64Array([1n, 2n, 3n]),
  refTo: new BigUint64Array([4n, 5n, 6n]),
  refKind: new Uint8Array([1, 1, 1]),
  completeness: { complete:true, reasons:[] },
};
assert.throws(
  () => new ProgramIndex({ ...indexedScan, callCount:-1 }, null, null),
  (error) => error instanceof TypeError && error.message === 'program-call-count-invalid',
  '#3633: negative callCount must fail closed instead of becoming subarray(0, -1)',
);
assert.throws(
  () => new ProgramIndex({ ...indexedScan, refCount:-1 }, null, null),
  (error) => error instanceof TypeError && error.message === 'program-ref-count-invalid',
  '#3633: negative refCount must fail closed instead of becoming subarray(0, -1)',
);
assert.throws(
  () => new ProgramIndex({ ...indexedScan, callCount:'2' }, null, null),
  TypeError,
  '#3633: malformed explicit callCount must not be laundered into a complete graph',
);

const omittedCounts = new ProgramIndex(indexedScan, null, null);
assert.equal(omittedCounts.callCount, 3, '#3633: omitted callCount retains raw-array inference');
assert.equal(omittedCounts.refCount, 3, '#3633: omitted refCount retains raw-array inference');

const zeroCounts = new ProgramIndex({ ...indexedScan, callCount:0, refCount:0 }, null, null);
assert.equal(zeroCounts.callCount, 0, '#3633: explicit zero callCount remains valid');
assert.equal(zeroCounts.refCount, 0, '#3633: explicit zero refCount remains valid');

const positiveCounts = new ProgramIndex({ ...indexedScan, callCount:2, refCount:2 }, null, null);
assert.equal(positiveCounts.callCount, 2, '#3633: positive safe integer callCount remains valid');
assert.equal(positiveCounts.refCount, 2, '#3633: positive safe integer refCount remains valid');

const oversizedCounts = new ProgramIndex({ ...indexedScan, callCount:99, refCount:99 }, null, null);
assert.equal(oversizedCounts.callCount, 3, '#3633: callCount above raw cardinality preserves existing clamp semantics');
assert.equal(oversizedCounts.refCount, 3, '#3633: refCount above raw cardinality preserves existing clamp semantics');

const cardinalityMismatch = new ProgramIndex({
  ...indexedScan,
  callCount:3,
  callTo:new BigUint64Array([0x4000n, 0x5000n]),
  refCount:3,
  refKind:new Uint8Array([1]),
}, null, null);
assert.equal(cardinalityMismatch.callCount, 2, '#3633: call graph clamps to the shortest owned array');
assert.equal(cardinalityMismatch.refCount, 1, '#3633: ref graph clamps to the shortest owned array');

// #4144: supplied completeness metadata is an authority boundary. Only an
// explicit boolean true may assert source completeness; malformed explicit
// values must fail closed rather than becoming true through `!== false`.
const completenessScan = {
  callFrom:new BigUint64Array(0),
  callTo:new BigUint64Array(0),
  refFrom:new BigUint64Array(0),
  refTo:new BigUint64Array(0),
  refKind:new Uint8Array(0),
};
for (const malformed of ['false', [], {}, 0, 1, null, undefined]) {
  const program = new ProgramIndex({
    ...completenessScan,
    completeness:{ complete:malformed, reasons:[] },
  }, null, null);
  assert.equal(program.completeness.complete, false, `#4144: malformed completeness ${String(malformed)} must fail closed`);
  assert.equal(program.graphCompleteness.callsComplete, false, '#4144: malformed source completeness must not authorize calls');
  assert.equal(program.graphCompleteness.refsComplete, false, '#4144: malformed source completeness must not authorize refs');
  assert.equal(program.queryIncompleteReason, 'program-analysis-incomplete', '#4144: malformed source completeness must retain an incomplete query reason');
}

const explicitComplete = new ProgramIndex({
  ...completenessScan,
  completeness:{ complete:true, reasons:[] },
}, null, null);
assert.equal(explicitComplete.completeness.complete, true, '#4144: explicit boolean true remains complete');
assert.equal(explicitComplete.graphCompleteness.callsComplete, true, '#4144: explicit true still authorizes uncapped calls');
assert.equal(explicitComplete.graphCompleteness.refsComplete, true, '#4144: explicit true still authorizes uncapped refs');

const explicitIncomplete = new ProgramIndex({
  ...completenessScan,
  completeness:{ complete:false, reasons:['fixture-incomplete'] },
}, null, null);
assert.equal(explicitIncomplete.completeness.complete, false, '#4144: explicit boolean false remains incomplete');
assert.equal(explicitIncomplete.queryIncompleteReason, 'fixture-incomplete', '#4144: producer incomplete reason is preserved');

const legacyCompletenessFallback = new ProgramIndex(completenessScan, null, null);
assert.equal(legacyCompletenessFallback.completeness.complete, true, '#4144: omitted completeness metadata retains legacy uncapped fallback');

const legacyCappedFallback = new ProgramIndex({ ...completenessScan, callsCapped:true }, null, null);
assert.equal(legacyCappedFallback.completeness.complete, false, '#4144: omitted metadata still fails closed when the legacy source is capped');

console.log('issue #2059/#3416/#3633/#4144/#4546/#4934 program merge/index regressions passed');
