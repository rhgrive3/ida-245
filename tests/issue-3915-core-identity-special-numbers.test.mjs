import assert from 'node:assert/strict';
import {
  createEntityId,
  createEvidenceId,
} from '../js/core/identity/index.js';

const entityBase = {
  binaryId: 'bin-test',
  kind: 'numeric-identity',
};
const evidenceBase = {
  binaryId: 'bin-test',
  kind: 'numeric-identity',
};

function idFor(factory, base, value) {
  return factory({ ...base, identity: { value } });
}

for (const [label, factory, base] of [
  ['entity', createEntityId, entityBase],
  ['evidence', createEvidenceId, evidenceBase],
]) {
  const nan = idFor(factory, base, NaN);
  const positiveInfinity = idFor(factory, base, Infinity);
  const negativeInfinity = idFor(factory, base, -Infinity);

  assert.equal(
    new Set([nan, positiveInfinity, negativeInfinity]).size,
    3,
    `${label} identity must preserve NaN/+Infinity/-Infinity distinctions`,
  );

  assert.notEqual(
    idFor(factory, base, 0),
    idFor(factory, base, -0),
    `${label} identity must preserve +0/-0 distinction`,
  );

  assert.notEqual(
    factory({ ...base, identity: { nested: [NaN, -0] } }),
    factory({ ...base, identity: { nested: [Infinity, 0] } }),
    `${label} identity must preserve special-number distinctions when nested`,
  );

  assert.notEqual(
    idFor(factory, base, 1n),
    idFor(factory, base, '1'),
    `${label} BigInt/string type witness must remain intact`,
  );
  assert.notEqual(
    idFor(factory, base, new Uint8Array([1, 2])),
    idFor(factory, base, [1, 2]),
    `${label} typed-bytes/array type witness must remain intact`,
  );
  assert.notEqual(
    idFor(factory, base, new Date('2026-01-02T03:04:05.000Z')),
    idFor(factory, base, '2026-01-02T03:04:05.000Z'),
    `${label} Date/string type witness must remain intact`,
  );
}

// Ordinary JSON-safe numeric identities do not gain a witness and therefore
// retain their exact persisted IDs.
const ordinaryIdentity = { value: 42, nested: ['x', 1] };
assert.equal(
  createEntityId({ ...entityBase, identity: ordinaryIdentity }),
  'entity_bdc61ae78bd9dc1442f835c728542895',
  'ordinary EntityId material must keep its persisted identity',
);
assert.equal(
  createEvidenceId({ ...evidenceBase, identity: ordinaryIdentity }),
  'evidence_0226f2e20287756d1f27a40a25c73eca',
  'ordinary EvidenceId material must keep its persisted identity',
);

console.log('issue #3915 core identity special-number regression PASS');
