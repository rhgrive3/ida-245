import assert from 'node:assert/strict';
import { CapabilityCatalog } from '../../../js/ai/capabilities/catalog.js';
import { auditCapabilityParity } from '../../../js/ai/capabilities/parity.js';

const valid = {
  id: 'custom.valid',
  category: 'human-only',
  agentExposed: false,
  humanOnlyReason: 'browser-security-user-gesture:fixture',
};

assert.equal(auditCapabilityParity([valid]).ok, true);
assert.equal(auditCapabilityParity([valid]).checked, 1);

for (const id of [1, true, {}, [], '']) {
  const result = auditCapabilityParity([{ ...valid, id }]);
  assert.equal(result.ok, false);
  assert.equal(result.failures[0].reason, 'invalid-id');
}

const semanticDuplicate = auditCapabilityParity([
  { ...valid, id: 1 },
  { ...valid, id: '1' },
]);
assert.equal(semanticDuplicate.ok, false);
assert.ok(semanticDuplicate.failures.some((failure) => failure.reason === 'invalid-id'));

const duplicate = auditCapabilityParity([valid, { ...valid, humanOnlyReason: `${valid.humanOnlyReason}:again` }]);
assert.equal(duplicate.ok, false);
assert.equal(duplicate.failures[0].reason, 'missing-or-duplicate-id');

const catalog = new CapabilityCatalog([valid, { ...valid, id: ' custom.trimmed ' }]);
assert.notEqual(catalog.get('custom.valid'), valid);
assert.equal(catalog.get('custom.valid').id, 'custom.valid');
assert.equal(catalog.get('custom.valid').humanOnlyReason, valid.humanOnlyReason);
assert.equal(catalog.get('custom.trimmed').id, 'custom.trimmed');
assert.equal(catalog.get(1), null);
assert.equal(catalog.has({ toString:() => 'custom.valid' }), false);
assert.throws(() => new CapabilityCatalog([{ ...valid, id: 1 }]), /invalid capability id/);
assert.throws(() => new CapabilityCatalog([valid, { ...valid }]), /duplicate capability id/);

let catalogIdReads = 0;
const statefulCatalogEntry = {
  ...valid,
  get id() {
    catalogIdReads++;
    return catalogIdReads === 1 ? 'custom.stateful' : 1;
  },
};
const statefulCatalog = new CapabilityCatalog([statefulCatalogEntry]);
assert.equal(catalogIdReads, 1);
assert.equal(statefulCatalog.get('custom.stateful').id, 'custom.stateful');
assert.equal(statefulCatalog.get(1), null);
assert.notEqual(statefulCatalog.get('custom.stateful'), statefulCatalogEntry);

let parityIdReads = 0;
const statefulParityEntry = {
  ...valid,
  get id() {
    parityIdReads++;
    return parityIdReads === 1 ? 'custom.parity' : 1;
  },
};
const statefulParity = auditCapabilityParity([statefulParityEntry]);
assert.equal(statefulParity.ok, true);
assert.equal(statefulParity.checked, 1);
assert.equal(parityIdReads, 1);

console.log('issue #6170 capability parity ID validation: PASS');
