import test from 'node:test';
import assert from 'node:assert/strict';

import { RemoteCollaborationGate } from '../../../js/collaboration/remote-authority.js';

const gate = (allowedActors) => new RemoteCollaborationGate({
  projectIdentity: 'project-A',
  sessionIdentity: 'session-A',
  allowedActors,
});

for (const permission of [[['*']], [['fact:name']], [{ token: '*' }], [1], [true], ['']]) {
  test(`structured or invalid permission ${JSON.stringify(permission)} fails closed`, () => {
    assert.throws(
      () => gate({ alice: permission }),
      (error) => error instanceof TypeError && error.message === 'remote-gate-permission-invalid',
    );
  });
}

test('explicit string wildcard remains authorized configuration', () => {
  const configured = gate({ alice: ['*'] });
  assert.deepEqual(configured.allowedActors.alice, ['*']);
});

test('normal string permissions retain dedupe and deterministic sort', () => {
  const configured = gate({ alice: ['fact:name', 'action:set', 'fact:name'] });
  assert.deepEqual(configured.allowedActors.alice, ['action:set', 'fact:name']);
});

test('Map permission configuration uses the same strict token boundary', () => {
  assert.throws(
    () => gate(new Map([['alice', [['*']]]])),
    (error) => error instanceof TypeError && error.message === 'remote-gate-permission-invalid',
  );
});
