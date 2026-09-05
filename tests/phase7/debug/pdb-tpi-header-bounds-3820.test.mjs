import test from 'node:test';
import assert from 'node:assert/strict';

import { parseTpiStream } from '../../../js/analysis/debug/pdb.js';

const makeTpi = (length, headerSize, firstIndex = 0x1000) => {
  const bytes = new Uint8Array(length);
  const view = new DataView(bytes.buffer);
  view.setUint32(4, headerSize, true);
  view.setUint32(8, firstIndex, true);
  return bytes;
};

test('TPI headerSize beyond the stream fails closed', () => {
  const bytes = makeTpi(56, 0xffffffff, 0x1234);
  const parsed = parseTpiStream(bytes);

  assert.equal(parsed.complete, false);
  assert.equal(parsed.types.size, 0);
  assert.equal(parsed.firstIndex, 0x1234);
});

test('TPI headerSize below the supported 56-byte header cannot expose header bytes as records', () => {
  const bytes = makeTpi(56, 52);
  // If offset 52 were trusted, these final four header bytes form a complete
  // LF_ARGLIST record and the old parser would report complete:true.
  bytes.set([0x02, 0x00, 0x01, 0x12], 52);

  const parsed = parseTpiStream(bytes);
  assert.equal(parsed.complete, false);
  assert.equal(parsed.types.size, 0);
  assert.equal(parsed.firstIndex, 0x1000);
});

test('the canonical 56-byte empty TPI header remains complete', () => {
  const parsed = parseTpiStream(makeTpi(56, 56));
  assert.equal(parsed.complete, true);
  assert.equal(parsed.types.size, 0);
});

test('a bounded extended header still starts records at its declared offset', () => {
  const bytes = makeTpi(64, 60);
  // length=2, LF_ARGLIST. The four extension bytes at 56..59 are skipped.
  bytes.set([0x02, 0x00, 0x01, 0x12], 60);

  const parsed = parseTpiStream(bytes);
  assert.equal(parsed.complete, true);
  assert.equal(parsed.types.size, 1);
  assert.equal(parsed.types.get(0x1000)?.kind, 'arg-list');
});
