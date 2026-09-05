import assert from 'node:assert/strict';
import { collectRelrRelocations } from '../../js/binary/elf-extended.js';

const DT_RELRSZ = 35n;
const DT_RELR = 36n;
const DT_RELRENT = 37n;
const BASE = 0x1000n;

function makeReader(entries) {
  const bytes = new Uint8Array(entries.length * 8);
  const view = new DataView(bytes.buffer);
  entries.forEach((entry, index) => view.setBigUint64(index * 8, entry, true));
  return {
    bytes,
    u64(offset) { return view.getBigUint64(offset, true); },
    u32(offset) { return view.getUint32(offset, true); },
  };
}

function run(entries) {
  const reader = makeReader(entries);
  const image = {
    segments: [{ address: BASE, fileOffset: 0n, fileSize: BigInt(reader.bytes.length) }],
    metadata: {},
    warnings: [],
  };
  const tags = new Map([
    [DT_RELR, [BASE]],
    [DT_RELRSZ, [BigInt(reader.bytes.length)]],
    [DT_RELRENT, [8n]],
  ]);
  const out = collectRelrRelocations(reader, tags, image, 64);
  return { out, image };
}

{
  const { out, image } = run([0x3n]);
  assert.deepEqual(out, [], 'a leading RELR bitmap must not synthesize address zero');
  assert.equal(image.metadata.programDynamicPartial, true);
  assert.ok(image.metadata.programDynamicDiagnostics?.includes('DT_RELR bitmap entry appears before any address entry'));
}

{
  const { out, image } = run([0x1n]);
  assert.deepEqual(out, [], 'even an empty leading bitmap has no valid base provenance');
  assert.equal(image.metadata.programDynamicPartial, true);
}

{
  const { out, image } = run([0x2000n]);
  assert.deepEqual(out.map((reloc) => reloc.address), [0x2000n]);
  assert.equal(image.metadata.programDynamicPartial, undefined);
}

{
  const { out, image } = run([0x2000n, 0x3n]);
  assert.deepEqual(out.map((reloc) => reloc.address), [0x2000n, 0x2008n]);
  assert.equal(image.metadata.programDynamicPartial, undefined);
}

{
  const { out, image } = run([0x2000n, 0x3n, 0x5n]);
  assert.deepEqual(out.map((reloc) => reloc.address), [0x2000n, 0x2008n, 0x2208n], 'subsequent bitmaps must retain the existing RELR base advance');
  assert.equal(image.metadata.programDynamicPartial, undefined);
}

console.log('issue #3659 ELF RELR leading bitmap regression PASS');
