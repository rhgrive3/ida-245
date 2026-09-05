import assert from 'node:assert/strict';
import { parseDynamicSymbolVersions } from '../../js/binary/elf-extended.js';

const DT_VERSYM = 0x6ffffff0n;
const DT_VERDEF = 0x6ffffffcn;
const DT_VERDEFNUM = 0x6ffffffdn;
const DT_VERNEED = 0x6ffffffen;
const DT_VERNEEDNUM = 0x6fffffffn;
const BASE = 0x1000n;
const TABLE = 16;

function writeU16(bytes, offset, value) {
  bytes[offset] = value & 0xff;
  bytes[offset + 1] = (value >>> 8) & 0xff;
}
function writeU32(bytes, offset, value) {
  bytes[offset] = value & 0xff;
  bytes[offset + 1] = (value >>> 8) & 0xff;
  bytes[offset + 2] = (value >>> 16) & 0xff;
  bytes[offset + 3] = (value >>> 24) & 0xff;
}
function reader(bytes) {
  return {
    u16(offset) { return bytes[offset] | (bytes[offset + 1] << 8); },
    u32(offset) { return (bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)) >>> 0; },
  };
}
function imageFor(bytes) {
  return { segments: [{ address: BASE, fileOffset: 0, fileSize: bytes.length }], metadata: {}, warnings: [] };
}
function parseVerdef({ declared, records }) {
  const bytes = new Uint8Array(192);
  writeU16(bytes, 0, 2);
  for (let i = 0; i < records; i++) {
    const p = TABLE + i * 28;
    writeU16(bytes, p, 1);
    writeU16(bytes, p + 4, 2 + i);
    writeU16(bytes, p + 6, 1);
    writeU32(bytes, p + 12, 20);
    writeU32(bytes, p + 16, i + 1 < records ? 28 : 0);
    writeU32(bytes, p + 20, 10 + i);
  }
  const image = imageFor(bytes);
  const tags = new Map([[DT_VERSYM, [BASE]], [DT_VERDEF, [BASE + BigInt(TABLE)]], [DT_VERDEFNUM, [BigInt(declared)]]]);
  const names = new Map([[10n, 'VER_A'], [11n, 'VER_B']]);
  const out = parseDynamicSymbolVersions(reader(bytes), tags, image, 1, (offset) => names.get(offset) ?? null);
  return { out, image };
}
function parseVerneed({ declared, records }) {
  const bytes = new Uint8Array(224);
  writeU16(bytes, 0, 3);
  for (let i = 0; i < records; i++) {
    const p = TABLE + i * 32;
    writeU16(bytes, p, 1);
    writeU16(bytes, p + 2, 1);
    writeU32(bytes, p + 4, 20 + i);
    writeU32(bytes, p + 8, 16);
    writeU32(bytes, p + 12, i + 1 < records ? 32 : 0);
    writeU16(bytes, p + 16 + 6, 3 + i);
    writeU32(bytes, p + 16 + 8, 30 + i);
    writeU32(bytes, p + 16 + 12, 0);
  }
  const image = imageFor(bytes);
  const tags = new Map([[DT_VERSYM, [BASE]], [DT_VERNEED, [BASE + BigInt(TABLE)]], [DT_VERNEEDNUM, [BigInt(declared)]]]);
  const names = new Map([[20n, 'liba.so'], [21n, 'libb.so'], [30n, 'NEED_A'], [31n, 'NEED_B']]);
  const out = parseDynamicSymbolVersions(reader(bytes), tags, image, 1, (offset) => names.get(offset) ?? null);
  return { out, image };
}

{
  const { image } = parseVerdef({ declared: 1, records: 1 });
  assert.equal(image.metadata.programDynamicPartial, undefined);
  assert.equal(image.metadata.symbolVersions.complete, true);
}
{
  const { image } = parseVerdef({ declared: 1, records: 2 });
  assert.equal(image.metadata.programDynamicPartial, true);
  assert.equal(image.metadata.symbolVersions.complete, false);
  assert.ok(image.metadata.programDynamicDiagnostics.includes('DT_VERDEF chain continues past declared count 1'));
}
{
  const { image } = parseVerdef({ declared: 2, records: 2 });
  assert.equal(image.metadata.programDynamicPartial, undefined);
  assert.equal(image.metadata.symbolVersions.complete, true);
}
{
  const { image } = parseVerdef({ declared: 2, records: 1 });
  assert.equal(image.metadata.programDynamicPartial, true);
  assert.equal(image.metadata.symbolVersions.complete, false);
  assert.ok(image.metadata.programDynamicDiagnostics.includes('DT_VERDEFNUM declares 2 records but 1 were reachable'));
}
{
  const { image } = parseVerneed({ declared: 1, records: 1 });
  assert.equal(image.metadata.programDynamicPartial, undefined);
  assert.equal(image.metadata.symbolVersions.complete, true);
}
{
  const { image } = parseVerneed({ declared: 1, records: 2 });
  assert.equal(image.metadata.programDynamicPartial, true);
  assert.equal(image.metadata.symbolVersions.complete, false);
  assert.ok(image.metadata.programDynamicDiagnostics.includes('DT_VERNEED chain continues past declared count 1'));
}
{
  const { image } = parseVerneed({ declared: 2, records: 2 });
  assert.equal(image.metadata.programDynamicPartial, undefined);
  assert.equal(image.metadata.symbolVersions.complete, true);
}
{
  const { image } = parseVerneed({ declared: 2, records: 1 });
  assert.equal(image.metadata.programDynamicPartial, true);
  assert.equal(image.metadata.symbolVersions.complete, false);
  assert.ok(image.metadata.programDynamicDiagnostics.includes('DT_VERNEEDNUM declares 2 records but 1 were reachable'));
}
{
  const { image } = parseVerdef({ declared: 0, records: 0 });
  assert.equal(image.metadata.programDynamicPartial, undefined);
  assert.equal(image.metadata.symbolVersions.complete, true);
}
{
  const { image } = parseVerdef({ declared: 65_537, records: 1 });
  assert.equal(image.metadata.programDynamicPartial, true);
  assert.ok(image.metadata.programDynamicDiagnostics.includes('DT_VERDEFNUM declares 65537 records but 1 were reachable'));
}

console.log('issue #3663 ELF version chain count regression PASS');
