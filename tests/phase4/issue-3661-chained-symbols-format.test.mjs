import assert from 'node:assert/strict';
import { deflateSync } from 'node:zlib';
import { chainedImportSymbols } from '../../js/chained.js';

function fixture({ symbolsFormat = 0, symbolPool = new TextEncoder().encode('_target\0') } = {}) {
  const thin = new Uint8Array(0x600);
  const dv = new DataView(thin.buffer);
  const vmaddr = 0x100000000n;
  const stub = vmaddr + 0x200n;
  const slot = vmaddr + 0x300n;

  // mach_header_64 with LC_SEGMENT_64 + LC_DYLD_CHAINED_FIXUPS.
  dv.setUint32(0, 0xfeedfacf, true);
  dv.setInt32(4, 0x0100000c, true);
  dv.setUint32(12, 2, true);
  dv.setUint32(16, 2, true);
  dv.setUint32(20, 168, true);

  const seg = 32;
  dv.setUint32(seg, 0x19, true);
  dv.setUint32(seg + 4, 152, true);
  new TextEncoder().encodeInto('__TEXT', thin.subarray(seg + 8, seg + 24));
  dv.setBigUint64(seg + 24, vmaddr, true);
  dv.setBigUint64(seg + 32, BigInt(thin.length), true);
  dv.setBigUint64(seg + 40, 0n, true);
  dv.setBigUint64(seg + 48, BigInt(thin.length), true);
  dv.setUint32(seg + 64, 1, true);

  const sec = seg + 72;
  new TextEncoder().encodeInto('__stubs', thin.subarray(sec, sec + 16));
  new TextEncoder().encodeInto('__TEXT', thin.subarray(sec + 16, sec + 32));
  dv.setBigUint64(sec + 32, stub, true);
  dv.setBigUint64(sec + 40, 12n, true);
  dv.setUint32(sec + 48, 0x200, true);
  dv.setUint32(sec + 64, 0x8, true);
  dv.setUint32(sec + 72, 12, true);

  const command = seg + 152;
  dv.setUint32(command, 0x80000034, true);
  dv.setUint32(command + 4, 16, true);
  dv.setUint32(command + 8, 0x400, true);
  dv.setUint32(command + 12, 0x80, true);

  // Conventional arm64 ADRP/LDR/BR stub and a chained bind pointer for ordinal 0.
  dv.setUint32(0x200, 0x90000010, true);
  dv.setUint32(0x204, 0xf9418210, true);
  dv.setUint32(0x208, 0xd61f0200, true);
  dv.setBigUint64(0x300, 1n << 63n, true);

  const fixups = 0x400;
  dv.setUint32(fixups + 4, 28, true);
  dv.setUint32(fixups + 8, 64, true);
  dv.setUint32(fixups + 12, 68, true);
  dv.setUint32(fixups + 16, 1, true);
  dv.setUint32(fixups + 20, 1, true);
  dv.setUint32(fixups + 24, symbolsFormat, true);
  dv.setUint32(fixups + 28, 1, true);
  dv.setUint32(fixups + 32, 8, true);
  dv.setUint32(fixups + 36, 24, true);
  dv.setUint16(fixups + 40, 0x1000, true);
  dv.setUint16(fixups + 42, 2, true);
  dv.setUint16(fixups + 56, 1, true);

  assert.ok(symbolPool.length <= 0x80 - 68, 'test symbol pool exceeds fixup payload');
  thin.set(symbolPool, fixups + 68);
  return { file: new Blob([thin]), stub, slot };
}

const uncompressed = fixture();
assert.deepEqual(await chainedImportSymbols(uncompressed.file, 0), [
  { addr: uncompressed.stub, name: '_target', kind: 1 },
  { addr: uncompressed.slot, name: '_target', kind: 2 },
], 'symbols_format=0 uncompressed recovery regressed');

const compressed = fixture({
  symbolsFormat: 1,
  symbolPool: deflateSync(Buffer.from('_target\0')),
});
assert.deepEqual(await chainedImportSymbols(compressed.file, 0), [],
  'symbols_format=1 compressed bytes were interpreted as an exact import name');

const unknown = fixture({ symbolsFormat: 2 });
assert.deepEqual(await chainedImportSymbols(unknown.file, 0), [],
  'unknown symbols_format was interpreted as an uncompressed symbol pool');

console.log('issue #3661 chained symbols-format regression: PASS');
