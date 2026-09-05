import assert from 'node:assert/strict';
import { fingerprintImage, fingerprintFunction } from '../js/binary/fingerprint.js';

// 1. resident mapping fileSize > available bytes -> throws RangeError
{
  const buffer = new Uint8Array(0x100);
  const image = {
    bytes: buffer,
    sections: [],
    segments: [{
      name: 'LOAD1',
      address: 0x1000n,
      fileOffset: 0n,
      fileSize: 0x200n, // exceeds buffer length 0x100
      perms: { read: true, write: false, execute: true },
    }],
  };
  assert.throws(
    () => fingerprintImage(image),
    (err) => err instanceof RangeError && err.message === 'binary-fingerprint-short-read',
    'resident short read must throw RangeError(binary-fingerprint-short-read)'
  );
}

// 2. 0-byte available chunk for non-zero mapping -> throws RangeError, not empty hash
{
  const buffer = new Uint8Array(0);
  const image = {
    bytes: buffer,
    sections: [{
      name: '.text',
      source: 'section-header',
      flags: 0x6n,
      address: 0x1000n,
      fileOffset: 0x10n,
      fileSize: 0x100n,
      perms: { read: true, write: false, execute: true },
    }],
    segments: [],
  };
  assert.throws(
    () => fingerprintImage(image),
    (err) => err instanceof RangeError && err.message === 'binary-fingerprint-short-read',
  );
}

// 3. middle chunk short/null -> does not return partial prefix hash
{
  const buffer = new Uint8Array(0x5000);
  const image = {
    bytes: buffer,
    sections: [],
    segments: [{
      name: 'LOAD1',
      address: 0x1000n,
      fileOffset: 0x2000n,
      fileSize: 0x4000n, // 0x2000 + 0x4000 = 0x6000 > buffer length 0x5000
      perms: { read: true, write: false, execute: true },
    }],
  };
  assert.throws(
    () => fingerprintImage(image, { chunkBytes: 0x1000 }),
    (err) => err instanceof RangeError && err.message === 'binary-fingerprint-short-read',
  );
}

// 4. source-backed short read -> throws RangeError
{
  const image = {
    source: {
      async readExactly(_offset, length) {
        // Return short chunk
        return new Uint8Array(length - 1);
      },
    },
    sections: [],
    segments: [{
      name: 'LOAD1',
      address: 0x1000n,
      fileOffset: 0n,
      fileSize: 0x1000n,
      perms: { read: true, write: false, execute: true },
    }],
  };
  await assert.rejects(
    () => fingerprintImage(image),
    (err) => err instanceof RangeError && err.message === 'binary-fingerprint-short-read',
    'source-backed short read must reject with RangeError'
  );
}

// 5. valid resident and source-backed return identical digest
{
  const buffer = new Uint8Array(0x2000);
  for (let i = 0; i < buffer.length; i++) buffer[i] = (i * 17) & 0xff;

  const seg = {
    name: 'LOAD1',
    address: 0x1000n,
    fileOffset: 0n,
    fileSize: 0x2000n,
    perms: { read: true, write: false, execute: true },
  };

  const resImg = { bytes: buffer, sections: [], segments: [seg] };
  const srcImg = {
    source: {
      async readExactly(offset, length) {
        return buffer.subarray(Number(offset), Number(offset) + length);
      },
    },
    sections: [],
    segments: [seg],
  };

  const resFp = fingerprintImage(resImg);
  const srcFp = await fingerprintImage(srcImg);
  assert.equal(resFp.hash, srcFp.hash);
  assert.equal(resFp.bytes, 0x2000);
  assert.equal(srcFp.bytes, 0x2000);
}

// 6. fingerprintFunction() existing truncated semantics preserved
{
  const buffer = new Uint8Array(0x20);
  const image = {
    bytes: buffer,
    readVirtual(_addr, len) {
      return buffer.subarray(0, Math.min(buffer.length, len));
    },
  };
  const fn = { address: 0x1000n, size: 0x40n };
  const result = fingerprintFunction(image, fn, { maxBytes: 0x10 });
  assert.ok(result);
  assert.equal(result.truncated, true, 'function fingerprint should retain truncated: true');
  assert.equal(result.bytes, 0x10);
}

// 7. chunkBytes bounds respected
{
  const buffer = new Uint8Array(0x1000);
  const image = {
    bytes: buffer,
    sections: [],
    segments: [{
      name: 'LOAD1',
      address: 0x1000n,
      fileOffset: 0n,
      fileSize: 0x1000n,
      perms: { read: true, write: false, execute: true },
    }],
  };
  const result = fingerprintImage(image, { chunkBytes: 512 });
  assert.equal(result.bytes, 0x1000);
  assert.ok(result.hash);
}

console.log('issue #6159 fingerprint short read fail closed tests: PASS');
