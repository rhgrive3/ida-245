import assert from 'node:assert/strict';
import { fingerprintImage } from '../js/binary/fingerprint.js';
import { regionsForImage } from '../js/platform/describe.js';

function makeImage(buffer, { sections = [], segments = [] } = {}) {
  return {
    bytes: buffer,
    sections,
    segments,
  };
}

function makeSourceImage(buffer, { sections = [], segments = [] } = {}) {
  return {
    source: {
      async readExactly(offset, length) {
        const off = Number(offset);
        return buffer.subarray(off, off + length);
      },
    },
    sections,
    segments,
  };
}

// 1. executable section A + uncovered executable segment B -> 1-byte change in B changes hash
{
  const buf1 = new Uint8Array(0x4000);
  buf1.fill(0xaa, 0, 0x1000);    // section A (0..0x1000)
  buf1.fill(0xbb, 0x1000, 0x2000); // segment B (0x1000..0x2000)

  const buf2 = new Uint8Array(buf1);
  buf2[0x1500] = 0xcc; // modify 1 byte in segment B

  const secA = {
    name: '.text',
    source: 'section-header',
    flags: 0x6n,
    address: 0x1000n,
    fileOffset: 0n,
    fileSize: 0x1000n,
    size: 0x1000n,
    perms: { read: true, write: false, execute: true },
  };
  const segB = {
    name: 'LOAD_EXEC',
    address: 0x2000n,
    fileOffset: 0x1000n,
    fileSize: 0x1000n,
    size: 0x1000n,
    perms: { read: true, write: false, execute: true },
  };

  const img1 = makeImage(buf1, { sections: [secA], segments: [segB] });
  const img2 = makeImage(buf2, { sections: [secA], segments: [segB] });

  const fp1 = fingerprintImage(img1);
  const fp2 = fingerprintImage(img2);

  assert.notEqual(fp1.hash, fp2.hash, '1-byte change in uncovered segment B must change fingerprint');
  assert.equal(fp1.bytes, 0x2000, 'both section A and segment B must be hashed');
}

// 2. Section completely covers segment -> bytes are not hashed twice
{
  const buf = new Uint8Array(0x1000);
  buf.fill(0x42);

  const secA = {
    name: '.text',
    source: 'section-header',
    flags: 0x6n,
    address: 0x1000n,
    fileOffset: 0n,
    fileSize: 0x1000n,
    size: 0x1000n,
    perms: { read: true, write: false, execute: true },
  };
  const segA = {
    name: 'LOAD1',
    address: 0x1000n,
    fileOffset: 0n,
    fileSize: 0x1000n,
    size: 0x1000n,
    perms: { read: true, write: false, execute: true },
  };

  const img = makeImage(buf, { sections: [secA], segments: [segA] });
  const fp = fingerprintImage(img);

  assert.equal(fp.bytes, 0x1000, 'covered segment bytes must not be double counted');
}

// 3. No sections -> segment fallback maintained
{
  const buf = new Uint8Array(0x1000);
  buf.fill(0x55);

  const seg = {
    name: 'LOAD1',
    address: 0x1000n,
    fileOffset: 0n,
    fileSize: 0x1000n,
    size: 0x1000n,
    perms: { read: true, write: false, execute: true },
  };

  const img = makeImage(buf, { sections: [], segments: [seg] });
  const fp = fingerprintImage(img);

  assert.equal(fp.bytes, 0x1000);
  assert.ok(fp.hash);
}

// 4. Multiple segments and partial section coverage -> stable canonical hash
{
  const buf = new Uint8Array(0x4000);
  for (let i = 0; i < buf.length; i++) buf[i] = i & 0xff;

  const sec1 = {
    name: '.text',
    source: 'section-header',
    flags: 0x6n,
    address: 0x1000n,
    fileOffset: 0n,
    fileSize: 0x1000n,
    size: 0x1000n,
    perms: { read: true, write: false, execute: true },
  };
  const seg1 = {
    name: 'LOAD1',
    address: 0x1000n,
    fileOffset: 0n,
    fileSize: 0x2000n,
    size: 0x2000n,
    perms: { read: true, write: false, execute: true },
  };
  const seg2 = {
    name: 'LOAD2',
    address: 0x3000n,
    fileOffset: 0x2000n,
    fileSize: 0x1000n,
    size: 0x1000n,
    perms: { read: true, write: false, execute: true },
  };

  const imgA = makeImage(buf, { sections: [sec1], segments: [seg1, seg2] });
  const imgB = makeImage(buf, { sections: [sec1], segments: [seg1, seg2] });

  const fpA = fingerprintImage(imgA);
  const fpB = fingerprintImage(imgB);

  assert.equal(fpA.hash, fpB.hash, 'hash must be deterministic and stable');
  assert.equal(fpA.bytes, 0x3000, 'total hashed bytes should equal union of executable bytes');
}

// 5. executableOnly: false -> all-mappings coverage similarly verified
{
  const buf = new Uint8Array(0x3000);
  buf.fill(0x77);

  const dataSec = {
    name: '.data',
    source: 'section-header',
    flags: 0x3n,
    address: 0x2000n,
    fileOffset: 0n,
    fileSize: 0x1000n,
    size: 0x1000n,
    perms: { read: true, write: true, execute: false },
  };
  const dataSeg = {
    name: 'LOAD_DATA',
    address: 0x3000n,
    fileOffset: 0x1000n,
    fileSize: 0x1000n,
    size: 0x1000n,
    perms: { read: true, write: true, execute: false },
  };

  const img = makeImage(buf, { sections: [dataSec], segments: [dataSeg] });
  const fp = fingerprintImage(img, { executableOnly: false });

  assert.equal(fp.bytes, 0x2000);
  assert.equal(fp.scope, 'all-mappings');
}

// 6. resident and source-backed paths return the exact same hash for the same logical mapping
{
  const buf = new Uint8Array(0x3000);
  for (let i = 0; i < buf.length; i++) buf[i] = (i * 31 + 7) & 0xff;

  const sec = {
    name: '.text',
    source: 'section-header',
    flags: 0x6n,
    address: 0x1000n,
    fileOffset: 0n,
    fileSize: 0x1000n,
    size: 0x1000n,
    perms: { read: true, write: false, execute: true },
  };
  const seg = {
    name: 'LOAD_EXTRA',
    address: 0x2000n,
    fileOffset: 0x1000n,
    fileSize: 0x1000n,
    size: 0x1000n,
    perms: { read: true, write: false, execute: true },
  };

  const resImg = makeImage(buf, { sections: [sec], segments: [seg] });
  const srcImg = makeSourceImage(buf, { sections: [sec], segments: [seg] });

  const resFp = fingerprintImage(resImg);
  const srcFp = await fingerprintImage(srcImg);

  assert.equal(resFp.hash, srcFp.hash, 'resident and source-backed hashes must match');
  assert.equal(resFp.bytes, srcFp.bytes);
}

// 7. section and segment share VA interval but have conflicting file mapping -> both participate in hash
{
  const buf1 = new Uint8Array(0x1000);
  buf1.fill(0x11, 0, 0x100);    // section bytes at fileOffset 0
  buf1.fill(0x22, 0x100, 0x200); // segment bytes at fileOffset 0x100

  const buf2 = new Uint8Array(buf1);
  buf2[0x150] = 0x99; // modify byte in segment-owned file region

  const sec = {
    name: '.text',
    source: 'section-header',
    flags: 0x6n,
    address: 0x1000n,
    fileOffset: 0n,
    fileSize: 0x100n,
    size: 0x100n,
    perms: { read: true, write: false, execute: true },
  };
  const seg = {
    name: 'LOAD_CONFLICT',
    address: 0x1000n,
    fileOffset: 0x100n,
    fileSize: 0x100n,
    size: 0x100n,
    perms: { read: true, write: false, execute: true },
  };

  const img1 = makeImage(buf1, { sections: [sec], segments: [seg] });
  const img2 = makeImage(buf2, { sections: [sec], segments: [seg] });

  const fp1 = fingerprintImage(img1);
  const fp2 = fingerprintImage(img2);

  assert.notEqual(fp1.hash, fp2.hash, 'modifying segment-mapped bytes with divergent fileOffset must change fingerprint');
  assert.equal(fp1.bytes, 0x200, 'both section and non-coincident segment bytes must be hashed');
}

// 8. Non-mapped section with execute perms is excluded from executable fingerprinting and region projection
{
  const buf = new Uint8Array(0x1000);
  buf.fill(0x77);

  // Section with execute perms but source='section-header' and flags=0 (no SHF_ALLOC: not mapped)
  const unmappedSec = {
    name: '.unmapped_exec',
    source: 'section-header',
    flags: 0n,
    address: 0x1000n,
    fileOffset: 0n,
    fileSize: 0x500n,
    size: 0x500n,
    perms: { read: true, write: false, execute: true },
  };
  // Overlapping executable segment
  const seg = {
    name: 'LOAD_EXEC',
    address: 0x1000n,
    fileOffset: 0n,
    fileSize: 0x1000n,
    size: 0x1000n,
    perms: { read: true, write: false, execute: true },
  };

  const img = makeImage(buf, { sections: [unmappedSec], segments: [seg] });
  const fp = fingerprintImage(img);

  // The unmapped section must NOT enter executable fingerprint ranges; the segment bytes should be hashed once (0x1000)
  assert.equal(fp.bytes, 0x1000, 'unmapped section must not double-count overlapping segment bytes');

  // Also verify region projection: unmapped section must have exec: false
  const regions = regionsForImage(img);
  const secRegion = regions.find((r) => r.section === '.unmapped_exec');
  assert.ok(secRegion, 'section region should exist');
  assert.equal(secRegion.exec, false, 'unmapped section must not be projected as executable');
}

console.log('issue #6234 fingerprint uncovered segments tests: PASS');
