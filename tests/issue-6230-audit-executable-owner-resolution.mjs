import assert from 'node:assert/strict';
import { auditBinary } from '../js/binary/audit.js';

function makeImage({ segments = [], sections = [], functions = [], entrypoint = null } = {}) {
  return {
    format: 'elf',
    arch: 'arm64',
    endian: 'little',
    bits: 64,
    fileSize: 0x1000n,
    segments,
    sections,
    imports: [],
    exports: [],
    symbols: [],
    relocations: [],
    functions,
    libraries: [],
    entrypoint,
    metadata: {},
    sectionAt(addr) {
      const a = BigInt(addr);
      return sections.find((s) => a >= s.address && a < s.address + s.size) || null;
    },
    segmentAt(addr) {
      const a = BigInt(addr);
      return segments.find((s) => a >= s.address && a < s.address + s.size) || null;
    },
    addressToOffset(addr) {
      const a = BigInt(addr);
      const seg = this.segmentAt(a);
      return seg ? seg.fileOffset + (a - seg.address) : null;
    },
    offsetToAddress(off) {
      const o = BigInt(off);
      const seg = segments.find((s) => o >= s.fileOffset && o < s.fileOffset + s.fileSize);
      return seg ? seg.address + (o - seg.fileOffset) : null;
    },
  };
}

// Case 1: non-ALLOC/non-exec section + executable segment covering the same VA
// -> Function should be treated as executable, not outside-exec
{
  const nonAllocSection = {
    name: '.comment',
    source: 'section-header',
    flags: 0n, // non-ALLOC (SHF_ALLOC = 0x2)
    address: 0x1000n,
    size: 0x100n,
    fileOffset: 0x200n,
    fileSize: 0x100n,
    perms: { read: false, write: false, execute: false },
  };
  const execSegment = {
    name: 'LOAD1',
    address: 0x1000n,
    size: 0x500n,
    fileOffset: 0x200n,
    fileSize: 0x500n,
    perms: { read: true, write: false, execute: true },
  };
  const fn = { address: 0x1040n, source: 'symbol', size: 0x20n };

  const image = makeImage({
    segments: [execSegment],
    sections: [nonAllocSection],
    functions: [fn],
  });

  const audit = auditBinary(image);
  assert.equal(audit.stats.executableFunctions, 1, 'function in executable segment must be counted as executable');
  assert.equal(audit.stats.unmappedFunctions, 0);
  assert.ok(!audit.issues.some((i) => i.code === 'function-outside-exec'), 'no function-outside-exec warning should be emitted');
}

// Case 2: Same non-ALLOC section + executable segment for entrypoint
// -> entrypoint-not-executable warning must NOT be emitted
{
  const nonAllocSection = {
    name: '.comment',
    source: 'section-header',
    flags: 0n,
    address: 0x1000n,
    size: 0x100n,
    fileOffset: 0x200n,
    fileSize: 0x100n,
    perms: { read: false, write: false, execute: false },
  };
  const execSegment = {
    name: 'LOAD1',
    address: 0x1000n,
    size: 0x500n,
    fileOffset: 0x200n,
    fileSize: 0x500n,
    perms: { read: true, write: false, execute: true },
  };

  const image = makeImage({
    segments: [execSegment],
    sections: [nonAllocSection],
    entrypoint: 0x1040n,
  });

  const audit = auditBinary(image);
  assert.ok(!audit.issues.some((i) => i.code === 'entrypoint-not-executable'), 'entrypoint in executable segment must not be warned');
}

// Case 3: Mapped executable section + segment
// -> Preserves existing executable behavior
{
  const execSection = {
    name: '.text',
    source: 'section-header',
    flags: 0x6n, // SHF_ALLOC | SHF_EXECINSTR
    address: 0x1000n,
    size: 0x100n,
    fileOffset: 0x200n,
    fileSize: 0x100n,
    perms: { read: true, write: false, execute: true },
  };
  const execSegment = {
    name: 'LOAD1',
    address: 0x1000n,
    size: 0x500n,
    fileOffset: 0x200n,
    fileSize: 0x500n,
    perms: { read: true, write: false, execute: true },
  };
  const fn = { address: 0x1010n, source: 'symbol', size: 0x20n };

  const image = makeImage({
    segments: [execSegment],
    sections: [execSection],
    functions: [fn],
    entrypoint: 0x1010n,
  });

  const audit = auditBinary(image);
  assert.equal(audit.stats.executableFunctions, 1);
  assert.equal(audit.stats.unmappedFunctions, 0);
  assert.ok(!audit.issues.some((i) => i.code === 'function-outside-exec'));
  assert.ok(!audit.issues.some((i) => i.code === 'entrypoint-not-executable'));
}

// Case 4: Mapped non-exec section + non-exec segment
// -> Outside-exec warning maintained
{
  const dataSection = {
    name: '.data',
    source: 'section-header',
    flags: 0x3n, // SHF_WRITE | SHF_ALLOC
    address: 0x2000n,
    size: 0x100n,
    fileOffset: 0x300n,
    fileSize: 0x100n,
    perms: { read: true, write: true, execute: false },
  };
  const dataSegment = {
    name: 'LOAD_DATA',
    address: 0x2000n,
    size: 0x100n,
    fileOffset: 0x300n,
    fileSize: 0x100n,
    perms: { read: true, write: true, execute: false },
  };
  const fn = { address: 0x2010n, source: 'symbol', size: 0x20n };

  const image = makeImage({
    segments: [dataSegment],
    sections: [dataSection],
    functions: [fn],
    entrypoint: 0x2010n,
  });

  const audit = auditBinary(image);
  assert.equal(audit.stats.executableFunctions, 0);
  assert.equal(audit.stats.unmappedFunctions, 1);
  assert.ok(audit.issues.some((i) => i.code === 'function-outside-exec'));
  assert.ok(audit.issues.some((i) => i.code === 'entrypoint-not-executable'));
}

// Case 5: Function with no owner at all
// -> Outside-exec warning maintained
{
  const fn = { address: 0x9000n, source: 'symbol', size: 0x20n };
  const image = makeImage({ functions: [fn], entrypoint: 0x9000n });

  const audit = auditBinary(image);
  assert.equal(audit.stats.executableFunctions, 0);
  assert.equal(audit.stats.unmappedFunctions, 1);
  assert.ok(audit.issues.some((i) => i.code === 'function-outside-exec'));
  assert.ok(audit.issues.some((i) => i.code === 'entrypoint-not-executable'));
}

console.log('issue #6230 audit executable owner resolution tests: PASS');
