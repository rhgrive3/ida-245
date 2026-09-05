import assert from 'node:assert/strict';
import { regionsForImage, describeBinaryImage } from '../js/platform/describe.js';

function makeMockImage({ sections = [], segments = [] } = {}) {
  return {
    format: 'elf',
    arch: 'arm64',
    bits: 64,
    endian: 'little',
    fileSize: 0x10000n,
    imageBase: 0x400000n,
    sections,
    segments,
    libraries: [],
    imports: [],
    exports: [],
    summary() { return {}; },
  };
}

// 1. executable segment + non-ALLOC .comment only -> executable region remains
{
  const execSeg = {
    name: 'LOAD1',
    address: 0x400000n,
    size: 0x2000n,
    fileOffset: 0x1000n,
    fileSize: 0x2000n,
    perms: { read: true, write: false, execute: true },
  };
  const commentSec = {
    name: '.comment',
    source: 'section-header',
    flags: 0n, // non-ALLOC
    address: 0n,
    size: 0x40n,
    fileOffset: 0x8000n,
    fileSize: 0x40n,
    perms: { read: false, write: false, execute: false },
  };
  const image = makeMockImage({ sections: [commentSec], segments: [execSeg] });
  const regions = regionsForImage(image);

  const execRegions = regions.filter((r) => r.exec);
  assert.equal(execRegions.length, 1, 'executable region must be present');
  assert.equal(execRegions[0].vmAddr, 0x400000n);
  assert.equal(execRegions[0].size, 0x2000n);
  assert.equal(execRegions[0].kind, 'segment');

  const desc = describeBinaryImage(image);
  assert.equal(desc.slices[0].regions.filter((r) => r.exec).length, 1);
  assert.equal(desc.productDescriptor.regions.filter((r) => r.exec).length, 1);
  assert.equal(desc.slices[0].info.textVM, 0x400000n);
}

// 2. executable segment + non-ALLOC .strtab only -> executable region remains
{
  const execSeg = {
    name: 'LOAD1',
    address: 0x400000n,
    size: 0x1000n,
    fileOffset: 0x1000n,
    fileSize: 0x1000n,
    perms: { read: true, write: false, execute: true },
  };
  const strtabSec = {
    name: '.strtab',
    source: 'section-header',
    flags: 0n,
    address: 0n,
    size: 0x100n,
    fileOffset: 0x9000n,
    fileSize: 0x100n,
    perms: { read: false, write: false, execute: false },
  };
  const image = makeMockImage({ sections: [strtabSec], segments: [execSeg] });
  const regions = regionsForImage(image);

  assert.ok(regions.some((r) => r.exec), 'executable region must be present with .strtab');
}

// 3. mapped executable section completely covers segment -> no duplicate scan
{
  const execSeg = {
    name: 'LOAD1',
    address: 0x400000n,
    size: 0x2000n,
    fileOffset: 0x1000n,
    fileSize: 0x2000n,
    perms: { read: true, write: false, execute: true },
  };
  const textSec = {
    name: '.text',
    source: 'section-header',
    flags: 0x6n, // SHF_ALLOC | SHF_EXECINSTR
    address: 0x400000n,
    size: 0x2000n,
    fileOffset: 0x1000n,
    fileSize: 0x2000n,
    perms: { read: true, write: false, execute: true },
  };
  const image = makeMockImage({ sections: [textSec], segments: [execSeg] });
  const regions = regionsForImage(image);

  assert.equal(regions.length, 1, 'only section must be emitted when fully covered');
  assert.equal(regions[0].kind, 'section');
  assert.equal(regions[0].name, '.text');
}

// 4. ELF without section table -> falls back to segments
{
  const execSeg = {
    name: 'LOAD1',
    address: 0x400000n,
    size: 0x2000n,
    fileOffset: 0x1000n,
    fileSize: 0x2000n,
    perms: { read: true, write: false, execute: true },
  };
  const image = makeMockImage({ sections: [], segments: [execSeg] });
  const regions = regionsForImage(image);

  assert.equal(regions.length, 1);
  assert.equal(regions[0].kind, 'segment');
  assert.equal(regions[0].vmAddr, 0x400000n);
}

// 5. section coverage is only partial -> uncovered executable span preserved
{
  const execSeg = {
    name: 'LOAD1',
    address: 0x400000n,
    size: 0x4000n,
    fileOffset: 0x1000n,
    fileSize: 0x4000n,
    perms: { read: true, write: false, execute: true },
  };
  const textSec = {
    name: '.text',
    source: 'section-header',
    flags: 0x6n,
    address: 0x400000n,
    size: 0x1000n,
    fileOffset: 0x1000n,
    fileSize: 0x1000n,
    perms: { read: true, write: false, execute: true },
  };
  const image = makeMockImage({ sections: [textSec], segments: [execSeg] });
  const regions = regionsForImage(image);

  assert.equal(regions.length, 2, 'both .text and uncovered segment span must be present');
  assert.equal(regions[0].kind, 'section');
  assert.equal(regions[0].vmAddr, 0x400000n);
  assert.equal(regions[0].size, 0x1000n);

  assert.equal(regions[1].kind, 'segment');
  assert.equal(regions[1].vmAddr, 0x401000n);
  assert.equal(regions[1].size, 0x3000n);
  assert.equal(regions[1].fileOffset, 0x2000n);
  assert.equal(regions[1].exec, true);
}

// 6. describeBinaryImage slices[0].regions and productDescriptor.regions equality
{
  const execSeg = {
    name: 'LOAD1',
    address: 0x400000n,
    size: 0x3000n,
    fileOffset: 0x1000n,
    fileSize: 0x3000n,
    perms: { read: true, write: false, execute: true },
  };
  const textSec = {
    name: '.text',
    source: 'section-header',
    flags: 0x6n,
    address: 0x400000n,
    size: 0x1000n,
    fileOffset: 0x1000n,
    fileSize: 0x1000n,
    perms: { read: true, write: false, execute: true },
  };
  const image = makeMockImage({ sections: [textSec], segments: [execSeg] });
  const desc = describeBinaryImage(image);

  assert.deepEqual(desc.slices[0].regions, desc.productDescriptor.regions);
}

console.log('issue #6223 platform regions uncovered segments tests: PASS');
