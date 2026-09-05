/**
 * P7-5b — PDB provider.
 *
 * A second debug ecosystem behind the *same* boundary. That is the point of
 * this checkpoint: DWARF working is not the phase, and a PDB backend with its
 * own private route into type recovery would defeat the boundary entirely
 * (§11.1 step 6).
 *
 * Reads the MSF container, the PDB info stream (identity), the symbol record
 * stream (S_PUB32 / S_GPROC32 / S_LPROC32), the section header stream, and a
 * practical subset of TPI leaf records. Everything outside that subset is
 * reported as a diagnostic and keeps the result incomplete.
 *
 * Identity is the PDB GUID and age compared against the RSDS entry in the PE
 * debug directory. A matching filename proves nothing and is never accepted.
 */

import { createAnalysisStatus } from '../status.js';
import {
  DEBUG_DEFAULT_BUDGET,
  DEBUG_DEFAULT_PAGE_SIZE,
  DebugInfoProvider,
  createDebugPage,
  createDebugProviderResult,
  createDebugRecord,
} from './provider.js';

export const PDB_PROVIDER_ID = 'phase7.debug.pdb';
export const PDB_PROVIDER_VERSION = '1.0.0';

const MSF_MAGIC = 'Microsoft C/C++ MSF 7.00\r\n\u001aDS\0\0\0';

/** CodeView symbol record kinds this provider models. */
const S_PUB32 = 0x110e;
const S_LPROC32 = 0x110f;
const S_GPROC32 = 0x1110;
const S_LPROC32_ID = 0x1146;
const S_GPROC32_ID = 0x1147;

/** TPI leaf kinds this provider models. */
const LF_MODIFIER = 0x1001;
const LF_POINTER = 0x1002;
const LF_PROCEDURE = 0x1008;
const LF_ARGLIST = 0x1201;
const LF_FIELDLIST = 0x1203;
const LF_STRUCTURE = 0x1505;
const LF_CLASS = 0x1504;
const LF_UNION = 0x1506;
const LF_ENUM = 0x1507;
const LF_ARRAY = 0x1503;
const LF_MEMBER = 0x150d;

/** CV_PUBSYMFLAGS: bit 1 marks a function. */
const CVPSF_FUNCTION = 0x00000002;

/**
 * Built-in type indices below 0x1000. Only the common ones are named; anything
 * else is reported as `unknown` rather than guessed.
 */
const PRIMITIVE_TYPES = Object.freeze({
  0x0003: { name: 'void', widthBits: 0, class: 'void' },
  0x0010: { name: 'char', widthBits: 8, class: 'integer' },
  0x0020: { name: 'unsigned char', widthBits: 8, class: 'integer' },
  0x0068: { name: 'int8_t', widthBits: 8, class: 'integer' },
  0x0069: { name: 'uint8_t', widthBits: 8, class: 'integer' },
  0x0070: { name: 'char', widthBits: 8, class: 'integer' },
  0x0071: { name: 'wchar_t', widthBits: 16, class: 'integer' },
  0x0072: { name: 'int16_t', widthBits: 16, class: 'integer' },
  0x0073: { name: 'uint16_t', widthBits: 16, class: 'integer' },
  0x0074: { name: 'int', widthBits: 32, class: 'integer' },
  0x0075: { name: 'unsigned', widthBits: 32, class: 'integer' },
  0x0076: { name: 'int64_t', widthBits: 64, class: 'integer' },
  0x0077: { name: 'uint64_t', widthBits: 64, class: 'integer' },
  0x0040: { name: 'float', widthBits: 32, class: 'float' },
  0x0041: { name: 'double', widthBits: 64, class: 'float' },
});

function bytesOf(value) {
  if (value == null) return null;
  if (value instanceof Uint8Array) return value;
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  return null;
}

function cstring(bytes, offset, limit = bytes.length) {
  let end = offset;
  while (end < limit && bytes[end] !== 0) end += 1;
  return new TextDecoder('utf8').decode(bytes.subarray(offset, end));
}

function cstringWithNext(bytes, offset, limit = bytes.length) {
  let end = offset;
  while (end < limit && bytes[end] !== 0) end += 1;
  if (end >= limit) return null;
  return {
    value: new TextDecoder('utf8').decode(bytes.subarray(offset, end)),
    next: end + 1,
  };
}

/** Reads the MSF superblock and stream directory. */
export function parseMsf(bytes) {
  const data = bytesOf(bytes);
  if (!data || data.length < 56) return { streams: [], diagnostics: ['file too small for an MSF superblock'], complete: false };
  const magic = new TextDecoder('latin1').decode(data.subarray(0, MSF_MAGIC.length));
  if (magic !== MSF_MAGIC) return { streams: [], diagnostics: ['not an MSF 7.00 container'], complete: false };

  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const blockSize = view.getUint32(32, true);
  const numBlocks = view.getUint32(40, true);
  const numDirectoryBytes = view.getUint32(44, true);
  const blockMapAddr = view.getUint32(52, true);
  if (blockSize === 0 || (blockSize & (blockSize - 1)) !== 0) {
    return { streams: [], diagnostics: ['invalid MSF block size'], complete: false };
  }
  if (numBlocks * blockSize > data.length + blockSize) {
    return { streams: [], diagnostics: ['MSF block count exceeds the file'], complete: false };
  }

  const readBlock = (index) => {
    const start = index * blockSize;
    if (start + blockSize > data.length) return null;
    return data.subarray(start, start + blockSize);
  };
  const concatBlocks = (indices, byteLength) => {
    if (indices.length * blockSize < byteLength) return null;
    const out = new Uint8Array(byteLength);
    let written = 0;
    for (const index of indices) {
      const block = readBlock(index);
      if (!block) return null;
      const take = Math.min(blockSize, byteLength - written);
      out.set(block.subarray(0, take), written);
      written += take;
      if (written >= byteLength) break;
    }
    return written === byteLength ? out : null;
  };

  // The directory is itself stored in blocks whose indices live in the block map.
  const directoryBlockCount = Math.ceil(numDirectoryBytes / blockSize);
  const mapBlock = readBlock(blockMapAddr);
  if (!mapBlock) return { streams: [], diagnostics: ['MSF block map is out of range'], complete: false };
  const mapView = new DataView(mapBlock.buffer, mapBlock.byteOffset, mapBlock.byteLength);
  const directoryBlocks = [];
  for (let index = 0; index < directoryBlockCount; index += 1) {
    if ((index + 1) * 4 > mapBlock.length) break;
    directoryBlocks.push(mapView.getUint32(index * 4, true));
  }
  const directory = concatBlocks(directoryBlocks, numDirectoryBytes);
  if (!directory) return { streams: [], diagnostics: ['MSF stream directory is truncated'], complete: false };

  const directoryView = new DataView(directory.buffer, directory.byteOffset, directory.byteLength);
  const numStreams = directoryView.getUint32(0, true);
  const sizes = [];
  let cursor = 4;
  for (let index = 0; index < numStreams; index += 1) {
    if (cursor + 4 > directory.length) return { streams: [], diagnostics: ['MSF directory sizes are truncated'], complete: false };
    const size = directoryView.getUint32(cursor, true);
    // 0xffffffff marks a stream that does not exist.
    sizes.push(size === 0xffffffff ? 0 : size);
    cursor += 4;
  }
  const streams = [];
  for (let index = 0; index < numStreams; index += 1) {
    const count = Math.ceil(sizes[index] / blockSize);
    const blocks = [];
    for (let block = 0; block < count; block += 1) {
      if (cursor + 4 > directory.length) return { streams, diagnostics: ['MSF directory block list is truncated'], complete: false };
      blocks.push(directoryView.getUint32(cursor, true));
      cursor += 4;
    }
    streams.push({ index, size: sizes[index], read: () => (sizes[index] === 0 ? new Uint8Array(0) : concatBlocks(blocks, sizes[index])) });
  }
  return { streams, blockSize, diagnostics: [], complete: true };
}

function guidString(bytes, offset) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const d1 = view.getUint32(offset, true);
  const d2 = view.getUint16(offset + 4, true);
  const d3 = view.getUint16(offset + 6, true);
  const rest = [...bytes.subarray(offset + 8, offset + 16)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
  return `${d1.toString(16).padStart(8, '0')}-${d2.toString(16).padStart(4, '0')}-${d3.toString(16).padStart(4, '0')}-${rest.slice(0, 4)}-${rest.slice(4)}`.toUpperCase();
}

/** Stream 1: version, signature, age, GUID. */
export function parsePdbInfoStream(bytes) {
  if (!bytes || bytes.length < 28) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return {
    version: view.getUint32(0, true),
    signature: view.getUint32(4, true),
    age: view.getUint32(8, true),
    guid: guidString(bytes, 12),
  };
}

/**
 * DBI header (NewDBIHdr).
 *
 * The substream sizes matter as much as the stream indices: the optional debug
 * header, which names the section-header stream, sits after all of them, and
 * getting one size wrong silently points at the wrong stream.
 */
export const DBI_HEADER_SIZE = 64;

export function parseDbiHeader(bytes) {
  if (!bytes || bytes.length < DBI_HEADER_SIZE) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return {
    versionSignature: view.getInt32(0, true),
    versionHeader: view.getUint32(4, true),
    age: view.getUint32(8, true),
    globalStreamIndex: view.getUint16(12, true),
    publicStreamIndex: view.getUint16(16, true),
    symRecordStreamIndex: view.getUint16(20, true),
    moduleSubstreamSize: view.getInt32(24, true),
    sectionContributionSize: view.getInt32(28, true),
    sectionMapSize: view.getInt32(32, true),
    sourceInfoSize: view.getInt32(36, true),
    typeServerMapSize: view.getInt32(40, true),
    optionalDbgHeaderSize: view.getInt32(48, true),
    ecSubstreamSize: view.getInt32(52, true),
  };
}

/**
 * Module entries from the DBI module substream.
 *
 * Procedure symbols with type indices live in per-module streams, not in the
 * global symbol record stream, so reaching them means walking this list.
 */
export function parseModuleInfo(bytes, dbi) {
  const modules = [];
  if (!bytes || !dbi || dbi.moduleSubstreamSize <= 0) return modules;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const end = Math.min(DBI_HEADER_SIZE + dbi.moduleSubstreamSize, bytes.length);
  let offset = DBI_HEADER_SIZE;
  while (offset + 64 <= end) {
    const streamIndex = view.getInt16(offset + 34, true);
    const symbolByteSize = view.getUint32(offset + 36, true);
    const moduleNameEntry = cstringWithNext(bytes, offset + 64, end);
    if (!moduleNameEntry) break;
    const objectNameEntry = cstringWithNext(bytes, moduleNameEntry.next, end);
    if (!objectNameEntry) break;
    let cursor = objectNameEntry.next;
    // Entries are aligned to 4 bytes.
    cursor = (cursor + 3) & ~3;
    modules.push({
      streamIndex,
      symbolByteSize,
      moduleName: moduleNameEntry.value,
      objectName: objectNameEntry.value,
    });
    if (cursor <= offset) break;
    offset = cursor;
  }
  return modules;
}

/** PE section headers, as stored in the PDB's section-header stream. */
export function parseSectionHeaders(bytes) {
  const headers = [];
  if (!bytes) return headers;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  for (let offset = 0; offset + 40 <= bytes.length; offset += 40) {
    headers.push({
      name: cstring(bytes, offset, offset + 8),
      virtualAddress: view.getUint32(offset + 12, true),
      sizeOfRawData: view.getUint32(offset + 16, true),
    });
  }
  return headers;
}

/**
 * Walks a CodeView symbol record stream.
 *
 * Records are length-prefixed, so an unrecognised kind can be skipped safely —
 * unlike DWARF forms, which have no self-describing length.
 */
export function parseSymbolRecords(bytes, budget = DEBUG_DEFAULT_BUDGET) {
  const symbols = [];
  const unmodelled = new Set();
  if (!bytes) return { symbols, unmodelled, complete: false };
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let offset = 0;
  while (offset + 4 <= bytes.length && symbols.length < budget.maxRecords) {
    const length = view.getUint16(offset, true);
    if (length < 2) break;
    const kind = view.getUint16(offset + 2, true);
    const end = offset + 2 + length;
    if (end > bytes.length) break;

    // Fixed-field reads are confined to the record's own end (#1845): a short
    // known-kind record must fail closed instead of reading the next record's
    // bytes as its fields, or faulting past the stream end.
    const fieldEnd = kind === S_PUB32 ? offset + 14
      : (kind === S_GPROC32 || kind === S_LPROC32 || kind === S_GPROC32_ID || kind === S_LPROC32_ID)
        ? offset + 38
        : end;
    if (fieldEnd > end) break;
    if (kind === S_PUB32) {
      const nameEntry = cstringWithNext(bytes, offset + 14, end);
      if (!nameEntry) break;
      const flags = view.getUint32(offset + 4, true);
      symbols.push({
        kind: 'public',
        flags,
        isFunction: (flags & CVPSF_FUNCTION) !== 0,
        offsetInSegment: view.getUint32(offset + 8, true),
        segment: view.getUint16(offset + 12, true),
        sizeBytes: null,
        name: nameEntry.value,
        recordOffset: offset,
      });
    } else if (kind === S_GPROC32 || kind === S_LPROC32 || kind === S_GPROC32_ID || kind === S_LPROC32_ID) {
      // PROCSYM32: parent/end/next (12) + length/dbgStart/dbgEnd (12) + typeIndex (4)
      // + offset (4) + segment (2) + flags (1) + name
      const nameEntry = cstringWithNext(bytes, offset + 39, end);
      if (!nameEntry) break;
      symbols.push({
        kind: 'procedure',
        isFunction: true,
        sizeBytes: view.getUint32(offset + 16, true),
        typeIndex: view.getUint32(offset + 28, true),
        offsetInSegment: view.getUint32(offset + 32, true),
        segment: view.getUint16(offset + 36, true),
        name: nameEntry.value,
        recordOffset: offset,
      });
    } else {
      unmodelled.add(kind);
    }
    offset = end;
  }
  return { symbols, unmodelled, complete: offset >= bytes.length };
}

/** Walks the TPI stream's leaf records. */
export function parseTpiStream(bytes, budget = DEBUG_DEFAULT_BUDGET) {
  const types = new Map();
  const unmodelled = new Set();
  if (!bytes || bytes.length < 56) return { types, unmodelled, complete: false, firstIndex: 0x1000 };
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const headerSize = view.getUint32(4, true);
  const firstIndex = view.getUint32(8, true);
  if (headerSize < 56 || headerSize > bytes.length) {
    return { types, unmodelled, complete: false, firstIndex };
  }
  let offset = headerSize;
  let index = firstIndex;

  while (offset + 4 <= bytes.length && types.size < budget.maxRecords) {
    const length = view.getUint16(offset, true);
    if (length < 2) break;
    const leaf = view.getUint16(offset + 2, true);
    const end = offset + 2 + length;
    if (end > bytes.length) break;
    const body = offset + 4;

    // Fixed-field reads are confined to the record's own end (#1845): a short
    // known-leaf record must fail closed instead of reading the next record's
    // bytes as its fields, or faulting past the stream end.
    const bodyEnd = {
      [LF_STRUCTURE]: body + 18, [LF_CLASS]: body + 18, [LF_UNION]: body + 10,
      [LF_POINTER]: body + 8, [LF_MODIFIER]: body + 6, [LF_PROCEDURE]: body + 12,
      [LF_ARRAY]: body + 8, [LF_ENUM]: body + 8,
    }[leaf] ?? end;
    if (bodyEnd > end) break;

    if (leaf === LF_STRUCTURE || leaf === LF_CLASS || leaf === LF_UNION) {
      const count = view.getUint16(body, true);
      const properties = view.getUint16(body + 2, true);
      const fieldList = leaf === LF_UNION ? 0 : view.getUint32(body + 4, true);
      const sizeOffset = leaf === LF_UNION ? body + 8 : body + 16;
      const numeric = readNumeric(view, bytes, sizeOffset, end);
      if (!numeric) break;
      const { value: sizeBytes, next } = numeric;
      // Type names are NUL-terminated: a record that ends without one is
      // truncated, not a complete type with a shorter name (#5265).
      const nameEntry = cstringWithNext(bytes, next, end);
      if (!nameEntry) break;
      const keyword = leaf === LF_UNION ? 'union' : leaf === LF_CLASS ? 'class' : 'struct';
      types.set(index, {
        leaf, kind: 'aggregate', keyword,
        // Bit 7 of the property field marks a forward reference: it names the
        // type but carries no layout, so it is not a complete fact.
        forwardReference: (properties & 0x0080) !== 0,
        memberCount: count,
        fieldList,
        sizeBytes,
        name: nameEntry.value,
      });
    } else if (leaf === LF_POINTER) {
      types.set(index, { leaf, kind: 'pointer', referent: view.getUint32(body, true), attributes: view.getUint32(body + 4, true) });
    } else if (leaf === LF_MODIFIER) {
      types.set(index, { leaf, kind: 'modifier', underlying: view.getUint32(body, true), modifiers: view.getUint16(body + 4, true) });
    } else if (leaf === LF_PROCEDURE) {
      types.set(index, {
        leaf, kind: 'procedure',
        returnType: view.getUint32(body, true),
        parameterCount: view.getUint16(body + 6, true),
        argumentList: view.getUint32(body + 8, true),
      });
    } else if (leaf === LF_ARRAY) {
      const numeric = readNumeric(view, bytes, body + 8, end);
      if (!numeric) break;
      const { value: sizeBytes } = numeric;
      types.set(index, { leaf, kind: 'array', elementType: view.getUint32(body, true), sizeBytes });
    } else if (leaf === LF_ENUM) {
      types.set(index, { leaf, kind: 'enum', underlying: view.getUint32(body + 4, true), name: null });
    } else if (leaf === LF_FIELDLIST) {
      types.set(index, { leaf, kind: 'field-list', members: parseFieldList(view, bytes, body, end) });
    } else if (leaf === LF_ARGLIST) {
      types.set(index, { leaf, kind: 'arg-list' });
    } else {
      unmodelled.add(leaf);
      types.set(index, { leaf, kind: 'unmodelled' });
    }
    offset = end;
    index += 1;
  }
  return { types, unmodelled, complete: offset >= bytes.length, firstIndex };
}

/**
 * CodeView numeric leaves: a value below 0x8000 is the value itself; otherwise
 * the value's width is encoded in the leaf.
 *
 * Fixed-size leaves beyond 0x8004 (REAL32/64, QUADWORD/UQUADWORD, REAL80/128,
 * REAL48) carry payloads that must be consumed; anything else has no known
 * shape here and fails closed so the record desyncs loudly instead of
 * decoding its payload as the next field (#5262).
 */
const MAX_SAFE_BIGINT = BigInt(Number.MAX_SAFE_INTEGER);
const MIN_SAFE_BIGINT = -MAX_SAFE_BIGINT;
const NUMERIC_TAIL_BYTES = {
  0x8005: 4, 0x8006: 8, 0x8007: 10, 0x8008: 16, 0x8009: 8, 0x800a: 8, 0x800b: 6,
};
function readNumeric(view, bytes, offset, end = bytes.length) {
  if (offset + 2 > end) return null;
  const raw = view.getUint16(offset, true);
  if (raw < 0x8000) return { value: raw, next: offset + 2 };
  const tail = raw === 0x8000 ? 1
    : (raw === 0x8001 || raw === 0x8002) ? 2
      : (raw === 0x8003 || raw === 0x8004) ? 4
        : NUMERIC_TAIL_BYTES[raw] ?? null;
  if (tail == null) return null;
  if (offset + 2 + tail > end) return null;
  switch (raw) {
    case 0x8000: return { value: view.getInt8(offset + 2), next: offset + 3 };
    case 0x8001: return { value: view.getInt16(offset + 2, true), next: offset + 4 };
    case 0x8002: return { value: view.getUint16(offset + 2, true), next: offset + 4 };
    case 0x8003: return { value: view.getInt32(offset + 2, true), next: offset + 6 };
    case 0x8004: return { value: view.getUint32(offset + 2, true), next: offset + 6 };
    case 0x8005: return { value: view.getFloat32(offset + 2, true), next: offset + 6 };
    case 0x8006: return { value: view.getFloat64(offset + 2, true), next: offset + 10 };
    case 0x8009: {
      const quad = view.getBigInt64(offset + 2, true);
      return { value: quad >= MIN_SAFE_BIGINT && quad <= MAX_SAFE_BIGINT ? Number(quad) : null, next: offset + 10 };
    }
    case 0x800a: {
      const uquad = view.getBigUint64(offset + 2, true);
      return { value: uquad <= MAX_SAFE_BIGINT ? Number(uquad) : null, next: offset + 10 };
    }
    // REAL80/REAL128/REAL48 have no exact JS number: consume the payload so
    // the record stays in sync, but report no value.
    case 0x8007:
    case 0x8008:
    case 0x800b: return { value: null, next: offset + 2 + tail };
    default: return null;
  }
}

function parseFieldList(view, bytes, start, end) {
  const members = [];
  let offset = start;
  while (offset + 8 <= end) {
    const leaf = view.getUint16(offset, true);
    if (leaf !== LF_MEMBER) break;
    const typeIndex = view.getUint32(offset + 4, true);
    const numeric = readNumeric(view, bytes, offset + 8, end);
    if (!numeric) break;
    const { value: fieldOffset, next } = numeric;
    const nameEntry = cstringWithNext(bytes, next, end);
    if (!nameEntry) break;
    members.push({ name: nameEntry.value, typeIndex, offset: fieldOffset });
    // Records are padded to a 4-byte boundary with 0xf1..0xf3 filler.
    let cursor = nameEntry.next;
    while (cursor < end && bytes[cursor] >= 0xf0) cursor += 1;
    if (cursor <= offset) break;
    offset = cursor;
  }
  return members;
}

/** Renders a TPI type index as a nominal name plus machine facts. */
function describeTypeIndex(index, types, depth = 0) {
  if (depth > 16) return { name: 'unknown', complete: false };
  if (index < 0x1000) {
    const primitive = PRIMITIVE_TYPES[index];
    // The high nibble of a primitive index encodes an indirection mode; 0x0600
    // is a 64-bit pointer to the base type in the low bits.
    if (!primitive && (index & 0x0700) === 0x0600) {
      const target = describeTypeIndex(index & 0x00ff, types, depth + 1);
      return { name: `${target.name} *`, widthBits: 64, class: 'pointer', complete: target.complete };
    }
    if (!primitive) return { name: 'unknown', complete: false };
    return { ...primitive, complete: true };
  }
  const record = types.get(index);
  if (!record) return { name: 'unknown', complete: false };
  if (record.kind === 'aggregate') {
    return {
      name: record.name ? `${record.keyword} ${record.name}` : `${record.keyword} <anonymous>`,
      sizeBytes: record.sizeBytes,
      isAggregate: true,
      complete: !record.forwardReference && record.sizeBytes != null,
    };
  }
  if (record.kind === 'pointer') {
    const target = describeTypeIndex(record.referent, types, depth + 1);
    return { name: `${target.name} *`, widthBits: 64, class: 'pointer', complete: target.complete };
  }
  if (record.kind === 'modifier') {
    const target = describeTypeIndex(record.underlying, types, depth + 1);
    const qualifier = (record.modifiers & 0x0001) ? 'const' : (record.modifiers & 0x0002) ? 'volatile' : '';
    return { ...target, name: qualifier ? `${qualifier} ${target.name}` : target.name };
  }
  if (record.kind === 'procedure') {
    const returns = describeTypeIndex(record.returnType, types, depth + 1);
    return { name: `${returns.name} (*)()`, class: 'code', complete: returns.complete };
  }
  if (record.kind === 'array') {
    const element = describeTypeIndex(record.elementType, types, depth + 1);
    return { name: `${element.name}[]`, sizeBytes: record.sizeBytes, class: 'array', complete: false };
  }
  return { name: 'unknown', complete: false };
}

export class PdbDebugInfoProvider extends DebugInfoProvider {
  constructor() {
    super({ id: PDB_PROVIDER_ID, version: PDB_PROVIDER_VERSION, ecosystem: 'pdb' });
  }

  /**
   * `image.pdbBytes` is the PDB file; `image.identity.codeView` is the RSDS
   * record from the PE debug directory: `{ guid, age, path }`.
   */
  probe(image, { budget = DEBUG_DEFAULT_BUDGET, signal = null } = {}) {
    const status = (completeness, stopReason) => createAnalysisStatus({
      snapshotId: image?.snapshotId ?? 'snapshot-unbound',
      analyzerId: PDB_PROVIDER_ID,
      analyzerVersion: PDB_PROVIDER_VERSION,
      completeness,
      stopReason,
    });

    if (signal?.aborted) {
      return createDebugProviderResult({
        ecosystem: 'pdb',
        identity: { verdict: 'unsupported', providerId: this.id, providerVersion: this.version, method: 'cancelled' },
        status: status('partial', 'cancelled'),
      });
    }

    const expectedCodeView = image?.identity?.codeView ?? null;
    const pdbBytes = bytesOf(image?.pdbBytes);
    const diagnostics = [];

    if (!pdbBytes) {
      return createDebugProviderResult({
        ecosystem: 'pdb',
        identity: {
          verdict: 'companion-missing',
          providerId: this.id, providerVersion: this.version,
          method: 'codeview-guid-age',
          expected: expectedCodeView ? `${expectedCodeView.guid}/${expectedCodeView.age}` : null,
          observed: null,
          detail: expectedCodeView?.path
            ? `the binary references a PDB but its bytes were not supplied`
            : 'no PDB was supplied',
        },
        status: status('unsupported', 'dependency-missing'),
      });
    }

    const msf = parseMsf(pdbBytes);
    diagnostics.push(...msf.diagnostics);
    if (!msf.complete || msf.streams.length < 4) {
      return createDebugProviderResult({
        ecosystem: 'pdb',
        identity: {
          verdict: 'unsupported', providerId: this.id, providerVersion: this.version,
          method: 'codeview-guid-age', detail: 'the PDB container could not be read',
        },
        diagnostics,
        status: status('unsupported', 'unsupported-input'),
      });
    }

    const info = parsePdbInfoStream(msf.streams[1].read());
    const observed = info ? `${info.guid}/${info.age}` : null;
    const expected = expectedCodeView ? `${String(expectedCodeView.guid).toUpperCase()}/${expectedCodeView.age}` : null;

    let verdict;
    let detail = null;
    if (expected == null || observed == null) {
      verdict = 'identity-unavailable';
      detail = expected == null ? 'the binary carries no CodeView debug directory entry' : 'the PDB has no info stream';
    } else if (expected === observed) {
      verdict = 'matched-authoritative';
    } else {
      verdict = 'identity-mismatch';
      detail = 'PDB GUID/age does not match the binary CodeView record';
    }

    const dbiBytes = msf.streams[3]?.read();
    const dbi = parseDbiHeader(dbiBytes);
    const symbolStream = dbi && dbi.symRecordStreamIndex < msf.streams.length
      ? msf.streams[dbi.symRecordStreamIndex].read()
      : null;
    const symbols = parseSymbolRecords(symbolStream, budget);

    // Procedure symbols live in the per-module streams. Each module stream
    // begins with a 4-byte signature before its symbol records.
    const modules = parseModuleInfo(dbiBytes, dbi);
    for (const module of modules) {
      const declaredSize = module.symbolByteSize;
      if (declaredSize < 4) {
        symbols.complete = false;
        continue;
      }
      if (module.streamIndex < 0 || module.streamIndex >= msf.streams.length) {
        if (declaredSize > 4) symbols.complete = false;
        continue;
      }
      const moduleBytes = msf.streams[module.streamIndex].read();
      if (!moduleBytes) {
        if (declaredSize > 4) symbols.complete = false;
        continue;
      }
      if (declaredSize > moduleBytes.length) {
        symbols.complete = false;
        continue;
      }
      // The module stream is [4-byte signature][symbols][C11][C13]... with the
      // symbol range exactly [4, SymByteSize): SymByteSize == 4 is the valid
      // boundary meaning zero symbol bytes, not a cue to scan line info as
      // symbol records (#5276).
      const moduleSymbols = parseSymbolRecords(moduleBytes.subarray(4, declaredSize), budget);
      symbols.complete = symbols.complete && moduleSymbols.complete;
      for (const symbol of moduleSymbols.symbols) {
        if (symbol.kind !== 'procedure') continue;
        symbols.symbols.push({ ...symbol, recordOffset: `${module.streamIndex}:${symbol.recordOffset}` });
      }
      for (const kind of moduleSymbols.unmodelled) symbols.unmodelled.add(kind);
    }

    const tpi = parseTpiStream(msf.streams[2]?.read(), budget);
    const sectionHeaders = parseSectionHeaders(findSectionHeaderStream(msf, dbi, dbiBytes));

    if (symbols.unmodelled.size) {
      diagnostics.push(`unmodelled CodeView symbol kinds: ${[...symbols.unmodelled].map((kind) => `0x${kind.toString(16)}`).slice(0, 8).join(', ')}`);
    }
    if (tpi.unmodelled.size) {
      diagnostics.push(`unmodelled TPI leaf kinds: ${[...tpi.unmodelled].map((leaf) => `0x${leaf.toString(16)}`).slice(0, 8).join(', ')}`);
    }
    if (!sectionHeaders.length) diagnostics.push('no section header stream: symbol addresses stay segment-relative');

    const result = createDebugProviderResult({
      ecosystem: 'pdb',
      identity: {
        verdict,
        providerId: this.id,
        providerVersion: this.version,
        expected,
        observed,
        method: 'codeview-guid-age',
        detail,
      },
      sections: ['pdb-info', 'dbi', 'tpi', 'symbol-records'],
      counts: { streams: msf.streams.length, symbols: symbols.symbols.length, types: tpi.types.size, modules: modules.length },
      diagnostics,
      status: symbols.complete && tpi.complete && diagnostics.length === 0
        ? status('complete', null)
        : status('partial', 'evidence-missing'),
    });
    return Object.freeze({ ...result, parsed: { info, dbi, symbols, tpi, sectionHeaders } });
  }

  symbols(result, { cursor = null, pageSize = DEBUG_DEFAULT_PAGE_SIZE } = {}) {
    const parsed = result.parsed;
    if (!parsed) return createDebugPage({ records: [] });
    const headers = parsed.sectionHeaders;
    const ordered = parsed.symbols.symbols;
    return page(ordered, cursor, pageSize, (symbol) => {
      // Segment indices are one-based. Without section headers the address
      // stays segment-relative and the record says so rather than inventing an
      // RVA.
      const header = headers[symbol.segment - 1] ?? null;
      const address = header
        ? `0x${(header.virtualAddress + symbol.offsetInSegment).toString(16)}`
        : null;
      return createDebugRecord({
        kind: 'symbol',
        entityId: `pdb_sym_${symbol.recordOffset}`,
        name: symbol.name,
        address,
        sizeBytes: symbol.sizeBytes,
        descriptor: {
          isFunction: symbol.isFunction === true,
          segment: symbol.segment,
          offsetInSegment: symbol.offsetInSegment,
          complete: address != null,
        },
        providerId: result.providerId,
        providerVersion: result.providerVersion,
        buildIdentity: result.identity.observed,
        evidenceIds: [`pdb:sym:${symbol.recordOffset}`],
      });
    });
  }

  types(result, { cursor = null, pageSize = DEBUG_DEFAULT_PAGE_SIZE } = {}) {
    const parsed = result.parsed;
    if (!parsed) return createDebugPage({ records: [] });
    // Procedures carry the type index that names a function's signature; that
    // is the record the type graph can actually use.
    const typed = parsed.symbols.symbols.filter((symbol) => symbol.kind === 'procedure' && symbol.typeIndex);
    return page(typed, cursor, pageSize, (symbol) => {
      const described = describeTypeIndex(symbol.typeIndex, parsed.tpi.types);
      return createDebugRecord({
        kind: 'type',
        entityId: `pdb_sym_${symbol.recordOffset}`,
        name: symbol.name,
        descriptor: {
          layer: 'nominal',
          claim: { name: described.name, aliases: [] },
          machine: described.widthBits == null ? null : { widthBits: described.widthBits, class: described.class },
          complete: described.complete,
        },
        providerId: result.providerId,
        providerVersion: result.providerVersion,
        buildIdentity: result.identity.observed,
        evidenceIds: [`pdb:type:${symbol.typeIndex}`],
      });
    });
  }

  /** Aggregate layouts, for the structural type layer. */
  aggregates(result) {
    const parsed = result.parsed;
    if (!parsed) return [];
    const out = [];
    for (const [index, record] of parsed.tpi.types) {
      if (record.kind !== 'aggregate' || record.forwardReference || !record.fieldList) continue;
      const fields = parsed.tpi.types.get(record.fieldList);
      if (!fields || fields.kind !== 'field-list') continue;
      out.push({
        typeIndex: index,
        name: record.name,
        sizeBytes: record.sizeBytes,
        members: fields.members.map((member) => ({
          name: member.name,
          offset: member.offset,
          type: describeTypeIndex(member.typeIndex, parsed.tpi.types),
        })),
      });
    }
    return out;
  }
}

/**
 * The section header stream index lives after the DBI's variable-size
 * substreams, in the optional debug header. Walking there needs the substream
 * sizes, which is why the DBI header is parsed first.
 */
function findSectionHeaderStream(msf, dbi, dbiBytes) {
  if (!dbi || !dbiBytes) return null;
  const view = new DataView(dbiBytes.buffer, dbiBytes.byteOffset, dbiBytes.byteLength);
  const optionalHeaderOffset = DBI_HEADER_SIZE
    + dbi.moduleSubstreamSize
    + dbi.sectionContributionSize
    + dbi.sectionMapSize
    + dbi.sourceInfoSize
    + dbi.typeServerMapSize
    + dbi.ecSubstreamSize;
  // The optional debug header is an array of stream indices; index 5 is the
  // original section header stream.
  const entryOffset = optionalHeaderOffset + 5 * 2;
  if (entryOffset + 2 > dbiBytes.length) return null;
  const streamIndex = view.getUint16(entryOffset, true);
  if (streamIndex === 0xffff || streamIndex >= msf.streams.length) return null;
  return msf.streams[streamIndex].read();
}

function page(items, cursor, pageSize, map) {
  const start = cursor == null ? 0 : Number(cursor);
  const slice = items.slice(start, start + pageSize);
  const next = start + slice.length;
  return createDebugPage({
    records: slice.map(map),
    nextCursor: next < items.length ? String(next) : null,
    truncated: next < items.length,
  });
}
