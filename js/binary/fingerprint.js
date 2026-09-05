import { sectionHasMappedAddress } from './audit.js';

const FNV_OFFSET_HI = 0xcbf29ce4;
const FNV_OFFSET_LO = 0x84222325;
const FNV_PRIME_LO = 0x1b3;
const FNV_PRIME_HI = 0x100;

/*
 * FNV-1a 64-bit without a BigInt operation per byte.
 * The two uint32 limbs produce the exact canonical 64-bit digest but avoid
 * millions of BigInt multiplications on large mobile binaries.
 */
function fnv1a64State(bytes, seed = null) {
  let hi, lo;
  if (seed == null) {
    hi = FNV_OFFSET_HI;
    lo = FNV_OFFSET_LO;
  } else if (typeof seed === 'bigint') {
    hi = Number((seed >> 32n) & 0xffffffffn) >>> 0;
    lo = Number(seed & 0xffffffffn) >>> 0;
  } else if (typeof seed === 'object' && seed) {
    hi = Number(seed.hi) >>> 0;
    lo = Number(seed.lo) >>> 0;
  } else throw new TypeError('FNV seed must be BigInt or {hi, lo}');

  for (let i = 0; i < bytes.length; i++) {
    lo = (lo ^ bytes[i]) >>> 0;
    const a0 = lo & 0xffff;
    const a1 = lo >>> 16;
    const p0 = a0 * FNV_PRIME_LO;
    const p1 = a1 * FNV_PRIME_LO;
    const lowWide = p0 + ((p1 & 0xffff) * 0x10000);
    const carry = Math.floor(lowWide / 0x100000000) + Math.floor(p1 / 0x10000);
    const nextLo = lowWide >>> 0;
    hi = (Math.imul(hi, FNV_PRIME_LO) + carry + Math.imul(lo, FNV_PRIME_HI)) >>> 0;
    lo = nextLo;
  }
  return { hi, lo };
}

export function fnv1a64(bytes, seed = null) {
  const x = fnv1a64State(bytes, seed);
  return (BigInt(x.hi) << 32n) | BigInt(x.lo);
}

export const fnv1a64BigInt = fnv1a64;

export function fingerprintBytes(bytes) {
  return digestHex(fnv1a64State(bytes));
}

function functionFingerprintResult(bytes, fn) {
  if (!bytes || !bytes.length) return null;
  return {
    algorithm: 'fnv1a64',
    hash: fingerprintBytes(bytes),
    bytes: bytes.length,
    truncated: fn.size != null && BigInt(fn.size) > BigInt(bytes.length),
  };
}

function byteCountOption(value, fallback, minimum = 1) {
  const n = Number(value);
  return Number.isSafeInteger(n) && n > 0 ? Math.max(minimum, n) : fallback;
}

/**
 * Keep the historical synchronous API for resident BinaryImage instances while
 * allowing source-backed images to perform the same bounded read asynchronously.
 * Callers that need to support both forms may simply `await` the result.
 */
export function fingerprintFunction(image, fn, opts = {}) {
  const maxBytes = byteCountOption(opts.maxBytes, 1 << 20, 16);
  let size = fn.size == null ? BigInt(byteCountOption(opts.fallbackBytes, 64)) : BigInt(fn.size);
  if (size <= 0n) return null;
  if (size > BigInt(maxBytes)) size = BigInt(maxBytes);
  const length = Number(size);

  if (image.bytes && typeof image.readVirtual === 'function') {
    return functionFingerprintResult(image.readVirtual(fn.address, length), fn);
  }
  if (typeof image.readVirtualAsync === 'function') {
    return Promise.resolve(image.readVirtualAsync(fn.address, length))
      .then((bytes) => functionFingerprintResult(bytes, fn));
  }
  if (typeof image.readVirtual === 'function') {
    return functionFingerprintResult(image.readVirtual(fn.address, length), fn);
  }
  return null;
}

function residentMappingChunk(image, mapping, offset, length) {
  const fileOffset = BigInt(mapping.fileOffset) + BigInt(offset);
  const start = Number(fileOffset);
  if (!Number.isSafeInteger(start) || start < 0 || start + length > image.bytes.length) return null;
  return image.bytes.subarray(start, start + length);
}

async function sourceMappingChunk(image, mapping, offset, length) {
  const fileOffset = BigInt(mapping.fileOffset) + BigInt(offset);
  if (image.source) return image.source.readExactly(fileOffset, length);
  if (mapping.address != null && typeof image.readVirtualAsync === 'function') {
    return image.readVirtualAsync(BigInt(mapping.address) + BigInt(offset), length);
  }
  return null;
}

function requireMappingChunk(bytes, expectedLength) {
  if (!bytes || bytes.length !== expectedLength) {
    throw new RangeError('binary-fingerprint-short-read');
  }
  return bytes;
}

function mergeIntervals(intervals) {
  if (intervals.length <= 1) return intervals;
  intervals.sort((a, b) => (a.start < b.start ? -1 : a.start > b.start ? 1 : 0));
  const merged = [];
  for (const iv of intervals) {
    if (!merged.length) {
      merged.push({ start: iv.start, end: iv.end });
    } else {
      const last = merged[merged.length - 1];
      if (iv.start <= last.end) {
        if (iv.end > last.end) last.end = iv.end;
      } else {
        merged.push({ start: iv.start, end: iv.end });
      }
    }
  }
  return merged;
}

function subtractIntervals(start, end, covered) {
  const result = [];
  let cursor = start;
  for (const iv of covered) {
    if (iv.end <= cursor) continue;
    if (iv.start >= end) break;
    if (iv.start > cursor) {
      result.push({ start: cursor, end: iv.start < end ? iv.start : end });
    }
    if (iv.end > cursor) {
      cursor = iv.end;
    }
    if (cursor >= end) break;
  }
  if (cursor < end) {
    result.push({ start: cursor, end });
  }
  return result;
}

function fingerprintRanges(image, executableOnly) {
  const sections = (image.sections || []).filter((x) => BigInt(x.fileSize ?? 0) > 0n && (!executableOnly || (x.perms?.execute && sectionHasMappedAddress(x))));
  const segments = (image.segments || []).filter((x) => BigInt(x.fileSize ?? 0) > 0n && (!executableOnly || x.perms?.execute));

  if (!sections.length) return segments;
  if (!segments.length) return sections;

  const ranges = [...sections];

  for (const seg of segments) {
    if (seg.address == null) continue;
    const segStart = BigInt(seg.address);
    const segFileSize = BigInt(seg.fileSize ?? 0);
    if (segFileSize <= 0n) continue;
    const segEnd = segStart + segFileSize;
    const segBias = BigInt(seg.fileOffset ?? 0) - segStart;

    const coveredIntervals = [];
    for (const sec of sections) {
      if (sec.address == null || !sectionHasMappedAddress(sec)) continue;
      const secStart = BigInt(sec.address);
      const secSize = BigInt(sec.fileSize ?? sec.size ?? 0);
      if (secSize <= 0n) continue;
      const secEnd = secStart + secSize;
      if (secEnd <= segStart || secStart >= segEnd) continue;

      if (sec.fileOffset != null && seg.fileOffset != null) {
        const secBias = BigInt(sec.fileOffset) - secStart;
        if (secBias !== segBias) {
          // Inconsistent file mapping: section does not cover segment file bytes
          continue;
        }
      } else {
        continue;
      }

      const overlapStart = secStart > segStart ? secStart : segStart;
      const overlapEnd = secEnd < segEnd ? secEnd : segEnd;
      if (overlapStart < overlapEnd) {
        coveredIntervals.push({ start: overlapStart, end: overlapEnd });
      }
    }

    const mergedCovered = mergeIntervals(coveredIntervals);
    const uncovered = subtractIntervals(segStart, segEnd, mergedCovered);
    for (const span of uncovered) {
      const spanSize = span.end - span.start;
      const offsetDelta = span.start - segStart;
      const fileOffset = BigInt(seg.fileOffset ?? 0) + offsetDelta;
      ranges.push({
        name: seg.name,
        address: span.start,
        fileOffset,
        fileSize: spanSize,
        perms: seg.perms,
      });
    }
  }

  return ranges;
}

function fingerprintImageResult(state, total, executableOnly) {
  return {
    algorithm: 'fnv1a64',
    hash: digestHex(state),
    bytes: total,
    scope: executableOnly ? 'executable-mappings' : 'all-mappings',
  };
}

/**
 * Resident images remain synchronous for API compatibility. Source-backed
 * images return a Promise and stream bounded chunks without materializing the
 * complete binary in memory (#387).
 */
export function fingerprintImage(image, opts = {}) {
  const executableOnly = opts.executableOnly !== false;
  const chunkBytes = Math.min(1 << 20, byteCountOption(opts.chunkBytes, 256 * 1024, 4096));
  const ranges = fingerprintRanges(image, executableOnly);

  if (image.bytes) {
    let state = { hi: FNV_OFFSET_HI, lo: FNV_OFFSET_LO }, total = 0;
    for (const mapping of ranges) {
      const size = BigInt(mapping.fileSize);
      for (let off = 0n; off < size;) {
        const take = Number(size - off < BigInt(chunkBytes) ? size - off : BigInt(chunkBytes));
        const bytes = requireMappingChunk(residentMappingChunk(image, mapping, off, take), take);
        state = fnv1a64State(bytes, state);
        total += bytes.length;
        off += BigInt(bytes.length);
      }
    }
    return fingerprintImageResult(state, total, executableOnly);
  }

  return (async () => {
    let state = { hi: FNV_OFFSET_HI, lo: FNV_OFFSET_LO }, total = 0;
    for (const mapping of ranges) {
      const size = BigInt(mapping.fileSize);
      for (let off = 0n; off < size;) {
        const take = Number(size - off < BigInt(chunkBytes) ? size - off : BigInt(chunkBytes));
        const bytes = requireMappingChunk(await sourceMappingChunk(image, mapping, off, take), take);
        state = fnv1a64State(bytes, state);
        total += bytes.length;
        off += BigInt(bytes.length);
      }
    }
    return fingerprintImageResult(state, total, executableOnly);
  })();
}

function digestHex(state) {
  return state.hi.toString(16).padStart(8, '0') + state.lo.toString(16).padStart(8, '0');
}
