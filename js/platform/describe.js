import { architectureCapability } from '../architecture/index.js';
import { sectionHasMappedAddress } from '../binary/audit.js';
import { DEPLOYED_CAPSTONE_SUPPORT } from './capstone-capability.js';
import { supportDisplayForTruth, supportTruthForImage } from './support-capability.js';

function displayFormat(image) {
  if (image.format === 'elf') return `ELF ${image.bits || '?'}-bit`;
  if (image.format === 'pe') return image.bits === 64 ? 'PE32+' : 'PE32';
  if (image.format === 'macho') return `Mach-O ${image.bits || '?'}-bit`;
  return String(image.format || 'Raw binary');
}

function regionFrom(item, id, kind) {
  const fileSize = BigInt(item.fileSize ?? item.size ?? 0);
  const declaredSize = BigInt(item.size ?? fileSize);
  const section = kind === 'section' ? item.name || '' : null;
  return {
    id,
    kind,
    name: item.name || (kind === 'segment' ? `Segment ${id}` : `Section ${id}`),
    segment: item.segment || (kind === 'segment' ? item.name || null : null),
    section,
    fileOffset: BigInt(item.fileOffset ?? 0),
    vmAddr: BigInt(item.address ?? 0),
    size: fileSize,
    declaredSize,
    exec: !!item.perms?.execute && (kind !== 'section' || sectionHasMappedAddress(item)),
    write: !!item.perms?.write,
    read: !!item.perms?.read,
    zerofill: fileSize === 0n && declaredSize > 0n,
    truncated: false,
    cstrings: /cstring|string|strtab|rdata|rodata/i.test(item.name || ''),
  };
}

export function regionsForImage(image, prefix = 'p0_') {
  const sections = image.sections || [];
  const usefulSections = sections.filter((s) => BigInt(s.fileSize ?? s.size ?? 0) > 0n || BigInt(s.size ?? 0n) > 0n);
  const segments = image.segments || [];

  if (!usefulSections.length) {
    return segments.map((item, index) => regionFrom(item, `${prefix}s${index}`, 'segment'));
  }

  const regions = usefulSections.map((item, index) => regionFrom(item, `${prefix}s${index}`, 'section'));
  const mappedExecSections = usefulSections.filter((s) => sectionHasMappedAddress(s) && !!s.perms?.execute);

  let extraIndex = usefulSections.length;
  for (const seg of segments) {
    if (!seg.perms?.execute) continue;
    const segStart = BigInt(seg.address ?? 0);
    const segSize = BigInt(seg.size ?? seg.fileSize ?? 0);
    if (segSize <= 0n) continue;
    const segEnd = segStart + segSize;

    const coveredSpans = [];
    for (const sec of mappedExecSections) {
      const secStart = BigInt(sec.address ?? 0);
      const secSize = BigInt(sec.size ?? sec.fileSize ?? 0);
      if (secSize <= 0n) continue;
      const secEnd = secStart + secSize;
      if (secEnd <= segStart || secStart >= segEnd) continue;
      coveredSpans.push({
        start: secStart > segStart ? secStart : segStart,
        end: secEnd < segEnd ? secEnd : segEnd,
      });
    }

    coveredSpans.sort((a, b) => (a.start < b.start ? -1 : a.start > b.start ? 1 : 0));
    const merged = [];
    for (const span of coveredSpans) {
      if (!merged.length) {
        merged.push(span);
      } else {
        const last = merged[merged.length - 1];
        if (span.start <= last.end) {
          if (span.end > last.end) last.end = span.end;
        } else {
          merged.push(span);
        }
      }
    }

    let cursor = segStart;
    for (const span of merged) {
      if (span.start > cursor) {
        emitUncovered(cursor, span.start);
      }
      if (span.end > cursor) {
        cursor = span.end;
      }
    }
    if (cursor < segEnd) {
      emitUncovered(cursor, segEnd);
    }

    function emitUncovered(uStart, uEnd) {
      const uSize = uEnd - uStart;
      const offsetDelta = uStart - segStart;
      const fileOffset = BigInt(seg.fileOffset ?? 0) + offsetDelta;
      const segFileSize = BigInt(seg.fileSize ?? seg.size ?? 0);
      const fileSize = offsetDelta < segFileSize
        ? (segFileSize - offsetDelta < uSize ? segFileSize - offsetDelta : uSize)
        : 0n;
      const spanItem = {
        name: seg.name,
        segment: seg.name,
        address: uStart,
        size: uSize,
        fileOffset,
        fileSize,
        perms: seg.perms,
      };
      regions.push(regionFrom(spanItem, `${prefix}s${extraIndex++}`, 'segment'));
    }
  }

  return regions;
}

export function describeBinaryImage(image, options = {}) {
  const requestedEngine = options.engine || {};
  const engine = {
    ...DEPLOYED_CAPSTONE_SUPPORT,
    ...requestedEngine,
    verified: requestedEngine.verified === true,
  };
  const capability = architectureCapability(image, engine);
  const support = supportTruthForImage(image, { engine });
  const supportDisplay = supportDisplayForTruth(support);
  const regions = regionsForImage(image);
  const info = {
    cpu: image.arch || 'unknown',
    cpuSub: image.metadata?.subtypeName || (image.metadata?.subtypeBase == null ? 'all' : String(image.metadata.subtypeBase)),
    is64: image.bits === 64,
    isArm64: image.arch === 'arm64' || image.arch === 'arm64e',
    isArm64e: image.arch === 'arm64e',
    textVM: (regions.find((r) => r.exec)?.vmAddr ?? image.imageBase ?? 0n),
    encrypted: false,
    endian: image.endian,
    format: image.format,
    capability,
    support,
    supportDisplay,
  };
  const summary = image.summary();
  const formatMetadata = {
    format: image.format,
    arch: image.arch,
    bits: image.bits,
    endian: image.endian,
  };
  if (image.platform != null) formatMetadata.platform = image.platform;
  if (image.abi != null) formatMetadata.abi = image.abi;
  if (image.entrypoint != null) formatMetadata.entrypoint = image.entrypoint;
  if (image.imageBase != null) formatMetadata.imageBase = image.imageBase;
  if (image.metadata?.riscvIsa != null) formatMetadata.riscvIsa = image.metadata.riscvIsa;
  const productDescriptor = {
    formatId: image.format || 'raw',
    regions,
    dependencies: [...(image.libraries || [])],
    imports: [...(image.imports || [])],
    exports: [...(image.exports || [])],
    formatMetadata,
    support,
  };
  info.descriptor = productDescriptor;
  const raw = {
    id: 'raw', kind: 'file', name: 'Whole file (raw)', fileOffset: 0n, vmAddr: 0n,
    size: image.fileSize, declaredSize: image.fileSize, exec: false, write: false, read: true,
    zerofill: false, truncated: false,
  };
  return {
    name: options.name || 'binary',
    size: image.fileSize,
    format: displayFormat(image),
    formatId: image.format,
    slices: [{ name: image.arch || 'unknown', offset: image.fileOffset || 0n, size: image.fileSize, info, capability, support, supportDisplay, regions }],
    raw,
    productDescriptor,
    warnings: [...(image.warnings || [])],
    capability,
    support,
    supportDisplay,
    platform: {
      summary,
      sourceBacked: !!image.metadata?.sourceBacked,
      sourceReads: image.metadata?.sourceReads || null,
      metadataKeys: Object.keys(image.metadata || {}).sort(),
    },
  };
}