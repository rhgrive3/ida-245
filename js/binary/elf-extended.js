import { createRelocationBudget } from './relocation-budget.js';
import { createDynamicSymbolBudget } from './dynamic-symbol-budget.js';
import { mappedELFFileRangeForVa, mappedELFFileSpanForVa } from './elf-mapping.js';

const DT_RELRSZ = 35n;
const DT_RELR = 36n;
const DT_RELRENT = 37n;
const DT_ANDROID_REL = 0x6000000fn;
const DT_ANDROID_RELSZ = 0x60000010n;
const DT_ANDROID_RELA = 0x60000011n;
const DT_ANDROID_RELASZ = 0x60000012n;
const DT_VERSYM = 0x6ffffff0n;
const DT_VERDEF = 0x6ffffffcn;
const DT_VERDEFNUM = 0x6ffffffdn;
const DT_VERNEED = 0x6ffffffen;
const DT_VERNEEDNUM = 0x6fffffffn;

const GROUPED_BY_INFO = 1n;
const GROUPED_BY_OFFSET_DELTA = 2n;
const GROUPED_BY_ADDEND = 4n;
const GROUP_HAS_ADDEND = 8n;

function one(tags, tag) { return tags.get(tag)?.[0] ?? null; }
function safe(v) { const n=Number(v); return Number.isSafeInteger(n) && n >= 0 ? n : null; }
function vaToOffset(image, va) { return mappedELFFileRangeForVa(image,va)?.start ?? null; }
function partial(image, message) {
  image.metadata.programDynamicPartial = true;
  const list=image.metadata.programDynamicDiagnostics ||= [];
  if (!list.includes(message)) list.push(message);
  image.warnings.push(`PT_DYNAMIC: ${message}`);
}

function dynamicBudget(image, limits = {}) {
  return createRelocationBudget({
    limits,
    onLimit(message) { partial(image, `relocation decode budget exceeded: ${message}`); },
  });
}

function relocationContext(image, context) {
  const c = context && typeof context === 'object' ? context : {};
  return {
    out: Array.isArray(c.out) ? c.out : [],
    budget: c.budget || dynamicBudget(image, c.limits || {}),
  };
}

export function collectRelrRelocations(r, tags, image, bits, context = null) {
  const { out, budget } = relocationContext(image, context);
  const va=one(tags,DT_RELR), size64=one(tags,DT_RELRSZ);
  if (va == null || size64 == null || size64 === 0n || budget.stopped) return out;
  const word=bits===64?8:4, ent=one(tags,DT_RELRENT) ?? BigInt(word);
  if (ent !== BigInt(word)) { partial(image,`DT_RELRENT ${ent} does not match pointer size ${word}`); return out; }
  const size=safe(size64), span=size==null?null:mappedELFFileSpanForVa(image,va,size), off=span?.start??null;
  if(off==null||size==null){partial(image,'DT_RELR table crosses a file-backed PT_LOAD boundary');return out;}
  if (!budget.claimInput(size, 'DT_RELR')) return out;
  if (size % word) partial(image,'DT_RELRSZ is not a multiple of DT_RELRENT');
  let base=0n; const wordBits=BigInt(word*8);
  const count=Math.floor(size/word);
  outer: for(let i=0;i<count;i++){
    if (!budget.step()) break;
    const entry=word===8?r.u64(off+i*word):BigInt(r.u32(off+i*word));
    if((entry&1n)===0n){
      if (!budget.push(out,{address:entry,symIndex:0,type:null,addend:null,source:'PT_DYNAMIC-RELR',relative:true},'DT_RELR')) break;
      base=entry+BigInt(word);
      continue;
    }
    for(let bit=1n;bit<wordBits;bit++) {
      if (!budget.step()) break outer;
      if(entry&(1n<<bit)) {
        if (!budget.push(out,{address:base+(bit-1n)*BigInt(word),symIndex:0,type:null,addend:null,source:'PT_DYNAMIC-RELR',relative:true},'DT_RELR')) break outer;
      }
    }
    base+=(wordBits-1n)*BigInt(word);
  }
  return out;
}

function readSleb(r, state, end) {
  let value=0n, shift=0n, byte=0;
  const min=-(1n<<63n), max=(1n<<63n)-1n;
  for(let i=0;i<10;i++){
    if(state.p>=end) throw new Error('truncated SLEB128');
    byte=r.u8(state.p++); value|=BigInt(byte&0x7f)<<shift; shift+=7n;
    if(!(byte&0x80)){
      if(byte&0x40) value|=(-1n)<<shift;
      if(value<min||value>max) throw new Error('SLEB128 exceeds signed 64-bit range');
      return value;
    }
  }
  throw new Error('SLEB128 exceeds 10 bytes');
}

function decodeAndroidTable(r, va, size64, image, bits, rela, source, budget, out) {
  if (budget.stopped) return out;
  const size=safe(size64), span=size==null?null:mappedELFFileSpanForVa(image,va,size), off=span?.start??null;
  if(off==null||size==null){partial(image,`${source} table crosses a file-backed PT_LOAD boundary`);return out;}
  if (!budget.claimInput(size, source)) return out;
  const end=off+size;
  if(size<4||r.u8(off)!==0x41||r.u8(off+1)!==0x50||r.u8(off+2)!==0x53||r.u8(off+3)!==0x32){partial(image,`${source} is not APS2 encoded`);return out;}
  const st={p:off+4};
  try {
    const relocationCount=readSleb(r,st,end);
    if(relocationCount<0n) throw new Error('negative relocation count');
    let relocationOffset=readSleb(r,st,end), relocationAddend=0n, decoded=0n;
    while(decoded<relocationCount && !budget.stopped){
      if (!budget.step()) break;
      const groupSize=readSleb(r,st,end), flags=readSleb(r,st,end);
      if(groupSize<=0n||groupSize>relocationCount-decoded) throw new Error('invalid relocation group size');
      const groupedDelta=!!(flags&GROUPED_BY_OFFSET_DELTA), groupedInfo=!!(flags&GROUPED_BY_INFO), hasAddend=!!(flags&GROUP_HAS_ADDEND), groupedAddend=!!(flags&GROUPED_BY_ADDEND);
      const groupDelta=groupedDelta?readSleb(r,st,end):0n, groupInfo=groupedInfo?readSleb(r,st,end):0n, groupAddend=hasAddend&&groupedAddend?readSleb(r,st,end):0n;
      for(let i=0n;i<groupSize && !budget.stopped;i++,decoded++){
        if (!budget.step()) break;
        relocationOffset+=groupedDelta?groupDelta:readSleb(r,st,end);
        const info=groupedInfo?groupInfo:readSleb(r,st,end);
        if(hasAddend) relocationAddend+=groupedAddend?groupAddend:readSleb(r,st,end); else if(rela) relocationAddend=0n;
        if(relocationOffset<0n||info<0n) throw new Error('negative relocation field');
        const symIndex=bits===64?Number(info>>32n):Number(info>>8n), type=bits===64?Number(info&0xffffffffn):Number(info&0xffn);
        if(!Number.isSafeInteger(symIndex)||!Number.isSafeInteger(type)) throw new Error('relocation info exceeds safe integer range');
        if (!budget.push(out,{address:relocationOffset,symIndex,type,addend:rela?relocationAddend:null,source},source)) break;
      }
    }
  } catch(error){ if (!budget.stopped) partial(image,`${source}: ${error.message}`); }
  return out;
}

export function collectAndroidPackedRelocations(r,tags,image,bits,context=null){
  const { out, budget } = relocationContext(image, context);
  const rel=one(tags,DT_ANDROID_REL), relsz=one(tags,DT_ANDROID_RELSZ), rela=one(tags,DT_ANDROID_RELA), relasz=one(tags,DT_ANDROID_RELASZ);
  if(rel!=null&&relsz!=null) decodeAndroidTable(r,rel,relsz,image,bits,false,'PT_DYNAMIC-ANDROID-REL',budget,out);
  if(!budget.stopped&&rela!=null&&relasz!=null) decodeAndroidTable(r,rela,relasz,image,bits,true,'PT_DYNAMIC-ANDROID-RELA',budget,out);
  return out;
}


function symbolBudgetContext(image, context) {
  const c = context && typeof context === 'object' ? context : {};
  return c.budget || createDynamicSymbolBudget({
    limits:c.limits || {},
    onLimit(message){ partial(image, `dynamic symbol decode budget exceeded: ${message}`); },
  });
}

function symbolVersionPair(tags, addressTag, countTag, label, image) {
  const address = one(tags, addressTag);
  const rawCount = one(tags, countTag);
  const hasAddress = address != null;
  const hasCount = rawCount != null;
  if (hasAddress !== hasCount) {
    partial(image, `${label} address/count tag pair is incomplete`);
    return { address, count: null, valid: false };
  }
  if (!hasAddress) return { address: null, count: null, valid: true };
  const count = safe(rawCount);
  if (count == null) {
    partial(image, `${label} count is not a valid non-negative safe integer`);
    return { address, count: null, valid: false };
  }
  return { address, count, valid: true };
}

export function parseDynamicSymbolVersions(r,tags,image,symbolCount,stringAt,context=null){
  const out=new Map(),versym=one(tags,DT_VERSYM);if(versym==null||symbolCount<=0)return out;const budget=symbolBudgetContext(image,context);const count=Math.min(symbolCount,budget.limits.maxSymbolRecords);if(symbolCount>count)partial(image,`DT_VERSYM symbol count ${symbolCount} exceeds record limit ${count}; clamped`);
  const vspan=mappedELFFileSpanForVa(image,versym,count*2);if(!vspan){partial(image,'DT_VERSYM table crosses a file-backed PT_LOAD boundary');return out;}const voff=vspan.start;if(!budget.claimInput(count*2,'DT_VERSYM'))return out;const names=new Map();
  const verdefPair=symbolVersionPair(tags,DT_VERDEF,DT_VERDEFNUM,'DT_VERDEF/DT_VERDEFNUM',image),verdef=verdefPair.address,verdefnum=verdefPair.count;
  if(verdefPair.valid&&verdef!=null&&verdefnum){const range=mappedELFFileRangeForVa(image,verdef);let p=range?.start??null,decoded=0;for(let i=0;p!=null&&i<Math.min(verdefnum,65536)&&!budget.stopped;i++){
    if(!budget.step(1,'DT_VERDEF decode'))break;if(p+20>range.end){partial(image,'DT_VERDEF crosses a file-backed PT_LOAD boundary');break;}if(!budget.claimInput(20,'DT_VERDEF'))break;decoded++;const ndx=r.u16(p+4)&0x7fff,cnt=r.u16(p+6),aux=r.u32(p+12),next=r.u32(p+16),ap=p+aux;
    if(cnt<1||aux<20){partial(image,'DT_VERDEF has no valid first auxiliary entry');break;}if(ap<p||ap+8>range.end){partial(image,'DT_VERDEF auxiliary entry crosses a file-backed PT_LOAD boundary');break;}if(!budget.claimInput(8,'DT_VERDEF auxiliary'))break;const name=stringAt(BigInt(r.u32(ap)));if(name){if(!budget.claimOutput(1,96,'DT_VERDEF names'))break;names.set(ndx,{name,definition:true,library:null});}if(!next)break;if(decoded===verdefnum){partial(image,`DT_VERDEF chain continues past declared count ${verdefnum}`);break;}if(next<20||p+next<=p||p+next>range.end){partial(image,'DT_VERDEF next pointer leaves its mapped table');break;}p+=next;
  }if(decoded!==verdefnum)partial(image,`DT_VERDEFNUM declares ${verdefnum} records but ${decoded} were reachable`);}
  const verneedPair=symbolVersionPair(tags,DT_VERNEED,DT_VERNEEDNUM,'DT_VERNEED/DT_VERNEEDNUM',image),verneed=verneedPair.address,verneednum=verneedPair.count;
  if(verneedPair.valid&&verneed!=null&&verneednum&&!budget.stopped){const range=mappedELFFileRangeForVa(image,verneed);let p=range?.start??null,decoded=0;for(let i=0;p!=null&&i<Math.min(verneednum,65536)&&!budget.stopped;i++){
    if(!budget.step(1,'DT_VERNEED decode'))break;if(p+16>range.end){partial(image,'DT_VERNEED crosses a file-backed PT_LOAD boundary');break;}if(!budget.claimInput(16,'DT_VERNEED'))break;decoded++;const cnt=r.u16(p+2),file=stringAt(BigInt(r.u32(p+4))),aux=r.u32(p+8),next=r.u32(p+12);let ap=p+aux;
    if(ap<p||ap>range.end){partial(image,'DT_VERNEED auxiliary pointer leaves its mapped table');break;}
    for(let j=0;j<cnt&&j<65536&&!budget.stopped;j++){
      if(!budget.step(1,'DT_VERNEED auxiliary decode'))break;if(ap+16>range.end){partial(image,'DT_VERNEED auxiliary entry crosses a file-backed PT_LOAD boundary');break;}if(!budget.claimInput(16,'DT_VERNEED auxiliary'))break;const other=r.u16(ap+6)&0x7fff,name=stringAt(BigInt(r.u32(ap+8))),anext=r.u32(ap+12);if(name){if(!budget.claimOutput(1,112,'DT_VERNEED names'))break;names.set(other,{name,definition:false,library:file||null});}if(!anext)break;if(anext<16||ap+anext<=ap||ap+anext>range.end){partial(image,'DT_VERNEED auxiliary next pointer leaves its mapped table');break;}ap+=anext;
    }
    if(!next)break;if(decoded===verneednum){partial(image,`DT_VERNEED chain continues past declared count ${verneednum}`);break;}if(next<16||p+next<=p||p+next>range.end){partial(image,'DT_VERNEED next pointer leaves its mapped table');break;}p+=next;
  }if(decoded!==verneednum)partial(image,`DT_VERNEEDNUM declares ${verneednum} records but ${decoded} were reachable`);}
  for(let i=0;i<count&&!budget.stopped;i++){if(!budget.step(1,'DT_VERSYM decode'))break;const raw=r.u16(voff+i*2),index=raw&0x7fff;if(index<=1)continue;if(!budget.claimOutput(1,96,'DT_VERSYM entries'))break;const named=names.get(index);out.set(i,{index,hidden:!!(raw&0x8000),name:named?.name||null,library:named?.library||null,definition:named?.definition??null});}
  image.metadata.symbolVersions={entries:out.size,named:[...out.values()].filter((v)=>v.name).length,complete:!budget.stopped&&!image.metadata.programDynamicPartial};return out;
}
