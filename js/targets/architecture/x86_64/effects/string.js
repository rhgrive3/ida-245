import { createX86EffectContext, x86MemoryFaults, x86RegisterOperand } from './common.js';
import { x86EffectiveAddressExpression } from './addressing.js';
import { emitX86ArithmeticFlags } from './flags.js';

const STRING_FAMILIES = new Map([
  ['movsb', { kind:'movs', widthBits:8 }], ['movsw', { kind:'movs', widthBits:16 }],
  ['movsd', { kind:'movs', widthBits:32, ambiguous:true }], ['movsq', { kind:'movs', widthBits:64 }],
  ['stosb', { kind:'stos', widthBits:8 }], ['stosw', { kind:'stos', widthBits:16 }],
  ['stosd', { kind:'stos', widthBits:32 }], ['stosq', { kind:'stos', widthBits:64 }],
  ['lodsb', { kind:'lods', widthBits:8 }], ['lodsw', { kind:'lods', widthBits:16 }],
  ['lodsd', { kind:'lods', widthBits:32 }], ['lodsq', { kind:'lods', widthBits:64 }],
  ['cmpsb', { kind:'cmps', widthBits:8 }], ['cmpsw', { kind:'cmps', widthBits:16 }],
  ['cmpsd', { kind:'cmps', widthBits:32, ambiguous:true }], ['cmpsq', { kind:'cmps', widthBits:64 }],
  ['scasb', { kind:'scas', widthBits:8 }], ['scasw', { kind:'scas', widthBits:16 }],
  ['scasd', { kind:'scas', widthBits:32 }], ['scasq', { kind:'scas', widthBits:64 }],
]);
const SEGMENT_PREFIX = new Map([[0x2e,'cs'],[0x36,'ss'],[0x3e,'ds'],[0x26,'es'],[0x64,'fs'],[0x65,'gs']]);
const LEGACY_PREFIXES = new Set([0xf0,0xf2,0xf3,0x2e,0x36,0x3e,0x26,0x64,0x65,0x66,0x67]);
const COMPARE_FLAGS = Object.freeze(['CF','PF','AF','ZF','SF','OF']);

function legacyPrefixes(instruction) { return [...(instruction?.detail?.prefixes?.legacy || [])]; }
function addressSizeBits(instruction) { const width = Number(instruction?.detail?.addressSizeBits || 64); return width === 32 || width === 64 ? width : null; }
function accumulatorName(widthBits) { return ({8:'al',16:'ax',32:'eax',64:'rax'})[widthBits] || null; }
function pointerName(role, widthBits) {
  if (role === 'source') return widthBits === 32 ? 'esi' : 'rsi';
  if (role === 'destination') return widthBits === 32 ? 'edi' : 'rdi';
  if (role === 'count') return widthBits === 32 ? 'ecx' : 'rcx';
  return null;
}
function sourceSegment(instruction) { let segment = 'ds'; for (const prefix of legacyPrefixes(instruction)) if (SEGMENT_PREFIX.has(prefix)) segment = SEGMENT_PREFIX.get(prefix); return segment; }
function repeatKind(instruction, kind) {
  const prefixes = legacyPrefixes(instruction);
  if (prefixes.includes(0xf2)) return kind === 'cmps' || kind === 'scas' ? 'repne' : 'unsupported-f2';
  if (prefixes.includes(0xf3)) return kind === 'cmps' || kind === 'scas' ? 'repe' : 'rep';
  return null;
}
function physicalSet(values) { return new Set((values || []).map((entry) => entry?.physicalId || entry?.id).filter(Boolean)); }
function hasVectorOperand(instruction) { return (instruction?.detail?.operands || []).some((operand) => operand?.type === 'register' && operand.register?.kind === 'vector'); }
function ambiguousStringFormIsProven(instruction, spec) {
  if (!spec.ambiguous) return true;
  if (hasVectorOperand(instruction)) return false;
  const reads = physicalSet(instruction?.detail?.implicitReads), writes = physicalSet(instruction?.detail?.implicitWrites);
  return (reads.has('rsi') || writes.has('rsi')) && (reads.has('rdi') || writes.has('rdi'));
}
function repeatedPrefixMultiplicity(instruction) {
  const bytes = instruction?.rawBytes || [];
  let repeat = 0, lock = 0, segment = 0, operandSize = 0, addressSize = 0;
  for (const byte of bytes) {
    if (!LEGACY_PREFIXES.has(byte) && !(byte >= 0x40 && byte <= 0x4f)) break;
    if (byte === 0xf2 || byte === 0xf3) repeat++;
    else if (byte === 0xf0) lock++;
    else if (SEGMENT_PREFIX.has(byte)) segment++;
    else if (byte === 0x66) operandSize++;
    else if (byte === 0x67) addressSize++;
  }
  return { repeat, lock, segment, operandSize, addressSize };
}
function prefixStateIsProven(instruction) {
  const legacy = legacyPrefixes(instruction);
  if (legacy.some((prefix) => !LEGACY_PREFIXES.has(prefix))) return false;
  const normalizedRepeat = legacy.filter((prefix) => prefix === 0xf2 || prefix === 0xf3).length;
  const normalizedSegment = legacy.filter((prefix) => SEGMENT_PREFIX.has(prefix)).length;
  const multiplicity = repeatedPrefixMultiplicity(instruction);
  return normalizedRepeat <= 1 && normalizedSegment <= 1
    && legacy.filter((prefix) => prefix === 0x66).length <= 1
    && legacy.filter((prefix) => prefix === 0x67).length <= 1
    && !legacy.includes(0xf0)
    && multiplicity.repeat <= 1 && multiplicity.lock === 0 && multiplicity.segment <= 1
    && multiplicity.operandSize <= 1 && multiplicity.addressSize <= 1;
}
function memoryBaseIs(operand, name) { return operand?.type === 'memory' && operand.memory?.base?.id === name && operand.memory?.index == null && Number(operand.memory?.scale) === 1 && BigInt(operand.memory?.displacement ?? 0n) === 0n; }
function accessIs(operand, expected) { return operand?.access === expected || operand?.access === 'unknown'; }
function registerIs(operand, name, access) { return operand?.type === 'register' && operand.register?.id === name && (!access || accessIs(operand,access)); }
function stringOperandShapeIsProven(instruction, spec, addressBits) {
  const operands = instruction?.detail?.operands || [], source = pointerName('source', addressBits), destination = pointerName('destination', addressBits), accumulator = accumulatorName(spec.widthBits);
  const mem = (operand, base, access) => memoryBaseIs(operand,base) && operand.widthBits === spec.widthBits && accessIs(operand,access);
  if (spec.kind === 'movs') return operands.length === 2 && mem(operands[0],destination,'write') && mem(operands[1],source,'read');
  if (spec.kind === 'stos') return operands.length === 2 && mem(operands[0],destination,'write') && registerIs(operands[1],accumulator,'read');
  if (spec.kind === 'lods') return operands.length === 2 && registerIs(operands[0],accumulator,'write') && mem(operands[1],source,'read');
  if (spec.kind === 'cmps') return operands.length === 2 && mem(operands[0],source,'read') && mem(operands[1],destination,'read');
  if (spec.kind === 'scas') return operands.length === 2 && registerIs(operands[0],accumulator,'read') && mem(operands[1],destination,'read');
  return false;
}
function requiredImplicitState(spec, repeat) {
  const reads = new Set(['rflags']), writes = new Set();
  if (['movs','lods','cmps'].includes(spec.kind)) { reads.add('rsi'); writes.add('rsi'); }
  if (['movs','stos','cmps','scas'].includes(spec.kind)) { reads.add('rdi'); writes.add('rdi'); }
  if (spec.kind === 'stos' || spec.kind === 'scas') reads.add('rax');
  if (spec.kind === 'lods') writes.add('rax');
  if (spec.kind === 'cmps' || spec.kind === 'scas') writes.add('rflags');
  if (repeat) { reads.add('rcx'); writes.add('rcx'); }
  return { reads, writes };
}
function implicitStateIsProven(instruction, spec, repeat) {
  const actualReads = physicalSet(instruction?.detail?.implicitReads), actualWrites = physicalSet(instruction?.detail?.implicitWrites), required = requiredImplicitState(spec,repeat);
  return [...required.reads].every((name) => actualReads.has(name)) && [...required.writes].every((name) => actualWrites.has(name));
}
function stringMemoryOperand(role, widthBits, addressBits, segment) {
  const register = x86RegisterOperand(pointerName(role, addressBits));
  if (!register) return null;
  return Object.freeze({ type:'memory', widthBits, access:'unknown', memory:Object.freeze({ base:register.register, index:null, scale:1, displacement:0n, segment, addressSizeBits:addressBits }) });
}
function stringAddress(ctx, role, spec, addressBits) {
  const segment = role === 'source' ? sourceSegment(ctx.instruction) : 'es';
  const operand = stringMemoryOperand(role, spec.widthBits, addressBits, segment);
  return operand ? x86EffectiveAddressExpression(ctx.instruction, operand) : null;
}
function updatePointer(ctx, role, addressBits, elementBytes, directionFlag) {
  const operand = x86RegisterOperand(pointerName(role, addressBits));
  const current = operand ? ctx.readRegister(operand) : null;
  if (!current) return false;
  const inc = ctx.valueOp('add', [current,ctx.constant(addressBits,BigInt(elementBytes))], addressBits, { semantic:'x86-string-pointer-increment', role, elementBytes, addressSizeBits:addressBits, wrap:true });
  const dec = ctx.valueOp('sub', [current,ctx.constant(addressBits,BigInt(elementBytes))], addressBits, { semantic:'x86-string-pointer-decrement', role, elementBytes, addressSizeBits:addressBits, wrap:true });
  const next = ctx.valueOp('select', [directionFlag,dec,inc], addressBits, { semantic:'x86-string-direction-select', condition:'DF', truePath:'decrement', falsePath:'increment', elementBytes });
  return ctx.writeRegister(operand, next);
}
function readPhysicalRegister(ctx, name) {
  const operand = x86RegisterOperand(name);
  return operand ? ctx.readRegister(operand) : null;
}
function repeatedMemoryScope(spaces, detail) {
  const unique = [...new Set(spaces.filter(Boolean))].sort();
  return unique.length === 0 ? { scope:'none' } : { scope:'all', spaces:unique, detail };
}
function repeatedStringEffects(ctx, spec, repeat, addressBits) {
  const elementBytes = spec.widthBits / 8, sourcePresent = ['movs','lods','cmps'].includes(spec.kind), destinationPresent = ['movs','stos','cmps','scas'].includes(spec.kind);
  const sourceAddress = sourcePresent ? stringAddress(ctx,'source',spec,addressBits) : null, destinationAddress = destinationPresent ? stringAddress(ctx,'destination',spec,addressBits) : null;
  if (sourcePresent && !sourceAddress) return ctx.partial('x86-repeated-string-source-address-unmodelled',['memory','registers']);
  if (destinationPresent && !destinationAddress) return ctx.partial('x86-repeated-string-destination-address-unmodelled',['memory','registers']);

  const inputs = [], inputRoles = [], registersRead = [], registersWritten = [], outputs = [], outputRoles = [];
  const addInput = (name,value,role) => { if (!value) return false; inputs.push(value); inputRoles.push(Object.freeze(role)); registersRead.push(name); return true; };
  const addOutput = (role,widthBits,registerName) => { outputs.push(widthBits); outputRoles.push({role,registerName}); if (registerName) registersWritten.push(registerName); };
  const addressStates = [];
  const readAddressState = (role,physicalRegister) => {
    const full = readPhysicalRegister(ctx,physicalRegister);
    if (!full) return null;
    registersRead.push(physicalRegister);
    const state = { role, physicalRegister,view:pointerName(role,addressBits),full,semantic:null };
    addressStates.push(state);
    return state;
  };

  const countState = readAddressState('count','rcx');
  if (!countState) return ctx.partial('x86-repeated-string-count-unmodelled',['registers']);
  const df = ctx.readFlag('DF'); registersRead.push('rflags');
  const sourceState = sourcePresent ? readAddressState('source','rsi') : null;
  if (sourcePresent && !sourceState) return ctx.partial('x86-repeated-string-source-pointer-unmodelled',['registers']);
  const destinationState = destinationPresent ? readAddressState('destination','rdi') : null;
  if (destinationPresent && !destinationState) return ctx.partial('x86-repeated-string-destination-pointer-unmodelled',['registers']);

  if (addressBits === 32) {
    const projected = addressStates.map((state) => ctx.temporary(32, `repeated-string-${state.view}`));
    ctx.addOperation({
      kind:'value', opcode:'x86-string-address-state-project32',
      inputs:addressStates.map((state) => state.full), outputs:projected,
      metadata:{
        semantic:'x86-repeated-string-address-state-view', addressSizeBits:32,
        projections:addressStates.map((state) => ({ role:state.role, physicalRegister:state.physicalRegister, view:state.view, lsb:0, widthBits:32 })),
      },
    });
    for (let index = 0; index < addressStates.length; index++) addressStates[index].semantic = projected[index];
  } else {
    for (const state of addressStates) state.semantic = state.full;
  }

  const addAddressStateInputs = (state) => {
    if (!addInput(state.physicalRegister,state.semantic,{ role:state.role, kind:'semantic', register:state.view, widthBits:addressBits })) return false;
    if (addressBits === 32 && !addInput(state.physicalRegister,state.full,{ role:state.role, kind:'zero-count-preservation', register:state.physicalRegister, widthBits:64 })) return false;
    return true;
  };
  if (!addAddressStateInputs(countState)) return ctx.partial('x86-repeated-string-count-unmodelled',['registers']);
  inputs.push(df); inputRoles.push(Object.freeze({ role:'direction-flag', kind:'semantic', flag:'DF', widthBits:1 }));
  if (sourceState && !addAddressStateInputs(sourceState)) return ctx.partial('x86-repeated-string-source-pointer-unmodelled',['registers']);
  if (destinationState && !addAddressStateInputs(destinationState)) return ctx.partial('x86-repeated-string-destination-pointer-unmodelled',['registers']);
  if (spec.kind === 'stos' || spec.kind === 'scas') {
    const accumulator = x86RegisterOperand(accumulatorName(spec.widthBits)), value = accumulator ? ctx.readRegister(accumulator) : null;
    if (!addInput('rax',value,{ role:'accumulator', kind:'semantic', register:accumulatorName(spec.widthBits), widthBits:spec.widthBits })) return ctx.partial('x86-repeated-string-accumulator-unmodelled',['registers']);
  }
  if (spec.kind === 'lods' && !addInput('rax',readPhysicalRegister(ctx,'rax'),{ role:'accumulator', kind:'zero-count-preservation', register:'rax', widthBits:64 })) return ctx.partial('x86-repeated-string-accumulator-state-unmodelled',['registers']);
  if (spec.kind === 'cmps' || spec.kind === 'scas') {
    if (addressBits === 32) {
      const flags = readPhysicalRegister(ctx,'rflags');
      if (!addInput('rflags',flags,{ role:'compare-flags', kind:'zero-count-preservation', register:'rflags', widthBits:64, flags:COMPARE_FLAGS })) return ctx.partial('x86-repeated-string-compare-flags-unmodelled',['flags','registers']);
    } else {
      for (const flag of COMPARE_FLAGS) {
        const value = ctx.readFlag(flag); inputs.push(value); inputRoles.push(Object.freeze({ role:`flag-${flag}`, kind:'zero-count-preservation', flag, widthBits:1 }));
      }
      registersRead.push('rflags');
    }
  }

  addOutput('count',64,'rcx');
  if (sourcePresent) addOutput('source-pointer',64,'rsi');
  if (destinationPresent) addOutput('destination-pointer',64,'rdi');
  if (spec.kind === 'lods') addOutput('accumulator',64,'rax');
  if (spec.kind === 'cmps' || spec.kind === 'scas') for (const flag of COMPARE_FLAGS) addOutput(`flag-${flag}`,1,'rflags');

  const readsMemory = sourcePresent || spec.kind === 'scas', writesMemory = spec.kind === 'movs' || spec.kind === 'stos';
  const sourceDescriptor = sourceAddress ? Object.freeze({ role:'source', pointerPhysical:'rsi', pointerView:pointerName('source',addressBits), space:sourceAddress.space, segment:sourceAddress.metadata.segment, segmentBaseRule:sourceAddress.metadata.segmentBaseRule }) : null;
  const destinationDescriptor = destinationAddress ? Object.freeze({ role:'destination', pointerPhysical:'rdi', pointerView:pointerName('destination',addressBits), space:destinationAddress.space, segment:'es', segmentBaseRule:destinationAddress.metadata.segmentBaseRule }) : null;
  const perIterationSteps = Object.freeze(({
    movs:['source-read','destination-write','pointer/count-commit'],
    stos:['destination-write','pointer/count-commit'],
    lods:['source-read','accumulator-write','pointer/count-commit'],
    cmps:['source-read','destination-read','compare-flags-write','pointer/count-commit','termination-test'],
    scas:['accumulator-read','destination-read','compare-flags-write','pointer/count-commit','termination-test'],
  })[spec.kind].slice());
  const iterationMemory = Object.freeze({
    kind:'strided-runtime-count', elementWidthBits:spec.widthBits, elementBytes, addressSizeBits:addressBits, perIterationSteps,
    direction:'DF=0 adds elementBytes; DF=1 subtracts elementBytes',
    source:sourceDescriptor, destination:destinationDescriptor,
    zeroCount:'no memory access', faultProgress:'only fully completed elements advance pointers/count; faulting element remains restart point',
  });
  const readSpaces = [];
  if (sourcePresent) readSpaces.push(sourceAddress.space);
  if (spec.kind === 'cmps' || spec.kind === 'scas') readSpaces.push('memory');
  const writeSpaces = writesMemory ? ['memory'] : [];
  const continuation = repeat === 'repe'
    ? 'after each completed comparison: remaining count != 0 && updated ZF == 1'
    : repeat === 'repne'
      ? 'after each completed comparison: remaining count != 0 && updated ZF == 0'
      : 'after each completed element: remaining count != 0';
  const flagContract = spec.kind === 'cmps' || spec.kind === 'scas'
    ? Object.freeze({ reads:Object.freeze(['DF',...COMPARE_FLAGS]), writes:COMPARE_FLAGS, zeroCount:'all flags preserved', nonzero:'CF/PF/AF/ZF/SF/OF equal the last completed comparison; DF and unrelated flags preserved', initialZF:'does not gate the first iteration' })
    : Object.freeze({ reads:Object.freeze(['DF']), writes:Object.freeze([]), zeroCount:'all flags preserved', nonzero:'all flags preserved' });
  const metadata = {
    summaryContractVersion:'x86-repeated-string-summary/v1', exactArchitecturalSummary:true, boundedSummary:true, runtimeCountNotUnrolled:true,
    operation:spec.kind, repeatKind:repeat, repeatAliases:repeat === 'repe' ? Object.freeze(['repe','repz']) : repeat === 'repne' ? Object.freeze(['repne','repnz']) : Object.freeze(['rep']),
    elementWidthBits:spec.widthBits, elementBytes, addressSizeBits:addressBits,
    count:Object.freeze({ physicalRegister:'rcx', view:pointerName('count',addressBits), widthBits:addressBits, entryPredicate:'count != 0', decrement:'once after each fully completed element', zeroCount:'preserve full RCX; perform zero iterations', nonzeroWrite:addressBits === 32 ? 'write ECX after each completed element, zero-extending RCX' : 'write RCX after each completed element' }),
    direction:Object.freeze({ flag:'DF', zeroDelta:elementBytes, oneDelta:-elementBytes, arithmeticWidthBits:addressBits, zeroCount:'pointers preserve full physical register values', nonzeroWrite:addressBits === 32 ? 'ESI/EDI writes zero-extend their physical RSI/RDI after the first completed element' : 'RSI/RDI update modulo 2^64' }),
    termination:Object.freeze({ entry:'count != 0', continuation, normalControl:'fallthrough', zeroCount:'fallthrough with no data-memory access and no architectural state change', initialConditionFlagUsedBeforeFirstIteration:false }),
    flags:flagContract, memory:iterationMemory,
    accumulator:spec.kind === 'lods' ? Object.freeze({ physicalRegister:'rax', view:accumulatorName(spec.widthBits), zeroCount:'full RAX preserved', nonzero:spec.widthBits === 8 ? 'final successful AL load replaces low 8 bits and preserves upper 56 bits of RAX' : spec.widthBits === 16 ? 'final successful AX load replaces low 16 bits and preserves upper 48 bits of RAX' : spec.widthBits === 32 ? 'final successful EAX load zero-extends into full RAX' : 'final successful RAX load replaces full RAX' }) : spec.kind === 'stos' || spec.kind === 'scas' ? Object.freeze({ physicalRegister:'rax', view:accumulatorName(spec.widthBits), access:'read-only', zeroCount:'no accumulator effect' }) : null,
    addressState:Object.freeze({
      semanticWidthBits:addressBits,
      inputPolicy:addressBits === 32 ? 'semantic ECX/ESI/EDI low-32 views plus full physical preservation carriers' : 'full physical RCX/RSI/RDI values are the semantic address-size views',
      arithmetic:addressBits === 32 ? 'modulo 2^32' : 'modulo 2^64',
      outputPolicy:addressBits === 32 ? '64-bit physical output selects full entry state when ECX is zero; otherwise commits zero-extended 32-bit count/pointer results' : '64-bit physical result',
    }),
    inputRoles:Object.freeze(inputRoles),
    outputRoles:Object.freeze(outputRoles.map((entry) => Object.freeze(entry))),
  };
  const intrinsicOutputs = ctx.intrinsic(`x86.${repeat}.${spec.kind}.${spec.widthBits}`, inputs, outputs, {
    registersRead:[...new Set(registersRead)], registersWritten:[...new Set(registersWritten)],
    memoryRead:repeatedMemoryScope(readsMemory ? readSpaces : [],iterationMemory), memoryWrite:repeatedMemoryScope(writeSpaces,iterationMemory),
    controlEffects:[], determinism:'input-dependent', symbolicDetail:'summary-only', metadata,
  });
  let cursor = 0;
  const nextCount = intrinsicOutputs[cursor++];
  if (!ctx.writeRegister(x86RegisterOperand('rcx'),nextCount)) return ctx.partial('x86-repeated-string-count-write-unmodelled',['registers']);
  if (sourcePresent && !ctx.writeRegister(x86RegisterOperand('rsi'),intrinsicOutputs[cursor++])) return ctx.partial('x86-repeated-string-source-pointer-write-unmodelled',['registers']);
  if (destinationPresent && !ctx.writeRegister(x86RegisterOperand('rdi'),intrinsicOutputs[cursor++])) return ctx.partial('x86-repeated-string-destination-pointer-write-unmodelled',['registers']);
  if (spec.kind === 'lods' && !ctx.writeRegister(x86RegisterOperand('rax'),intrinsicOutputs[cursor++])) return ctx.partial('x86-repeated-string-accumulator-write-unmodelled',['registers']);
  if (spec.kind === 'cmps' || spec.kind === 'scas') for (const flag of COMPARE_FLAGS) ctx.writeFlag(flag,intrinsicOutputs[cursor++],{ operation:spec.kind, repeated:true, repeatKind:repeat, zeroCountPreserves:true, finalCompletedComparison:true });

  const possibleFaults = [];
  if (readsMemory) possibleFaults.push(...x86MemoryFaults('read',spec.widthBits));
  if (writesMemory) possibleFaults.push(...x86MemoryFaults('write',spec.widthBits));
  return ctx.finish({ family:'string', possibleFaults, metadata:{ operation:spec.kind, elementWidthBits:spec.widthBits, addressSizeBits:addressBits, repeatKind:repeat, repeated:true, exactRepeatedSummary:true, sourceAddress:sourceAddress?.metadata ?? null, destinationAddress:destinationAddress?.metadata ?? null } });
}
function liftSingleString(ctx, spec, addressBits) {
  const elementBytes = spec.widthBits / 8, df = ctx.readFlag('DF'), possibleFaults = [];
  let sourceAddress = null, destinationAddress = null;
  if (['movs','lods','cmps'].includes(spec.kind)) { sourceAddress = stringAddress(ctx,'source',spec,addressBits); if (!sourceAddress) return ctx.partial('x86-string-source-address-unmodelled',['memory','registers']); }
  if (['movs','stos','cmps','scas'].includes(spec.kind)) { destinationAddress = stringAddress(ctx,'destination',spec,addressBits); if (!destinationAddress) return ctx.partial('x86-string-destination-address-unmodelled',['memory','registers']); }
  if (spec.kind === 'movs') {
    const value = ctx.readMemory(sourceAddress.expression,spec.widthBits,{space:sourceAddress.space,metadata:{...sourceAddress.metadata,stringRole:'source',elementWidthBits:spec.widthBits}});
    ctx.writeMemory(destinationAddress.expression,spec.widthBits,value,{space:destinationAddress.space,metadata:{...destinationAddress.metadata,stringRole:'destination',elementWidthBits:spec.widthBits}});
    possibleFaults.push(...x86MemoryFaults('read',spec.widthBits),...x86MemoryFaults('write',spec.widthBits));
    if (!updatePointer(ctx,'source',addressBits,elementBytes,df) || !updatePointer(ctx,'destination',addressBits,elementBytes,df)) return ctx.partial('x86-movs-pointer-update-unmodelled',['registers']);
  } else if (spec.kind === 'stos') {
    const acc = x86RegisterOperand(accumulatorName(spec.widthBits)), value = acc ? ctx.readRegister(acc) : null;
    if (!value) return ctx.partial('x86-stos-accumulator-unmodelled',['registers','memory']);
    ctx.writeMemory(destinationAddress.expression,spec.widthBits,value,{space:destinationAddress.space,metadata:{...destinationAddress.metadata,stringRole:'destination',accumulator:acc.register.id}});
    possibleFaults.push(...x86MemoryFaults('write',spec.widthBits));
    if (!updatePointer(ctx,'destination',addressBits,elementBytes,df)) return ctx.partial('x86-stos-pointer-update-unmodelled',['registers']);
  } else if (spec.kind === 'lods') {
    const value = ctx.readMemory(sourceAddress.expression,spec.widthBits,{space:sourceAddress.space,metadata:{...sourceAddress.metadata,stringRole:'source',elementWidthBits:spec.widthBits}}), acc = x86RegisterOperand(accumulatorName(spec.widthBits));
    if (!acc || !ctx.writeRegister(acc,value)) return ctx.partial('x86-lods-accumulator-unmodelled',['registers','memory']);
    possibleFaults.push(...x86MemoryFaults('read',spec.widthBits));
    if (!updatePointer(ctx,'source',addressBits,elementBytes,df)) return ctx.partial('x86-lods-pointer-update-unmodelled',['registers']);
  } else if (spec.kind === 'cmps') {
    const left = ctx.readMemory(sourceAddress.expression,spec.widthBits,{space:sourceAddress.space,metadata:{...sourceAddress.metadata,stringRole:'source',compareOperand:'left'}}), right = ctx.readMemory(destinationAddress.expression,spec.widthBits,{space:destinationAddress.space,metadata:{...destinationAddress.metadata,stringRole:'destination',compareOperand:'right'}}), result = ctx.valueOp('sub',[left,right],spec.widthBits,{compareOnly:true,semantic:'x86-cmps'});
    emitX86ArithmeticFlags(ctx,'cmp',left,right,result,spec.widthBits); possibleFaults.push(...x86MemoryFaults('read',spec.widthBits),...x86MemoryFaults('read',spec.widthBits));
    if (!updatePointer(ctx,'source',addressBits,elementBytes,df) || !updatePointer(ctx,'destination',addressBits,elementBytes,df)) return ctx.partial('x86-cmps-pointer-update-unmodelled',['registers','flags']);
  } else if (spec.kind === 'scas') {
    const acc = x86RegisterOperand(accumulatorName(spec.widthBits)), left = acc ? ctx.readRegister(acc) : null;
    if (!left) return ctx.partial('x86-scas-accumulator-unmodelled',['registers','memory','flags']);
    const right = ctx.readMemory(destinationAddress.expression,spec.widthBits,{space:destinationAddress.space,metadata:{...destinationAddress.metadata,stringRole:'destination',compareOperand:'right'}}), result = ctx.valueOp('sub',[left,right],spec.widthBits,{compareOnly:true,semantic:'x86-scas'});
    emitX86ArithmeticFlags(ctx,'cmp',left,right,result,spec.widthBits); possibleFaults.push(...x86MemoryFaults('read',spec.widthBits));
    if (!updatePointer(ctx,'destination',addressBits,elementBytes,df)) return ctx.partial('x86-scas-pointer-update-unmodelled',['registers','flags']);
  }
  return ctx.finish({ family:'string', possibleFaults, metadata:{ operation:spec.kind, elementWidthBits:spec.widthBits, addressSizeBits:addressBits, repeatKind:null, directionFlag:'explicit-read', dfZeroDelta:elementBytes, dfOneDelta:-elementBytes, sourceAddress:sourceAddress?.metadata ?? null, destinationAddress:destinationAddress?.metadata ?? null } });
}
export function liftX86StringEffects(instruction, context = {}) {
  const family = String(instruction?.instructionFamily || '').toLowerCase(), spec = STRING_FAMILIES.get(family);
  if (!spec || !ambiguousStringFormIsProven(instruction,spec)) return null;
  const ctx = createX86EffectContext(instruction,context), addressBits = addressSizeBits(ctx.instruction);
  if (!addressBits) return ctx.partial('x86-string-address-size-unmodelled',['memory','registers']);
  if (!prefixStateIsProven(ctx.instruction)) return ctx.partial('x86-string-prefix-state-unmodelled',['memory','registers','flags'],{metadata:{family:'string',operation:spec.kind}});
  const repeat = repeatKind(ctx.instruction,spec.kind);
  if (repeat === 'unsupported-f2') return ctx.partial('x86-string-f2-repeat-prefix-not-proven-for-this-family',['memory','registers','flags'],{metadata:{family:'string',operation:spec.kind,lockIgnored:false,prefix:0xf2}});
  if (!stringOperandShapeIsProven(ctx.instruction,spec,addressBits)) return ctx.partial('x86-string-operand-shape-unmodelled',['memory','registers','flags'],{metadata:{family:'string',operation:spec.kind,addressSizeBits:addressBits,elementWidthBits:spec.widthBits}});
  if (!implicitStateIsProven(ctx.instruction,spec,repeat)) return ctx.partial('x86-string-implicit-state-unmodelled',['registers','flags'],{metadata:{family:'string',operation:spec.kind,addressSizeBits:addressBits,elementWidthBits:spec.widthBits,repeatKind:repeat}});
  return repeat ? repeatedStringEffects(ctx,spec,repeat,addressBits) : liftSingleString(ctx,spec,addressBits);
}
