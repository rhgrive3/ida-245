import { createX86EffectContext } from './common.js';

const EXECUTION_ENV = 'sys:x86.execution-environment';
const CONTROL_DERIVED_STATE = 'sys:x86.control-register-derived-state';
const DEBUG_DERIVED_STATE = 'sys:x86.debug-register-derived-state';

function privilegedKind(operand) {
  if (operand?.type !== 'register') return null;
  const id = String(operand.register?.id || '').toLowerCase();
  const kind = String(operand.register?.architecturalKind || operand.register?.kind || '').toLowerCase();
  if (kind === 'control-register' || /^cr(?:[0-9]|1[0-5])$/.test(id)) return 'control-register';
  if (kind === 'debug-register' || /^dr(?:[0-9]|1[0-5])$/.test(id)) return 'debug-register';
  return null;
}

function encoding(instruction) {
  const raw = [...(instruction?.rawBytes || [])];
  if (raw.length < 3 || raw.length > 4) return null;
  let cursor = 0;
  let rex = null;
  if (raw[cursor] >= 0x40 && raw[cursor] <= 0x4f) rex = raw[cursor++];
  if (cursor + 3 !== raw.length || raw[cursor] !== 0x0f) return null;
  const opcode = raw[cursor + 1];
  if (![0x20,0x21,0x22,0x23].includes(opcode)) return null;
  const modrm = raw[cursor + 2];
  return Object.freeze({ rex, opcode, modrm });
}

function trusted(instruction) {
  return instruction?.detailAvailable === true
    && instruction?.detailStatus === 'complete'
    && instruction?.decoderSemanticVersion === 'capstone-5-x86-structured-v2'
    && instruction?.detail?.abiContractVersion === 'capstone-5-wasm32-x86-detail/v1'
    && String(instruction?.opcodeName || instruction?.instructionFamily || '').toLowerCase() === 'mov';
}

function privilegeFault(kind, id) {
  return Object.freeze({
    kind:'general-protection',
    condition:Object.freeze({
      kind:'x86-privilege-check',
      instruction:'mov',
      registerClass:kind,
      register:id,
      rule:'CPL != 0',
    }),
    detail:Object.freeze({ fault:'#GP(0)' }),
  });
}

function invalidRegisterFault(kind, id) {
  return Object.freeze({
    kind:'undefined-opcode',
    condition:Object.freeze({
      kind:'x86-control-debug-register-validity',
      instruction:'mov',
      registerClass:kind,
      register:id,
      rule:'reserved register encoding or architectural feature unavailable',
    }),
    detail:Object.freeze({ fault:'#UD' }),
  });
}

function controlWriteFault(id) {
  return Object.freeze({
    kind:'general-protection',
    condition:Object.freeze({
      kind:'x86-control-register-write-validation',
      instruction:'mov',
      register:id,
      rule:'reserved/fixed-bit, paging, PCID, or feature-state precondition violated',
    }),
    detail:Object.freeze({ fault:'#GP(0)' }),
  });
}

function debugGeneralDetectFault() {
  return Object.freeze({
    kind:'debug-exception',
    condition:Object.freeze({
      kind:'x86-debug-general-detect',
      instruction:'mov',
      rule:'DR7.GD=1 causes #DB before debug-register access; DR6.BD records the cause',
    }),
    detail:Object.freeze({ fault:'#DB' }),
  });
}

function debugAliasUndefinedFault(id) {
  return Object.freeze({
    kind:'undefined-opcode',
    condition:Object.freeze({
      kind:'x86-debug-register-alias-control',
      instruction:'mov',
      register:id,
      controlRegister:'cr4',
      field:'DE',
      value:1,
      rule:'CR4.DE=1 makes DR4/DR5 access undefined after any DR7.GD pre-access #DB',
    }),
    detail:Object.freeze({ fault:'#UD' }),
  });
}

function expectedShape(encoded) {
  if (encoded.opcode === 0x20) return { kind:'control-register', privilegedIndex:1 };
  if (encoded.opcode === 0x22) return { kind:'control-register', privilegedIndex:0 };
  if (encoded.opcode === 0x21) return { kind:'debug-register', privilegedIndex:1 };
  return { kind:'debug-register', privilegedIndex:0 };
}

export function liftX86SystemRegisterMoveEffects(instruction, context = {}) {
  const family = String(instruction?.instructionFamily || '').toLowerCase();
  if (family !== 'mov') return null;
  const operands = instruction?.detail?.operands || [];
  const hasPrivileged = operands.some((operand) => privilegedKind(operand) != null);
  if (!hasPrivileged) return null;

  const ctx = createX86EffectContext(instruction, context);
  const encoded = encoding(ctx.instruction);
  if (!trusted(ctx.instruction) || !encoded || operands.length !== 2) {
    return ctx.partial('x86-mov-control-debug-decoder-proof-required', ['registers','faults','other'], {
      metadata:{ family:'system', operation:'mov', systemRegisterMove:true, encodingValidated:false },
    });
  }

  const shape = expectedShape(encoded);
  const destination = ctx.operands[0];
  const source = ctx.operands[1];
  const privileged = ctx.operands[shape.privilegedIndex];
  const ordinary = ctx.operands[shape.privilegedIndex ^ 1];
  const actualKind = privilegedKind(privileged);
  if (actualKind !== shape.kind || privileged?.type !== 'register' || ordinary?.type !== 'register'
    || privilegedKind(ordinary) != null || Number(privileged.widthBits) !== 64 || Number(ordinary.widthBits) !== 64) {
    return ctx.partial('x86-mov-control-debug-operand-shape-unmodelled', ['registers','faults'], {
      metadata:{ family:'system', operation:'mov', systemRegisterMove:true, encodingValidated:true },
    });
  }

  const privilegedId = String(privileged.register.id).toLowerCase();
  if (actualKind === 'debug-register' && (privilegedId === 'dr4' || privilegedId === 'dr5')) {
    return ctx.partial('x86-debug-register-alias-state-unmodelled', ['registers','faults','other'], {
      possibleFaults:[
        privilegeFault(actualKind, privilegedId),
        debugGeneralDetectFault(),
        debugAliasUndefinedFault(privilegedId),
      ],
      metadata:{
        family:'system',
        operation:'mov',
        systemRegisterMove:true,
        registerClass:actualKind,
        privilegedRegister:privilegedId,
        encodingValidated:true,
        controlRegister:'cr4',
        controlField:'DE',
        aliasWhenClear:privilegedId === 'dr4' ? 'dr6' : 'dr7',
        faultWhenSet:'#UD',
        debugGeneralDetectPrecedesAccess:true,
      },
    });
  }

  const sourceValue = ctx.readRegister(source);
  if (!sourceValue) {
    return ctx.partial('x86-mov-control-debug-source-state-unmodelled', ['registers'], {
      metadata:{ family:'system', operation:'mov', systemRegisterMove:true },
    });
  }

  const sourceId = String(source.register.physicalId).toLowerCase();
  const destinationId = String(destination.register.physicalId).toLowerCase();
  const writesPrivileged = shape.privilegedIndex === 0;
  const reads = new Set([sourceId, EXECUTION_ENV]);
  const writes = new Set([destinationId]);
  const possibleFaults = [privilegeFault(actualKind, privilegedId), invalidRegisterFault(actualKind, privilegedId)];

  if (actualKind === 'control-register') {
    if (writesPrivileged) {
      reads.add(privilegedId);
      writes.add(CONTROL_DERIVED_STATE);
      possibleFaults.push(controlWriteFault(privilegedId));
    }
  } else {
    reads.add('dr7');
    writes.add('dr6');
    writes.add('dr7');
    writes.add(DEBUG_DERIVED_STATE);
    possibleFaults.push(debugGeneralDetectFault());
  }

  const [architecturalValue] = ctx.intrinsic(`x86.system.mov.${actualKind}`, [sourceValue], [64], {
    registersRead:[...reads].sort(),
    registersWritten:[...writes].sort(),
    memoryRead:{ scope:'none' },
    memoryWrite:{ scope:'none' },
    controlEffects:[],
    determinism:'input-dependent',
    symbolicDetail:'summary-only',
    metadata:{
      operation:'mov',
      systemRegisterMove:true,
      registerClass:actualKind,
      privilegedRegister:privilegedId,
      direction:writesPrivileged ? 'gp-to-system' : 'system-to-gp',
      exactArchitecturalSummary:true,
      environmentDependent:true,
      virtualization:'VMX/SVM intercept and architectural privilege/validity conditions are represented by the system summary and fault alternatives',
    },
  });

  if (!ctx.writeRegister(destination, architecturalValue)) {
    return ctx.partial('x86-mov-control-debug-destination-state-unmodelled', ['registers'], {
      metadata:{ family:'system', operation:'mov', systemRegisterMove:true },
    });
  }

  return ctx.finish({
    family:'system',
    possibleFaults,
    metadata:{
      operation:'mov',
      systemRegisterMove:true,
      registerClass:actualKind,
      privilegedRegister:privilegedId,
      direction:writesPrivileged ? 'gp-to-system' : 'system-to-gp',
      encodingValidated:true,
      physicalStateModeled:true,
    },
  });
}
