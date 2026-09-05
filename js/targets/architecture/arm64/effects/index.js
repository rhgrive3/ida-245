import { createMachineEffectBundle } from '../../../../semantics/effects/index.js';
import { decorateArm64BtiGuardedPageEffects } from './bti-guard-state.js';
import { liftArm64ControlEffects } from './control.js';
import { createArm64EffectContext, directTargetOf, immediateOf, instructionMnemonic } from './common.js';
import { liftArm64FlagEffects } from './flags.js';
import { liftArm64FpEffects } from './fp.js';
import { liftArm64IntegerEffects } from './integer.js';
import { liftArm64MemoryEffects } from './memory.js';
import { liftArm64SimdEffects } from './simd.js';
import { liftArm64SystemEffects } from './system.js';

export const ARM64_MACHINE_EFFECTS_SEMANTIC_VERSION = '7';

const ARM64_EFFECT_FAMILIES = Object.freeze([
  Object.freeze({ id:'flags', lift:liftArm64FlagEffects }),
  Object.freeze({ id:'control', lift:liftArm64ControlEffects }),
  Object.freeze({ id:'memory', lift:liftArm64MemoryEffects }),
  Object.freeze({ id:'simd', lift:liftArm64SimdEffects }),
  Object.freeze({ id:'fp', lift:liftArm64FpEffects }),
  Object.freeze({ id:'integer', lift:liftArm64IntegerEffects }),
  Object.freeze({ id:'system', lift:liftArm64SystemEffects }),
]);

const ARM64_ADD_SUB_IMMEDIATE_MNEMONICS = Object.freeze(new Set(['add','adds','sub','subs']));
const ARM64_ADD_SUB_FAMILY_MNEMONICS = Object.freeze(new Set([
  ...ARM64_ADD_SUB_IMMEDIATE_MNEMONICS,
  'adc','adcs','sbc','sbcs','neg','negs','ngc','ngcs',
]));
const ARM64_LOGICAL_IMMEDIATE_MNEMONICS = Object.freeze(new Set(['and','ands','orr','eor','tst']));
const ARM64_LOGICAL_REGISTER_ONLY_MNEMONICS = Object.freeze(new Set(['bic','bics','orn','eon']));
const ARM64_LITERAL_MEMORY_MNEMONICS = Object.freeze(new Set(['ldr','ldrsw','prfm']));
const ARM64_MULTIPLY_DIVIDE_MNEMONICS = Object.freeze(new Set([
  'mul','mneg','smull','umull','smulh','umulh','sdiv','udiv',
  'madd','msub','smaddl','smsubl','umaddl','umsubl','smnegl','umnegl',
]));
const ARM64_CONDITIONAL_TWO_SOURCE = Object.freeze(new Set(['csel','csinc','csinv','csneg']));
const ARM64_CONDITIONAL_ONE_SOURCE = Object.freeze(new Set(['cinc','cneg','cinv']));
const ARM64_UNARY_REGISTER_MNEMONICS = Object.freeze(new Set([
  'sxtb','sxth','sxtw','uxtb','uxth','uxtw','clz','rbit','rev','rev16','rev32','abs',
]));
const ARM64_SHIFT_MNEMONICS = Object.freeze(new Set(['lsl','lslv','lsr','lsrv','asr','asrv','ror','rorv']));
const ARM64_VARIABLE_SHIFT_MNEMONICS = Object.freeze(new Set(['lslv','lsrv','asrv','rorv']));
const ARM64_BITFIELD_MNEMONICS = Object.freeze(new Set(['ubfm','sbfm','bfm','ubfx','sbfx','ubfiz','sbfiz','bfxil','bfi','bfc']));

function validImm12WithOptionalLsl12(op) {
  if (op?.k !== 'imm') return true;
  if (op.extend != null) return false;
  const immediate = immediateOf(op);
  if (immediate == null || immediate < 0n || immediate > 0xfffn) return false;
  if (op.shift == null) return true;
  return typeof op.shift.op === 'string'
    && op.shift.op.toLowerCase() === 'lsl'
    && typeof op.shift.amount === 'number'
    && Number.isInteger(op.shift.amount)
    && op.shift.amount === 12;
}

function rotateRightElement(value, amount, widthBits) {
  const width = BigInt(widthBits);
  const shift = BigInt(amount % widthBits);
  const mask = (1n << width) - 1n;
  if (shift === 0n) return value & mask;
  return ((value >> shift) | (value << (width - shift))) & mask;
}

function replicateElement(value, elementBits, widthBits) {
  let result = 0n;
  for (let offset = 0; offset < widthBits; offset += elementBits) result |= value << BigInt(offset);
  return BigInt.asUintN(widthBits, result);
}

function buildLogicalImmediateMasks(widthBits) {
  const masks = new Set();
  for (let elementBits = 2; elementBits <= widthBits; elementBits *= 2) {
    for (let ones = 1; ones < elementBits; ones++) {
      const base = (1n << BigInt(ones)) - 1n;
      for (let rotation = 0; rotation < elementBits; rotation++) {
        masks.add(replicateElement(rotateRightElement(base, rotation, elementBits), elementBits, widthBits).toString());
      }
    }
  }
  return masks;
}

const LOGICAL_IMMEDIATE_MASKS = Object.freeze({
  32: buildLogicalImmediateMasks(32),
  64: buildLogicalImmediateMasks(64),
});

function logicalImmediateEncodable(op, widthBits) {
  if (op?.k !== 'imm' || (widthBits !== 32 && widthBits !== 64) || op.shift != null || op.extend != null) return false;
  const immediate = immediateOf(op);
  if (immediate == null) return false;
  return LOGICAL_IMMEDIATE_MASKS[widthBits].has(BigInt.asUintN(widthBits, immediate).toString());
}

function singleWideMoveEncodable(pattern, widthBits) {
  const value = BigInt.asUintN(widthBits, pattern);
  const widthMask = (1n << BigInt(widthBits)) - 1n;
  for (let shift = 0; shift < widthBits; shift += 16) {
    const laneMask = 0xffffn << BigInt(shift);
    if ((value & (widthMask ^ laneMask)) === 0n) return true;
    const inverted = (~value) & widthMask;
    if ((inverted & (widthMask ^ laneMask)) === 0n) return true;
  }
  return false;
}

function movImmediateEncodable(op, widthBits) {
  if (op?.k !== 'imm' || (widthBits !== 32 && widthBits !== 64) || op.shift != null || op.extend != null) return false;
  const immediate = immediateOf(op);
  if (immediate == null) return false;
  const pattern = BigInt.asUintN(widthBits, immediate);
  return singleWideMoveEncodable(pattern, widthBits) || LOGICAL_IMMEDIATE_MASKS[widthBits].has(pattern.toString());
}

function asBigIntOrNull(value) {
  try { return value == null ? null : BigInt(value); }
  catch { return null; }
}

function isGpOrZrRegister(operand) {
  return operand?.k === 'reg' && typeof operand.cls === 'string' && ['gp','zr'].includes(operand.cls.toLowerCase());
}

function isPlainGpSource(operand) {
  return isGpOrZrRegister(operand) && operand.shift == null && operand.extend == null;
}

function structuredRegisterWidth(operand) {
  const bits = operand?.bits;
  return typeof bits === 'number' && Number.isInteger(bits) && (bits === 32 || bits === 64) ? bits : 0;
}

function isPlainGpSourceOfWidth(operand, widthBits) {
  return isPlainGpSource(operand) && structuredRegisterWidth(operand) === widthBits;
}

function isGpSourceOfWidth(operand, widthBits) {
  return isGpOrZrRegister(operand) && structuredRegisterWidth(operand) === widthBits;
}

function isLogicalShiftedGpSource(operand, widthBits) {
  if (!isGpOrZrRegister(operand) || structuredRegisterWidth(operand) !== widthBits || operand.extend != null) return false;
  if (operand.shift == null) return true;
  if (typeof operand.shift.op !== 'string') return false;
  const kind = operand.shift.op.toLowerCase();
  const amount = operand.shift.amount ?? 0;
  return ['lsl','lsr','asr','ror'].includes(kind)
    && typeof amount === 'number' && Number.isInteger(amount) && amount >= 0 && amount < widthBits;
}

function addSubImmediateEncodingFailure(instruction) {
  const mnemonic = instructionMnemonic(instruction);
  if (!ARM64_ADD_SUB_FAMILY_MNEMONICS.has(mnemonic)) return null;
  const ops = Array.isArray(instruction?.ops) ? instruction.ops : [];
  if (!isGpOrZrRegister(ops[0])) return null;
  const alias = ['neg','negs','ngc','ngcs'].includes(mnemonic);
  const expectedOperandCount = alias ? 2 : 3;
  if (ops.length !== expectedOperandCount) return `arm64-${mnemonic}-operand-shape-unencodable`;
  const lhs = alias ? null : ops[1];
  const rhs = alias ? ops[1] : ops[2];
  if (rhs?.k === 'imm' && !ARM64_ADD_SUB_IMMEDIATE_MNEMONICS.has(mnemonic)) return `arm64-${mnemonic}-immediate-form-unencodable`;
  const widthBits = structuredRegisterWidth(ops[0]);
  if (['adc','adcs','sbc','sbcs'].includes(mnemonic)) {
    if (!isGpSourceOfWidth(lhs, widthBits) || !isGpSourceOfWidth(rhs, widthBits)) return `arm64-${mnemonic}-register-width-unencodable`;
    if (!isPlainGpSource(lhs) || !isPlainGpSource(rhs)) return `arm64-${mnemonic}-register-modifier-unencodable`;
  } else if (alias && !isGpSourceOfWidth(rhs, widthBits)) {
    return `arm64-${mnemonic}-register-width-unencodable`;
  } else if (['ngc','ngcs'].includes(mnemonic) && !isPlainGpSource(rhs)) {
    return `arm64-${mnemonic}-register-modifier-unencodable`;
  }
  if (lhs?.k === 'imm') return `arm64-${mnemonic}-lhs-immediate-unencodable`;
  if (rhs?.k === 'reg' && String(rhs.shift?.op || '').toLowerCase() === 'ror') return `arm64-${mnemonic}-ror-shift-unencodable`;
  if (rhs?.k !== 'imm') return null;
  if (!validImm12WithOptionalLsl12(rhs)) {
    const immediate = immediateOf(rhs);
    if (immediate == null || immediate < 0n || immediate > 0xfffn) return `arm64-${mnemonic}-immediate-out-of-range`;
    return `arm64-${mnemonic}-immediate-shift-unencodable`;
  }
  return null;
}

function flagEncodingFailure(instruction) {
  const mnemonic = instructionMnemonic(instruction);
  if (!['cmp','cmn','ccmp','ccmn'].includes(mnemonic)) return null;
  const ops = Array.isArray(instruction?.ops) ? instruction.ops : [];
  if (!isGpOrZrRegister(ops[0])) return null;
  const rhs = ops[1];
  if (rhs?.k !== 'imm') return null;
  if (mnemonic === 'cmp' || mnemonic === 'cmn') {
    if (!validImm12WithOptionalLsl12(rhs)) {
      const immediate = immediateOf(rhs);
      if (immediate == null || immediate < 0n || immediate > 0xfffn) return `arm64-${mnemonic}-immediate-out-of-range`;
      return `arm64-${mnemonic}-immediate-shift-unencodable`;
    }
    return null;
  }
  const immediate = immediateOf(rhs);
  if (immediate == null || immediate < 0n || immediate > 31n) return `arm64-${mnemonic}-immediate-out-of-range`;
  if (rhs.shift != null) return `arm64-${mnemonic}-immediate-shift-unencodable`;
  return null;
}

function logicalEncodingFailure(instruction) {
  const mnemonic = instructionMnemonic(instruction);
  const isImmediateCapable = ARM64_LOGICAL_IMMEDIATE_MNEMONICS.has(mnemonic);
  const isRegisterOnly = ARM64_LOGICAL_REGISTER_ONLY_MNEMONICS.has(mnemonic) || mnemonic === 'mvn';
  if (!isImmediateCapable && !isRegisterOnly) return null;
  const ops = Array.isArray(instruction?.ops) ? instruction.ops : [];
  if (!isGpOrZrRegister(ops[0])) {
    if (mnemonic === 'tst' && ops[0]?.k !== 'reg') return 'arm64-tst-lhs-register-required';
    return null;
  }
  const expectedOperandCount = mnemonic === 'mvn' || mnemonic === 'tst' ? 2 : 3;
  if (ops.length !== expectedOperandCount) {
    if (mnemonic === 'tst' && ops.length < expectedOperandCount) return 'arm64-tst-rhs-register-required';
    return `arm64-${mnemonic}-operand-shape-unencodable`;
  }
  const widthBits = structuredRegisterWidth(ops[0]);
  if (widthBits !== 32 && widthBits !== 64) return `arm64-${mnemonic}-width-unencodable`;

  if (mnemonic === 'mvn') {
    return isLogicalShiftedGpSource(ops[1], widthBits) ? null : 'arm64-mvn-source-register-required';
  }

  const lhs = mnemonic === 'tst' ? ops[0] : ops[1];
  const rhs = mnemonic === 'tst' ? ops[1] : ops[2];
  if (!isPlainGpSourceOfWidth(lhs, widthBits)) return `arm64-${mnemonic}-lhs-register-required`;

  if (rhs?.k === 'imm') {
    if (!isImmediateCapable || !logicalImmediateEncodable(rhs, widthBits)) return `arm64-${mnemonic}-logical-immediate-unencodable`;
    return null;
  }
  return isLogicalShiftedGpSource(rhs, widthBits) ? null : `arm64-${mnemonic}-rhs-register-required`;
}

function multiplyDivideEncodingFailure(instruction) {
  const mnemonic = instructionMnemonic(instruction);
  if (!ARM64_MULTIPLY_DIVIDE_MNEMONICS.has(mnemonic)) return null;
  const ops = Array.isArray(instruction?.ops) ? instruction.ops : [];
  if (!isGpOrZrRegister(ops[0])) return null;
  const expectedOperandCount = ['madd','msub','smaddl','smsubl','umaddl','umsubl'].includes(mnemonic) ? 4 : 3;
  if (ops.length !== expectedOperandCount) return `arm64-${mnemonic}-operand-shape-unencodable`;
  const destinationBits = structuredRegisterWidth(ops[0]);
  const required = [];
  if (['mul','mneg','sdiv','udiv','madd','msub'].includes(mnemonic)) {
    for (let index = 1; index < ops.length; index++) required.push([index, destinationBits]);
  } else if (['smull','umull','smnegl','umnegl'].includes(mnemonic)) {
    required.push([1,32],[2,32]);
    if (destinationBits !== 64) return `arm64-${mnemonic}-source-register-required`;
  } else if (['smulh','umulh'].includes(mnemonic)) {
    required.push([1,64],[2,64]);
    if (destinationBits !== 64) return `arm64-${mnemonic}-source-register-required`;
  } else {
    required.push([1,32],[2,32],[3,64]);
    if (destinationBits !== 64) return `arm64-${mnemonic}-source-register-required`;
  }
  for (const [index,bits] of required) {
    if (!isPlainGpSourceOfWidth(ops[index], bits)) return `arm64-${mnemonic}-source-register-required`;
  }
  return null;
}

function modifierFreeImmediate(op) {
  return op?.k === 'imm' && op.shift == null && op.extend == null;
}

function scalarImmediateModifierEncodingFailure(mnemonic, ops) {
  if (['lsl','lsr','asr','ror'].includes(mnemonic) && ops[2]?.k === 'imm' && !modifierFreeImmediate(ops[2])) {
    return `arm64-${mnemonic}-immediate-modifier-unencodable`;
  }
  if (mnemonic === 'extr' && !modifierFreeImmediate(ops[3])) return 'arm64-extr-immediate-modifier-unencodable';
  if (['ubfm','sbfm','bfm','ubfx','sbfx','ubfiz','sbfiz','bfxil','bfi'].includes(mnemonic)
    && (!modifierFreeImmediate(ops[2]) || !modifierFreeImmediate(ops[3]))) {
    return `arm64-${mnemonic}-immediate-modifier-unencodable`;
  }
  if (mnemonic === 'bfc' && (!modifierFreeImmediate(ops[1]) || !modifierFreeImmediate(ops[2]))) {
    return 'arm64-bfc-immediate-modifier-unencodable';
  }
  return null;
}

function bitfieldRegisterShapeEncodingFailure(mnemonic, ops) {
  if (!ARM64_BITFIELD_MNEMONICS.has(mnemonic)) return null;
  const destination = ops[0];
  const widthBits = Number(destination?.bits || 0);
  if (!isGpOrZrRegister(destination) || ![32,64].includes(widthBits)
    || destination.shift != null || destination.extend != null) {
    return `arm64-${mnemonic}-destination-register-unencodable`;
  }
  if (mnemonic === 'bfc') return null;
  return isPlainGpSourceOfWidth(ops[1], widthBits)
    ? null
    : `arm64-${mnemonic}-source-register-unencodable`;
}

function registerOnlyIntegerEncodingFailure(instruction) {
  const mnemonic = instructionMnemonic(instruction);
  const ops = Array.isArray(instruction?.ops) ? instruction.ops : [];
  const immediateFailure = scalarImmediateModifierEncodingFailure(mnemonic, ops);
  if (immediateFailure) return immediateFailure;
  const bitfieldFailure = bitfieldRegisterShapeEncodingFailure(mnemonic, ops);
  if (bitfieldFailure) return bitfieldFailure;
  if (!isGpOrZrRegister(ops[0])) return null;
  const widthBits = structuredRegisterWidth(ops[0]);
  const widthSensitiveIndices = mnemonic === 'extr' ? [1,2]
    : ARM64_CONDITIONAL_TWO_SOURCE.has(mnemonic) ? [1,2]
      : ARM64_CONDITIONAL_ONE_SOURCE.has(mnemonic) ? [1]
        : null;
  if (widthSensitiveIndices) {
    for (const index of widthSensitiveIndices) {
      if (!isPlainGpSourceOfWidth(ops[index], widthBits)) return `arm64-${mnemonic}-source-register-required`;
    }
  } else if (ARM64_UNARY_REGISTER_MNEMONICS.has(mnemonic)) {
    if (!isPlainGpSource(ops[1])) return `arm64-${mnemonic}-source-register-required`;
  }
  if (!ARM64_SHIFT_MNEMONICS.has(mnemonic)) return null;
  if (!isPlainGpSourceOfWidth(ops[1], widthBits)) return `arm64-${mnemonic}-source-register-required`;
  if (ARM64_VARIABLE_SHIFT_MNEMONICS.has(mnemonic) && !isPlainGpSourceOfWidth(ops[2], widthBits)) return `arm64-${mnemonic}-shift-register-required`;
  return null;
}

function moveEncodingFailure(instruction) {
  const mnemonic = instructionMnemonic(instruction);
  if (mnemonic !== 'mov') return null;
  const ops = Array.isArray(instruction?.ops) ? instruction.ops : [];
  if (!isGpOrZrRegister(ops[0])) return null;
  const source = ops[1];
  if (source?.k !== 'imm') return null;
  const widthBits = structuredRegisterWidth(ops[0]);
  return movImmediateEncodable(source, widthBits) ? null : 'arm64-mov-immediate-unencodable';
}

function prefetchOperandShapeEncodingFailure(instruction) {
  const mnemonic = instructionMnemonic(instruction);
  if (mnemonic !== 'prfm' && mnemonic !== 'prfum') return null;
  const ops = Array.isArray(instruction?.ops) ? instruction.ops : [];
  const hasPrintedSpecifier = ops[0]?.k === 'other';
  const addressIndex = hasPrintedSpecifier ? 1 : 0;
  if (ops.length !== addressIndex + 1) return `arm64-${mnemonic}-operand-shape-unencodable`;
  const address = ops[addressIndex];
  if (address?.k === 'mem' || address?.kind === 'memory') return null;
  if (mnemonic === 'prfm' && (address?.k === 'imm' || address?.kind === 'immediate')) return null;
  return `arm64-${mnemonic}-operand-shape-unencodable`;
}

function literalMemoryEncodingFailure(instruction) {
  const mnemonic = instructionMnemonic(instruction);
  if (!ARM64_LITERAL_MEMORY_MNEMONICS.has(mnemonic)) return null;
  const ops = Array.isArray(instruction?.ops) ? instruction.ops : [];
  if (ops.some((op) => op?.k === 'mem' || op?.kind === 'memory')) return null;
  const immediate = ops.find((op) => op?.k === 'imm' || op?.kind === 'immediate');
  const target = asBigIntOrNull(instruction?.pcRelTarget ?? instruction?.literalTarget ?? immediateOf(immediate));
  if (target == null) return null;
  const address = asBigIntOrNull(instruction?.address);
  if (address == null) return `arm64-${mnemonic}-literal-address-unavailable-for-encoding`;
  if ((target & 3n) !== 0n) return `arm64-${mnemonic}-literal-target-misaligned-encoding`;
  const displacement = target - address;
  if (displacement < -(1n << 20n) || displacement > (1n << 20n) - 4n) return `arm64-${mnemonic}-literal-target-out-of-range-encoding`;
  return null;
}

function unaryEncodingFailure(instruction) {
  const mnemonic = instructionMnemonic(instruction);
  if (mnemonic !== 'rev32') return null;
  const ops = Array.isArray(instruction?.ops) ? instruction.ops : [];
  if (!isGpOrZrRegister(ops[0])) return null;
  if (ops[0]?.k === 'reg' && ops[0].bits !== 64) return 'arm64-rev32-destination-width-unencodable';
  if (ops[1]?.k === 'reg' && ops[1].bits !== 64) return 'arm64-rev32-source-width-unencodable';
  return null;
}

const SIGNED_IMM21_MIN = -(1n << 20n);
const SIGNED_IMM21_MAX = (1n << 20n) - 1n;
const A64_PAGE_BYTES = 4096n;

function addressImmediateEncodingFailure(instruction) {
  const mnemonic = instructionMnemonic(instruction);
  if (mnemonic !== 'adr' && mnemonic !== 'adrp') return null;
  const ops = Array.isArray(instruction?.ops) ? instruction.ops : [];
  if (ops.length !== 2) return `arm64-${mnemonic}-operand-shape-unencodable`;
  const destination = ops[0];
  const targetOperand = ops[1];
  if (!isGpOrZrRegister(destination) || Number(destination.bits) !== 64
    || destination.shift != null || destination.extend != null) {
    return `arm64-${mnemonic}-destination-unencodable`;
  }
  if ((targetOperand?.k !== 'imm' && targetOperand?.k !== 'other')
    || targetOperand?.shift != null || targetOperand?.extend != null) {
    return `arm64-${mnemonic}-target-operand-unencodable`;
  }
  const address = asBigIntOrNull(instruction?.address);
  const target = asBigIntOrNull(instruction?.pcRelTarget);
  if (address == null || target == null) return `arm64-${mnemonic}-encoding-address-unavailable`;
  if (targetOperand?.k === 'imm' && immediateOf(targetOperand) !== target) {
    return `arm64-${mnemonic}-target-evidence-mismatch`;
  }
  if (mnemonic === 'adr') {
    const delta = BigInt.asIntN(64, target - address);
    return delta < SIGNED_IMM21_MIN || delta > SIGNED_IMM21_MAX
      ? 'arm64-adr-target-out-of-encoding-range'
      : null;
  }
  if ((target & (A64_PAGE_BYTES - 1n)) !== 0n) return 'arm64-adrp-target-not-page-aligned';
  const pageBase = address & ~(A64_PAGE_BYTES - 1n);
  const pageDelta = BigInt.asIntN(64, target - pageBase) / A64_PAGE_BYTES;
  return pageDelta < SIGNED_IMM21_MIN || pageDelta > SIGNED_IMM21_MAX
    ? 'arm64-adrp-target-out-of-encoding-range'
    : null;
}

function structuredEncodingFailure(instruction) {
  return addressImmediateEncodingFailure(instruction)
    || addSubImmediateEncodingFailure(instruction)
    || flagEncodingFailure(instruction)
    || logicalEncodingFailure(instruction)
    || multiplyDivideEncodingFailure(instruction)
    || registerOnlyIntegerEncodingFailure(instruction)
    || moveEncodingFailure(instruction)
    || prefetchOperandShapeEncodingFailure(instruction)
    || literalMemoryEncodingFailure(instruction)
    || unaryEncodingFailure(instruction);
}

function normalizedInstruction(decoded, context) {
  if (!decoded || typeof decoded !== 'object') throw new TypeError('arm64-decoded-instruction-required');
  const instructionId = decoded.instructionId ?? context?.instructionId;
  const origin = decoded.origin ?? context?.origin;
  const mode = decoded.mode ?? context?.mode;
  const mnemonic = instructionMnemonic(decoded);
  const operands = Array.isArray(decoded.ops) ? decoded.ops : Array.isArray(decoded.operands) ? decoded.operands : [];
  const adrImmediate = operands.length > 1 ? immediateOf(operands[1]) : null;
  const normalizedPcRelTarget = (mnemonic === 'adr' || mnemonic === 'adrp') && decoded.pcRelTarget == null
    ? (adrImmediate ?? directTargetOf(decoded))
    : decoded.pcRelTarget;
  if (instructionId == null && origin == null && mode == null && normalizedPcRelTarget === decoded.pcRelTarget) return decoded;
  return {
    ...decoded,
    ...(instructionId == null ? {} : { instructionId }),
    ...(origin == null ? {} : { origin }),
    ...(mode == null ? {} : { mode }),
    ...(normalizedPcRelTarget == null ? {} : { pcRelTarget: normalizedPcRelTarget }),
  };
}

function normalizedContext(context = {}) {
  const machineEffectsOptions = context.machineEffectsOptions ?? context.options ?? {};
  return { ...context, ...machineEffectsOptions, options: machineEffectsOptions, machineEffectsOptions };
}

const FP_ADVSIMD_ACCESS_CONTROLS = Object.freeze([
  'PSTATE.EL',
  'CPACR_EL1.FPEN',
  'CPTR_EL2.FPEN',
  'CPTR_EL2.TFP',
  'CPTR_EL3.TFP',
  'HCR_EL2.E2H',
  'HCR_EL2.TGE',
]);

function fpAdvSimdAccessUnknown() {
  return { state:'unknown', target:'environment-dependent-exception-level' };
}

function validFpAdvSimdBoolean(value) {
  return typeof value === 'boolean';
}

function validFpAdvSimdFpen(value) {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0 && value <= 3;
}

function resolveFpAdvSimdAccess(context) {
  const access = context?.arm64AccessControl;
  if (!access || typeof access !== 'object' || Array.isArray(access)) return fpAdvSimdAccessUnknown();
  const currentEL = access.currentEL;
  if (!Number.isInteger(currentEL) || currentEL < 0 || currentEL > 3) return fpAdvSimdAccessUnknown();

  if (!validFpAdvSimdBoolean(access.el3Implemented)) return fpAdvSimdAccessUnknown();
  if (access.el3Implemented) {
    if (!validFpAdvSimdBoolean(access.cptrEl3Tfp)) return fpAdvSimdAccessUnknown();
    if (access.cptrEl3Tfp) {
      return currentEL === 3
        ? { state:'disabled', target:'EL3' }
        : fpAdvSimdAccessUnknown();
    }
  }
  if (currentEL === 3) return { state:'allowed' };

  if (!validFpAdvSimdBoolean(access.el2Enabled)) return fpAdvSimdAccessUnknown();
  if (currentEL === 2 && !access.el2Enabled) return fpAdvSimdAccessUnknown();
  const el2InHost = access.el2Enabled ? access.el2InHost : false;
  if (access.el2Enabled && !validFpAdvSimdBoolean(el2InHost)) return fpAdvSimdAccessUnknown();

  if (currentEL === 0) {
    if (!validFpAdvSimdBoolean(access.el0InHost)) return fpAdvSimdAccessUnknown();
    if (access.el0InHost && (!access.el2Enabled || !el2InHost)) return fpAdvSimdAccessUnknown();
    if (!access.el0InHost) {
      if (!validFpAdvSimdFpen(access.cpacrEl1Fpen)) return fpAdvSimdAccessUnknown();
      if (access.cpacrEl1Fpen !== 3) {
        const target = access.el2Enabled && access.hcrEl2Tge === true
          ? 'EL2'
          : access.hcrEl2Tge === false || !access.el2Enabled
            ? 'EL1'
            : 'environment-dependent-exception-level';
        return { state:'disabled', target };
      }
    } else {
      if (!validFpAdvSimdFpen(access.cptrEl2Fpen)) return fpAdvSimdAccessUnknown();
      if (access.cptrEl2Fpen !== 3) return { state:'disabled', target:'EL2' };
    }
  } else if (currentEL === 1) {
    if (!validFpAdvSimdFpen(access.cpacrEl1Fpen)) return fpAdvSimdAccessUnknown();
    if ((access.cpacrEl1Fpen & 1) === 0) return { state:'disabled', target:'EL1' };
  }

  if (access.el2Enabled) {
    if (el2InHost) {
      if (!validFpAdvSimdFpen(access.cptrEl2Fpen)) return fpAdvSimdAccessUnknown();
      if ((access.cptrEl2Fpen & 1) === 0) return { state:'disabled', target:'EL2' };
    } else {
      if (!validFpAdvSimdBoolean(access.cptrEl2Tfp)) return fpAdvSimdAccessUnknown();
      if (access.cptrEl2Tfp) return { state:'disabled', target:'EL2' };
    }
  }
  return { state:'allowed' };
}

function withFpAdvSimdAccessTrap(bundle, context) {
  if (!bundle || !['exact','exact-with-intrinsic'].includes(bundle.completeness)) return bundle;
  const access = resolveFpAdvSimdAccess(context);
  const possibleFaults = bundle.possibleFaults.filter((fault) => fault.kind !== 'fp-advsimd-access-trap');
  if (access.state === 'allowed') {
    if (possibleFaults.length === bundle.possibleFaults.length) return bundle;
    return createMachineEffectBundle({
      instructionId:bundle.instructionId,
      architectureId:bundle.architectureId,
      mode:bundle.mode,
      operations:bundle.operations,
      controlEffect:bundle.controlEffect,
      possibleFaults,
      origin:bundle.origin,
      completeness:bundle.completeness,
      ...(bundle.unknownEffects == null ? {} : { unknownEffects:bundle.unknownEffects }),
      ...(bundle.statePreservation == null ? {} : { statePreservation:bundle.statePreservation }),
      ...(bundle.metadata == null ? {} : { metadata:bundle.metadata }),
    }, context?.machineEffectsOptions || {});
  }
  const accessFault = access.state === 'disabled'
    ? {
      kind:'fp-advsimd-access-trap',
      detail:{ target:access.target, accessState:'disabled', check:'CheckFPAdvSIMDEnabled' },
    }
    : {
      kind:'fp-advsimd-access-trap',
      condition:{
        kind:'architectural-access-check',
        architecture:'arm64',
        access:'fp-advsimd',
        check:'CheckFPAdvSIMDEnabled',
        controls:FP_ADVSIMD_ACCESS_CONTROLS,
      },
      detail:{ target:'environment-dependent-exception-level', accessState:'unknown' },
    };
  return createMachineEffectBundle({
    instructionId:bundle.instructionId,
    architectureId:bundle.architectureId,
    mode:bundle.mode,
    operations:bundle.operations,
    controlEffect:bundle.controlEffect,
    possibleFaults:[...possibleFaults, accessFault],
    origin:bundle.origin,
    completeness:bundle.completeness,
    ...(bundle.unknownEffects == null ? {} : { unknownEffects:bundle.unknownEffects }),
    ...(bundle.statePreservation == null ? {} : { statePreservation:bundle.statePreservation }),
    ...(bundle.metadata == null ? {} : { metadata:bundle.metadata }),
  }, context?.machineEffectsOptions || {});
}

export function liftArm64MachineEffects(decoded, context = {}) {
  const instruction = normalizedInstruction(decoded, context);
  const familyContext = normalizedContext(context);
  const encodingFailure = structuredEncodingFailure(instruction);
  if (encodingFailure) {
    const partial = createArm64EffectContext(instruction, familyContext).partial(encodingFailure, ['registers','flags','memory','other']);
    return decorateArm64BtiGuardedPageEffects(instruction, partial, familyContext);
  }
  for (const family of ARM64_EFFECT_FAMILIES) {
    let result = family.lift(instruction, familyContext);
    if (result == null) continue;
    if (family.id === 'fp' || family.id === 'simd') result = withFpAdvSimdAccessTrap(result, familyContext);
    return decorateArm64BtiGuardedPageEffects(instruction, result, familyContext);
  }
  return null;
}

export function arm64MachineEffectFamilies() {
  return Object.freeze(ARM64_EFFECT_FAMILIES.map(({ id }) => id));
}

export const liftExact = liftArm64MachineEffects;