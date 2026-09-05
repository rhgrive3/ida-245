export {
  ARM64_INTEGER_EFFECT_MNEMONICS,
  decodeArm64BitMasks,
  evaluateArm64Bitfield,
} from './integer-core.js';
import {
  ARM64_INTEGER_EFFECT_MNEMONICS as INTEGER_MNEMONICS,
  liftArm64IntegerEffects as liftArm64IntegerEffectsCore,
} from './integer-core.js';
import { createArm64EffectContext, immediateOf } from './common.js';
import { snapshotArm64ImmediateOperands } from './immediate-authority.js';

const ADD_SUB_BASE = new Set(['add','adds','sub','subs']);
const ADD_SUB_ALL = new Set(['add','adds','sub','subs','adc','adcs','sbc','sbcs','neg','negs','ngc','ngcs']);
const LOGICAL_NO_SP = new Set(['and','ands','orr','eor','bic','bics','orn','eon','mvn']);
const LOGICAL_IMMEDIATE_SP_DEST = new Set(['and','orr','eor']);
const EXTEND_KINDS = new Set(['uxtb','uxth','uxtw','uxtx','sxtb','sxth','sxtw','sxtx']);
const CONDITIONAL_SELECT_MNEMONICS = new Set(['csel','csinc','csinv','csneg','cset','csetm','cinc','cneg','cinv']);
const MOVE_WIDE_MNEMONICS = new Set(['movz','movn','movk']);
const BITFIELD_MNEMONICS = new Set(['ubfm','sbfm','bfm','ubfx','sbfx','ubfiz','sbfiz','bfxil','bfi','bfc']);

function expectedOperandCount(mnemonic) {
  if (['lsl','lslv','lsr','lsrv','asr','asrv','ror','rorv'].includes(mnemonic)) return 3;
  if (['sxtb','sxth','sxtw','uxtb','uxth','uxtw','clz','rbit','rev','rev16','rev32','abs'].includes(mnemonic)) return 2;
  if (['csel','csinc','csinv','csneg'].includes(mnemonic)) return 4;
  if (['cset','csetm'].includes(mnemonic)) return 2;
  if (['cinc','cneg','cinv'].includes(mnemonic)) return 3;
  if (MOVE_WIDE_MNEMONICS.has(mnemonic)) return 2;
  if (mnemonic === 'extr') return 4;
  if (['ubfx','sbfx','ubfiz','sbfiz','bfxil','bfi','ubfm','sbfm','bfm'].includes(mnemonic)) return 4;
  if (mnemonic === 'bfc') return 3;
  return null;
}

function regClass(op) { return op?.k === 'reg' && typeof op.cls === 'string' ? op.cls.toLowerCase() : ''; }
function regBits(op) {
  const bits = op?.bits;
  return typeof bits === 'number' && Number.isInteger(bits) && (bits === 32 || bits === 64) ? bits : 0;
}
function isGpOrZr(op) { return op?.k === 'reg' && ['gp','zr'].includes(regClass(op)); }
function isGpOrSp(op) { return op?.k === 'reg' && ['gp','sp'].includes(regClass(op)); }

function validImm12(op) {
  if (op?.k !== 'imm' || op.extend != null) return false;
  let value;
  try { value = BigInt(op.value); } catch { return false; }
  if (value < 0n || value > 0xfffn) return false;
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
  let immediate;
  try { immediate = BigInt(op.value); } catch { return false; }
  return LOGICAL_IMMEDIATE_MASKS[widthBits].has(BigInt.asUintN(widthBits, immediate).toString());
}

function validExtendedSource(rhs, targetBits) {
  if (!isGpOrZr(rhs)) return false;
  const modifier = rhs.shift || rhs.extend || null;
  if (modifier == null) return regBits(rhs) === targetBits;
  if (typeof modifier.op !== 'string') return false;
  const kind = modifier.op.toLowerCase();
  const amount = modifier.amount ?? 0;
  if (typeof amount !== 'number' || !Number.isInteger(amount) || amount < 0 || amount > 4) return false;
  if (kind === 'lsl') return regBits(rhs) === targetBits;
  if (!EXTEND_KINDS.has(kind)) return false;
  if (targetBits === 32) return regBits(rhs) === 32;
  return kind.endsWith('x') ? regBits(rhs) === 64 : regBits(rhs) === 32;
}

function validShiftedSource(rhs, targetBits) {
  if (!isGpOrZr(rhs) || regBits(rhs) !== targetBits) return false;
  const modifier = rhs.shift || rhs.extend || null;
  if (modifier == null) return true;
  if (typeof modifier.op !== 'string') return false;
  const kind = modifier.op.toLowerCase();
  const amount = modifier.amount ?? 0;
  return ['lsl','lsr','asr'].includes(kind)
    && typeof amount === 'number' && Number.isInteger(amount) && amount >= 0 && amount < targetBits;
}

function validAddSubRegister31Encoding(mnemonic, ops) {
  if (!ADD_SUB_ALL.has(mnemonic)) return true;
  const containsSp = ops.some((op) => regClass(op) === 'sp');
  if (!ADD_SUB_BASE.has(mnemonic)) return !containsSp;
  if (ops.length !== 3) return false;

  const dst = ops[0], lhs = ops[1], rhs = ops[2];
  const bits = regBits(dst);
  if (bits !== 32 && bits !== 64) return false;
  if (regBits(lhs) !== bits) return false;

  if (rhs?.k === 'imm') {
    const dstOk = mnemonic === 'add' || mnemonic === 'sub' ? isGpOrSp(dst) : isGpOrZr(dst);
    return dstOk && isGpOrSp(lhs) && validImm12(rhs);
  }

  if (rhs?.k !== 'reg') return false;
  const dstClass = regClass(dst);
  const lhsClass = regClass(lhs);
  const modifier = rhs.shift || rhs.extend || null;
  const explicitExtend = typeof modifier?.op === 'string' && EXTEND_KINDS.has(modifier.op.toLowerCase());
  const usesExtendedEncoding = dstClass === 'sp' || lhsClass === 'sp' || explicitExtend;

  if (usesExtendedEncoding) {
    const dstOk = mnemonic === 'add' || mnemonic === 'sub' ? isGpOrSp(dst) : isGpOrZr(dst);
    if (!dstOk || !isGpOrSp(lhs)) return false;
    return validExtendedSource(rhs, bits);
  }

  if (!isGpOrZr(dst) || !isGpOrZr(lhs)) return false;
  return validShiftedSource(rhs, bits);
}

function validLogicalRegisterClass(mnemonic, ops) {
  if (!LOGICAL_NO_SP.has(mnemonic)) return true;
  if (!ops.some((op) => regClass(op) === 'sp')) return true;
  if (!LOGICAL_IMMEDIATE_SP_DEST.has(mnemonic) || ops.length !== 3 || ops[2]?.k !== 'imm') return false;
  const dst = ops[0], lhs = ops[1], rhs = ops[2];
  const bits = regBits(dst);
  return regClass(dst) === 'sp'
    && (bits === 32 || bits === 64)
    && isGpOrZr(lhs)
    && regBits(lhs) === bits
    && lhs.shift == null
    && lhs.extend == null
    && logicalImmediateEncodable(rhs, bits);
}

function validMovEncoding(mnemonic, ops) {
  if (mnemonic !== 'mov') return true;
  if (ops.length !== 2) return false;
  const dst = ops[0], src = ops[1];
  const dstClass = regClass(dst);
  if (!['gp','zr','sp'].includes(dstClass)) return true;
  const bits = regBits(dst);
  if (bits !== 32 && bits !== 64) return false;
  if (dst.shift != null || dst.extend != null) return false;
  if (src?.k === 'imm') return dstClass !== 'sp' && src.shift == null && src.extend == null;
  const srcClass = regClass(src);
  if (!['gp','zr','sp'].includes(srcClass) || regBits(src) !== bits || src.shift != null || src.extend != null) return false;
  const spInvolved = dstClass === 'sp' || srcClass === 'sp';
  if (spInvolved && (dstClass === 'zr' || srcClass === 'zr')) return false;
  return true;
}

function validMoveWideEncoding(mnemonic, ops) {
  if (!MOVE_WIDE_MNEMONICS.has(mnemonic)) return true;
  if (ops.length !== 2) return false;
  const dst = ops[0], src = ops[1];
  const bits = regBits(dst);
  if (!isGpOrZr(dst) || (bits !== 32 && bits !== 64) || dst.shift != null || dst.extend != null) return false;
  if (src?.k !== 'imm' || src.value == null || src.extend != null) return false;
  let immediate;
  try { immediate = BigInt(src.value); } catch { return false; }
  if (immediate < 0n || immediate > 0xffffn) return false;
  if (src.shift == null) return true;
  if (typeof src.shift.op !== 'string' || src.shift.op.toLowerCase() !== 'lsl') return false;
  const amount = src.shift.amount;
  if (typeof amount !== 'number' || !Number.isInteger(amount)) return false;
  return bits === 32 ? amount === 0 || amount === 16 : [0,16,32,48].includes(amount);
}

function validRegisterOnlyClass(expected, ops) {
  if (expected == null) return true;
  return !ops.some((op) => regClass(op) === 'sp');
}

function validConditionalOperand(mnemonic, ops) {
  if (!CONDITIONAL_SELECT_MNEMONICS.has(mnemonic)) return true;
  const condition = ops[ops.length - 1];
  return condition?.k === 'cond'
    && condition.shift == null
    && condition.extend == null;
}

function validAddressEncoding(instruction, ops) {
  if (typeof instruction?.mnemonic !== 'string') return null;
  const mnemonic = instruction.mnemonic.toLowerCase();
  if (mnemonic !== 'adr' && mnemonic !== 'adrp') return true;
  if (ops.length !== 2) return false;
  const destination = ops[0];
  const targetOperand = ops[1];
  if (!isGpOrZr(destination) || regBits(destination) !== 64
    || destination.shift != null || destination.extend != null) return false;
  if ((targetOperand?.k !== 'imm' && targetOperand?.k !== 'other')
    || targetOperand?.shift != null || targetOperand?.extend != null) return false;
  const rawAddress = instruction?.address;
  const rawTarget = instruction?.pcRelTarget ?? immediateOf(targetOperand);
  if (rawAddress == null || rawTarget == null) return false;
  let address, target;
  try { address = BigInt(rawAddress); } catch { return false; }
  try { target = BigInt(rawTarget); } catch { return false; }
  if (targetOperand?.k === 'imm' && immediateOf(targetOperand) !== target) return false;
  if (mnemonic === 'adr') {
    const delta = BigInt.asIntN(64, target - address);
    return delta >= -(1n << 20n) && delta <= (1n << 20n) - 1n;
  }
  if ((target & 0xfffn) !== 0n) return false;
  const pageBase = address & ~0xfffn;
  const pageDelta = BigInt.asIntN(64, target - pageBase) / 4096n;
  return pageDelta >= -(1n << 20n) && pageDelta <= (1n << 20n) - 1n;
}

function validBitfieldRegisterShape(mnemonic, ops) {
  if (!BITFIELD_MNEMONICS.has(mnemonic)) return true;
  const destination = ops[0];
  const bits = regBits(destination);
  if (!isGpOrZr(destination) || ![32,64].includes(bits)
    || destination.shift != null || destination.extend != null) return false;
  if (mnemonic === 'bfc') return true;
  const source = ops[1];
  return isGpOrZr(source) && regBits(source) === bits
    && source.shift == null && source.extend == null;
}

function modifierFreeImmediate(op) {
  return op?.k === 'imm' && op.shift == null && op.extend == null;
}

function hasNonCanonicalImmediateValue(ops) {
  return ops.some((op) => op?.k === 'imm' && op.value != null && typeof op.value !== 'bigint');
}

function validScalarImmediateModifiers(mnemonic, ops) {
  if (['lsl','lsr','asr','ror'].includes(mnemonic) && ops[2]?.k === 'imm') return modifierFreeImmediate(ops[2]);
  if (mnemonic === 'extr') return modifierFreeImmediate(ops[3]);
  if (['ubfm','sbfm','bfm','ubfx','sbfx','ubfiz','sbfiz','bfxil','bfi'].includes(mnemonic)) {
    return modifierFreeImmediate(ops[2]) && modifierFreeImmediate(ops[3]);
  }
  if (mnemonic === 'bfc') return modifierFreeImmediate(ops[1]) && modifierFreeImmediate(ops[2]);
  return true;
}

export function liftArm64IntegerEffects(instruction, options = {}) {
  if (typeof instruction?.mnemonic !== 'string') return null;
  const mnemonic = instruction.mnemonic.toLowerCase();
  const rawOps = Array.isArray(instruction?.ops) ? instruction.ops : [];
  const snapshot = INTEGER_MNEMONICS.has(mnemonic)
    ? snapshotArm64ImmediateOperands(instruction, rawOps)
    : Object.freeze({ instruction, ops:rawOps });
  if (!snapshot) {
    return createArm64EffectContext(instruction, options).partial(
      `arm64-${mnemonic}-immediate-value-unencodable`, ['registers','flags','other']);
  }
  const stableInstruction = snapshot.instruction;
  const ops = snapshot.ops;
  const expected = expectedOperandCount(mnemonic);
  if (expected != null && ops.length !== expected) {
    return liftArm64IntegerEffectsCore({ ...stableInstruction, ops: [] }, options);
  }
  if (INTEGER_MNEMONICS.has(mnemonic)
    && mnemonic !== 'adr' && mnemonic !== 'adrp'
    && hasNonCanonicalImmediateValue(ops)) {
    return createArm64EffectContext(stableInstruction, options).partial(
      `arm64-${mnemonic}-immediate-value-unencodable`, ['registers','flags','other']);
  }
  if (!validAddressEncoding(stableInstruction, ops)) {
    return createArm64EffectContext(stableInstruction, options).partial(
      `arm64-${mnemonic}-address-operand-unencodable`, ['registers','other']);
  }
  if (!validMoveWideEncoding(mnemonic, ops)) {
    return createArm64EffectContext(stableInstruction, options).partial(
      `arm64-${mnemonic}-move-wide-operand-shape-unencodable`, ['registers','other']);
  }
  if (!validRegisterOnlyClass(expected, ops)) {
    return liftArm64IntegerEffectsCore({ ...stableInstruction, ops: [] }, options);
  }
  if (!validConditionalOperand(mnemonic, ops)) {
    return createArm64EffectContext(stableInstruction, options).partial(
      `arm64-${mnemonic}-condition-operand-unencodable`, ['registers','flags','other']);
  }
  if (!validBitfieldRegisterShape(mnemonic, ops)) {
    return createArm64EffectContext(stableInstruction, options).partial(
      `arm64-${mnemonic}-bitfield-register-shape-unencodable`, ['registers','other']);
  }
  if (!validScalarImmediateModifiers(mnemonic, ops)) {
    return createArm64EffectContext(stableInstruction, options).partial(
      `arm64-${mnemonic}-immediate-modifier-unencodable`, ['registers','other']);
  }
  if (!validMovEncoding(mnemonic, ops)) {
    return createArm64EffectContext(stableInstruction, options).partial(
      'arm64-mov-operand-shape-unencodable', ['registers','other']);
  }
  if (!validAddSubRegister31Encoding(mnemonic, ops)) {
    return createArm64EffectContext(stableInstruction, options).partial(
      `arm64-${mnemonic}-register31-unencodable`, ['registers','flags','other']);
  }
  if (!validLogicalRegisterClass(mnemonic, ops)) {
    return liftArm64IntegerEffectsCore({ ...stableInstruction, ops: [] }, options);
  }
  return liftArm64IntegerEffectsCore(stableInstruction, options);
}
