export {
  ARM64_FP_EFFECT_MNEMONICS,
  decodeArm64FpImmediate,
  arm64FpImmediateBitPattern,
} from './fp-core.js';
import { liftArm64FpEffects as liftArm64FpEffectsCore } from './fp-core.js';

const FP_ENV_INTRINSICS = new Set([
  'fadd','fsub','fmul','fdiv','fsqrt','fmadd','fmsub','fnmadd','fnmsub',
  'fmax','fmin','fmaxnm','fminnm','frecpe','frecps','frsqrte','frsqrts',
  'fcvt','scvtf','ucvtf',
  'fcvtas','fcvtau','fcvtms','fcvtmu','fcvtns','fcvtnu','fcvtps','fcvtpu','fcvtzs','fcvtzu',
  'frinta','frintm','frintn','frintp','frintx','frinti','frintz',
]);
const FP_TERNARY = new Set(['fmadd','fmsub','fnmadd','fnmsub']);
const FP_BINARY = new Set(['fadd','fsub','fmul','fdiv','fmax','fmin','fmaxnm','fminnm','frecps','frsqrts']);
const FP_FINITE_SHAPE = new Set([
  ...FP_ENV_INTRINSICS,
  'fmov','fabs','fneg','fcsel','fcmp','fcmpe','fccmp','fccmpe',
]);
const FP_CONDITIONS = new Set(['eq','ne','cs','hs','cc','lo','mi','pl','vs','vc','hi','ls','ge','lt','gt','le','al','nv']);
const FP_FIXED_POINT = new Set(['scvtf','ucvtf','fcvtzs','fcvtzu']);

function operandsOf(instruction) {
  if (Array.isArray(instruction?.ops)) return instruction.ops;
  if (Array.isArray(instruction?.parsed)) return instruction.parsed;
  if (Array.isArray(instruction?.operandsParsed)) return instruction.operandsParsed;
  return [];
}

function invalidStructuredRegisterWidth(op) {
  return op?.k === 'reg'
    && (typeof op.bits !== 'number' || !Number.isSafeInteger(op.bits) || op.bits <= 0);
}

function invalidStructuredFpImmediate(op) {
  if (op?.k !== 'imm') return false;
  if (op.float != null && (typeof op.float !== 'number' || !Number.isFinite(op.float))) return true;
  return op.bitPattern != null && typeof op.bitPattern !== 'bigint';
}

function invalidConditionalEvidence(mnemonic, ops) {
  if (!['fcsel','fccmp','fccmpe'].includes(mnemonic)) return false;
  const conditions = ops.filter((op) => op?.k === 'cond');
  return conditions.length !== 1
    || typeof conditions[0].text !== 'string'
    || !FP_CONDITIONS.has(conditions[0].text.trim().toLowerCase());
}

function normalizeConditionalEvidence(mnemonic, ops) {
  if (!['fcsel','fccmp','fccmpe'].includes(mnemonic)) return ops;
  return ops.map((op) => op?.k === 'cond' && typeof op.text === 'string'
    ? { ...op, text: op.text.trim().toLowerCase() }
    : op);
}

function fixedPointScaleWidth(mnemonic, ops) {
  const register = mnemonic === 'scvtf' || mnemonic === 'ucvtf' ? ops[1] : ops[0];
  if (register?.k !== 'reg'
      || !['gp','zr'].includes(register.cls)
      || typeof register.bits !== 'number'
      || !Number.isSafeInteger(register.bits)
      || ![32,64].includes(register.bits)) return null;
  return register.bits;
}

function invalidIntegerImmediateEvidence(mnemonic, ops) {
  if (mnemonic === 'fccmp' || mnemonic === 'fccmpe') {
    const immediate = ops[2];
    return immediate?.k !== 'imm'
      || typeof immediate.value !== 'bigint'
      || immediate.value < 0n
      || immediate.value > 15n;
  }
  if (FP_FIXED_POINT.has(mnemonic) && ops.length === 3 && ops[2]?.k === 'imm') {
    const value = ops[2].value;
    const scaleWidth = fixedPointScaleWidth(mnemonic, ops);
    return typeof value !== 'bigint'
      || scaleWidth == null
      || value < 1n
      || value > BigInt(scaleWidth);
  }
  return false;
}

function invalidFiniteShape(mnemonic, ops) {
  if (!FP_FINITE_SHAPE.has(mnemonic)) return false;
  if (ops.some((op) => op?.shift != null || op?.extend != null)) return true;
  if (ops.some(invalidStructuredRegisterWidth)) return true;
  if (ops.some(invalidStructuredFpImmediate)) return true;
  if (invalidConditionalEvidence(mnemonic, ops)) return true;
  if (invalidIntegerImmediateEvidence(mnemonic, ops)) return true;
  if (ops.some((op) => op?.k === 'reg' && (!Number.isInteger(op.num) || op.num < 0 || op.num >= 32))) return true;
  if (ops.some((op) => op?.k === 'reg' && op.cls === 'zr' && op.num !== 31)) return true;
  if (['fmov','fabs','fneg'].includes(mnemonic)) return ops.length !== 2;
  if (mnemonic === 'fcsel') return ops.length !== 4;
  if (['fcmp','fcmpe'].includes(mnemonic)) return ops.length !== 2;
  if (['fccmp','fccmpe'].includes(mnemonic)) return ops.length !== 4;
  if (!FP_ENV_INTRINSICS.has(mnemonic)) return false;
  const expectedSources = FP_TERNARY.has(mnemonic) ? 3 : FP_BINARY.has(mnemonic) ? 2 : 1;
  const ordinary = ops.length === expectedSources + 1
    && ops.slice(1).every((op) => op?.k === 'reg' || op?.k === 'imm');
  const fixedPoint = FP_FIXED_POINT.has(mnemonic)
    && ops.length === 3 && ops[1]?.k === 'reg' && ops[2]?.k === 'imm';
  return !ordinary && !fixedPoint;
}

export function liftArm64FpEffects(instruction, context = {}) {
  if (typeof instruction?.mnemonic !== 'string') return null;
  const mnemonic = instruction.mnemonic.trim().toLowerCase();
  const ops = operandsOf(instruction);
  if (invalidFiniteShape(mnemonic, ops)) {
    return liftArm64FpEffectsCore({ ...instruction, ops: [] }, context);
  }
  const normalizedOps = normalizeConditionalEvidence(mnemonic, ops);
  return liftArm64FpEffectsCore(normalizedOps === ops ? instruction : { ...instruction, ops: normalizedOps }, context);
}

export const arm64FpMachineEffects = liftArm64FpEffects;