export {
  ARM64_FLAG_EFFECT_MNEMONICS,
  evaluateArm64AddSubFlags,
  evaluateArm64Condition,
  emitArm64AddSub,
  emitArm64LogicalFlags,
  writeArm64NZCV,
  emitArm64Condition,
} from './flags-core.js';
import { createArm64EffectContext } from './common.js';
import {
  ARM64_FLAG_EFFECT_MNEMONICS as FLAG_MNEMONICS,
  liftArm64FlagEffects as liftArm64FlagEffectsCore,
} from './flags-core.js';
import { snapshotArm64ImmediateOperands } from './immediate-authority.js';

const STRICT_REGISTER_LHS = new Set(['cmp','cmn','ccmp','ccmn']);
const SP_LHS_MNEMONICS = new Set(['cmp','cmn']);
const STRICT_IMMEDIATE_VALUE_MNEMONICS = new Set(['cmp','cmn','tst']);
const EXTEND_KINDS = new Set(['uxtb','uxth','uxtw','uxtx','sxtb','sxth','sxtw','sxtx']);

function registerClass(op) {
  return op?.k === 'reg' && typeof op.cls === 'string' ? op.cls.toLowerCase() : '';
}

function registerWidth(op) {
  const bits = op?.bits;
  return typeof bits === 'number' && Number.isInteger(bits) && (bits === 32 || bits === 64) ? bits : 0;
}

function validRegisterLhs(mnemonic, op) {
  const cls = registerClass(op);
  if (cls === 'gp' || cls === 'zr') return true;
  // ADD/SUB aliases CMP/CMN have architectural forms whose Rn=31 is SP
  // (notably immediate/extended-register encodings). Conditional compares do not.
  return cls === 'sp' && SP_LHS_MNEMONICS.has(mnemonic);
}

function validSpImmediateRhs(op) {
  if (op?.k !== 'imm') return true;
  if (op.extend != null) return false;
  let immediate;
  try { immediate = BigInt(op.value); } catch { return false; }
  if (immediate < 0n || immediate > 0xfffn) return false;
  if (op.shift == null) return true;
  return String(op.shift.op || '').toLowerCase() === 'lsl' && Number(op.shift.amount) === 12;
}

function validRegisterRhs(mnemonic, lhs, rhs) {
  if (rhs?.k !== 'reg') return true;
  const lhsBits = registerWidth(lhs);
  const rhsBits = registerWidth(rhs);
  if (![32,64].includes(lhsBits) || !['gp','zr'].includes(registerClass(rhs))) return false;
  const modifier = rhs.shift || rhs.extend || null;

  // Conditional compare has only the plain Wn/Wm or Xn/Xm register form.
  if (mnemonic === 'ccmp' || mnemonic === 'ccmn') return modifier == null && rhsBits === lhsBits;

  if (modifier == null) return rhsBits === lhsBits;
  const kind = String(modifier.op || '').toLowerCase();
  const amount = Number(modifier.amount ?? 0);
  if (!Number.isInteger(amount) || amount < 0) return false;
  const lhsClass = registerClass(lhs);

  // SUBS/ADDS shifted-register encodings allow LSL/LSR/ASR only. When Rn is
  // SP, assembler LSL is the preferred spelling of the extended-register UXTX
  // (or UXTW) option and its imm3 range is 0..4.
  if (kind === 'lsl' || kind === 'lsr' || kind === 'asr') {
    if (lhsClass === 'sp') return kind === 'lsl' && rhsBits === lhsBits && amount <= 4;
    return rhsBits === lhsBits && amount < lhsBits;
  }
  if (kind === 'ror') return false;

  if (!EXTEND_KINDS.has(kind) || amount > 4 || lhsClass === 'zr') return false;
  if (lhsBits === 32) return rhsBits === 32;
  return kind.endsWith('x') ? rhsBits === 64 : rhsBits === 32;
}

function validTstRegisterClass(ops) {
  return !ops.some((op) => op?.k === 'reg' && registerClass(op) === 'sp');
}

function hasNonCanonicalImmediateValue(ops) {
  return ops.some((op) => op?.k === 'imm' && op.value != null && typeof op.value !== 'bigint');
}

function validConditionalCompareCondition(op) {
  return op?.k === 'cond' && op.shift == null && op.extend == null;
}

function validConditionalCompareImmediates(ops) {
  const comparison = ops[1];
  const fallback = ops[2];
  if (comparison?.k === 'imm' && (comparison.shift != null || comparison.extend != null)) return false;
  if (fallback?.k === 'imm' && (fallback.shift != null || fallback.extend != null)) return false;
  // Only the bigint immediate encoding is canonical evidence (#3145 family):
  // coercible values must not reach the definite conditional-compare path.
  if (comparison?.k === 'imm' && typeof comparison.value !== 'bigint') return false;
  if (fallback?.k === 'imm' && typeof fallback.value !== 'bigint') return false;
  return true;
}

export function liftArm64FlagEffects(instruction, options = {}) {
  if (typeof instruction?.mnemonic !== 'string') return null;
  const mnemonic = instruction.mnemonic.trim().toLowerCase();
  const rawOps = Array.isArray(instruction?.ops) ? instruction.ops : [];
  const snapshot = FLAG_MNEMONICS.has(mnemonic)
    ? snapshotArm64ImmediateOperands(instruction, rawOps)
    : Object.freeze({ instruction, ops:rawOps });
  if (!snapshot) {
    return createArm64EffectContext(instruction, options).partial(
      `arm64-${mnemonic}-immediate-value-unencodable`, ['flags','other']);
  }
  const stableInstruction = snapshot.instruction;
  const ops = snapshot.ops;
  if (STRICT_IMMEDIATE_VALUE_MNEMONICS.has(mnemonic) && hasNonCanonicalImmediateValue(ops)) {
    return createArm64EffectContext(stableInstruction, options).partial(
      `arm64-${mnemonic}-immediate-value-unencodable`, ['flags','other']);
  }
  if (STRICT_REGISTER_LHS.has(mnemonic) && !validRegisterLhs(mnemonic, ops[0])) {
    return liftArm64FlagEffectsCore({ ...stableInstruction, ops: [] }, options);
  }
  if (SP_LHS_MNEMONICS.has(mnemonic) && !validSpImmediateRhs(ops[1])) {
    return liftArm64FlagEffectsCore({ ...stableInstruction, ops: [] }, options);
  }
  if (STRICT_REGISTER_LHS.has(mnemonic) && !validRegisterRhs(mnemonic, ops[0], ops[1])) {
    return liftArm64FlagEffectsCore({ ...stableInstruction, ops: [] }, options);
  }
  if ((mnemonic === 'ccmp' || mnemonic === 'ccmn') && ops.length === 4
    && (!validConditionalCompareCondition(ops[3]) || !validConditionalCompareImmediates(ops))) {
    // Malformed conditional-compare evidence must not produce register reads
    // or any definite state: return a bare partial with zero operations.
    // (Arity failures keep the core's canonical operand-shape reason.)
    const ctx = createArm64EffectContext(stableInstruction, options);
    return ctx.partial('arm64-conditional-compare-evidence-invalid', ['flags', 'other']);
  }
  if (mnemonic === 'tst' && !validTstRegisterClass(ops)) {
    return liftArm64FlagEffectsCore({ ...stableInstruction, ops: [] }, options);
  }
  return liftArm64FlagEffectsCore(stableInstruction, options);
}
