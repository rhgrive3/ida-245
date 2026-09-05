import assert from 'node:assert/strict';

import { liftArm64MachineEffects } from '../../js/targets/architecture/arm64/effects/index.js';
import { liftArm64FpEffects } from '../../js/targets/architecture/arm64/effects/fp.js';

const FMOV_D0_ONE_BITS = 0x3ff0000000000000n;

function fmovImmediate(bitPatternOrFields, id) {
  const fields = bitPatternOrFields && typeof bitPatternOrFields === 'object' && !Array.isArray(bitPatternOrFields)
    && ('bitPattern' in bitPatternOrFields || 'float' in bitPatternOrFields)
    ? bitPatternOrFields
    : { bitPattern: bitPatternOrFields };
  return {
    instructionId: id,
    mnemonic: 'fmov',
    mode: 'a64',
    ops: [
      { k:'reg', cls:'fp', num:0, bits:64, text:'d0' },
      { k:'imm', ...fields, text:'#1.0' },
    ],
    origin: { instructionIds:[id] },
  };
}

function writesV0(bundle) {
  return bundle.operations.some((operation) =>
    operation?.kind === 'register-write' && operation?.register?.registerId === 'v0');
}

const canonical = liftArm64FpEffects(fmovImmediate(FMOV_D0_ONE_BITS, 'fmov-bitpattern-bigint'));
assert.equal(canonical.completeness, 'exact');
assert.equal(writesV0(canonical), true);

const canonicalFloat = liftArm64FpEffects(fmovImmediate({ float:1 }, 'fmov-float-number'));
assert.equal(canonicalFloat.completeness, 'exact');
assert.equal(writesV0(canonicalFloat), true);

const unencodableCanonical = liftArm64FpEffects(fmovImmediate(0n, 'fmov-bitpattern-zero'));
assert.equal(unencodableCanonical.completeness, 'partial');
assert.equal(writesV0(unencodableCanonical), false);

const coercibleObject = {
  [Symbol.toPrimitive]() { return FMOV_D0_ONE_BITS; },
};

for (const [label, value] of [
  ['numeric-string', FMOV_D0_ONE_BITS.toString()],
  ['array', [FMOV_D0_ONE_BITS]],
  ['boolean', true],
  ['number', Number(FMOV_D0_ONE_BITS)],
  ['coercible-object', coercibleObject],
]) {
  const result = liftArm64FpEffects(fmovImmediate(value, `fmov-bitpattern-${label}`));
  assert.equal(result.completeness, 'partial', `${label} bitPattern must fail closed`);
  assert.equal(writesV0(result), false, `${label} bitPattern must not produce a definite destination write`);
}

const canonicalDispatcher = liftArm64MachineEffects(
  fmovImmediate(FMOV_D0_ONE_BITS.toString(), 'fmov-bitpattern-string-dispatcher'));
assert.equal(canonicalDispatcher.completeness, 'partial');
assert.equal(writesV0(canonicalDispatcher), false);

console.log('ARM64 FMOV bitPattern typed-authority regression: PASS');
