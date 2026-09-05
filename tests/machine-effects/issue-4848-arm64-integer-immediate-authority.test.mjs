import assert from 'node:assert/strict';
import { liftArm64MachineEffects } from '../../js/targets/architecture/arm64/effects/index.js';
import { liftArm64FlagEffects } from '../../js/targets/architecture/arm64/effects/flags.js';
import { liftArm64IntegerEffects } from '../../js/targets/architecture/arm64/effects/integer.js';

let seq = 0;
const gp = (num, bits = 64) => ({ k:'reg', cls:'gp', num, bits, text:`${bits === 32 ? 'w' : 'x'}${num}` });
const imm = (value, extra = {}) => ({ k:'imm', value, text:`#${typeof value === 'bigint' ? value : 'evidence'}`, ...extra });

function instruction(mnemonic, ops, extra = {}) {
  const instructionId = `issue-4848:${mnemonic}:${++seq}`;
  return {
    instructionId,
    mnemonic,
    mode:'a64',
    ops,
    origin:{ instructionIds:[instructionId] },
    ...extra,
  };
}

function lift(mnemonic, ops) {
  return liftArm64MachineEffects(instruction(mnemonic, ops));
}

function assertSemantic(bundle, label) {
  assert.ok(bundle, `${label}: family remains owned`);
  assert.notEqual(bundle.completeness, 'partial', `${label}: canonical encoding remains semantic`);
  assert.ok(bundle.operations.some((operation) => operation.kind !== 'unknown'), `${label}: canonical encoding emits definite semantics`);
}

function assertPartial(bundle, label) {
  assert.ok(bundle, `${label}: family remains owned`);
  assert.equal(bundle.completeness, 'partial', `${label}: invalid encoding fails closed`);
}

function assertAuthorityFailure(bundle, label) {
  assertPartial(bundle, label);
  assert.equal(bundle.operations.length, 0, `${label}: malformed immediate emits no definite operation`);
  assert.match(bundle.unknownEffects?.reason || '', /immediate-value-unencodable$/);
  assert.equal(bundle.metadata?.failClosed, true);
}

function statefulImmediate() {
  let reads = 0;
  let coercions = 0;
  const op = { k:'imm', text:'#stateful-evidence' };
  Object.defineProperty(op, 'value', {
    enumerable:true,
    configurable:true,
    get() {
      reads += 1;
      if (reads <= 2) return 1n;
      return {
        valueOf() {
          coercions += 1;
          return 1;
        },
      };
    },
  });
  return {
    op,
    reads:() => reads,
    coercions:() => coercions,
  };
}

// ADD/SUB and CMP/CMN retain the complete imm12 finite domain.
for (const mnemonic of ['add','sub']) {
  assertSemantic(lift(mnemonic, [gp(0), gp(1), imm(0n)]), `${mnemonic} imm12 lower boundary`);
  assertSemantic(lift(mnemonic, [gp(0), gp(1), imm(0xfffn)]), `${mnemonic} imm12 upper boundary`);
  assertPartial(lift(mnemonic, [gp(0), gp(1), imm(0x1000n)]), `${mnemonic} imm12 out of range`);
}
for (const mnemonic of ['cmp','cmn']) {
  assertSemantic(lift(mnemonic, [gp(0), imm(0n)]), `${mnemonic} imm12 lower boundary`);
  assertSemantic(lift(mnemonic, [gp(0), imm(0xfffn)]), `${mnemonic} imm12 upper boundary`);
  assertPartial(lift(mnemonic, [gp(0), imm(0x1000n)]), `${mnemonic} imm12 out of range`);
}

// Logical immediates preserve encodable masks while rejecting non-encodable zero.
assertSemantic(lift('and', [gp(0), gp(1), imm(0xffn)]), 'AND encodable logical immediate');
assertPartial(lift('and', [gp(0), gp(1), imm(0n)]), 'AND zero logical immediate');
assertSemantic(lift('tst', [gp(0), imm(0xffn)]), 'TST encodable logical immediate');
assertPartial(lift('tst', [gp(0), imm(0n)]), 'TST zero logical immediate');

// MOV aliases and move-wide forms retain their canonical bigint boundaries.
assertSemantic(lift('mov', [gp(0), imm(0n)]), 'MOV encodable zero');
assertSemantic(lift('mov', [gp(0), imm(0xffffn)]), 'MOV single-wide upper lane');
assertPartial(lift('mov', [gp(0), imm(0x123456789abcdefn)]), 'MOV non-encodable pattern');
for (const mnemonic of ['movz','movn','movk']) {
  assertSemantic(lift(mnemonic, [gp(0), imm(0n)]), `${mnemonic} lower boundary`);
  assertSemantic(lift(mnemonic, [gp(0), imm(0xffffn)]), `${mnemonic} upper boundary`);
  assertPartial(lift(mnemonic, [gp(0), imm(0x10000n)]), `${mnemonic} out of range`);
}

// Shift, EXTR and bitfield selectors retain the canonical finite-domain edges.
assertSemantic(lift('lsl', [gp(0), gp(1), imm(0n)]), 'LSL lower boundary');
assertSemantic(lift('lsl', [gp(0), gp(1), imm(63n)]), 'LSL upper boundary');
assertPartial(lift('lsl', [gp(0), gp(1), imm(64n)]), 'LSL out of range');
assertSemantic(lift('extr', [gp(0), gp(1), gp(2), imm(0n)]), 'EXTR lower boundary');
assertSemantic(lift('extr', [gp(0), gp(1), gp(2), imm(63n)]), 'EXTR upper boundary');
assertPartial(lift('extr', [gp(0), gp(1), gp(2), imm(64n)]), 'EXTR out of range');
assertSemantic(lift('ubfm', [gp(0), gp(1), imm(0n), imm(63n)]), 'UBFM canonical endpoints');
assertPartial(lift('ubfm', [gp(0), gp(1), imm(64n), imm(63n)]), 'UBFM immr out of range');
assertSemantic(lift('ubfx', [gp(0), gp(1), imm(0n), imm(64n)]), 'UBFX full-width alias');
assertPartial(lift('ubfx', [gp(0), gp(1), imm(63n), imm(2n)]), 'UBFX lsb plus width out of range');

// Representative scalar integer/flags families must reject coercible evidence
// before any definite MachineEffects operation is emitted.
const authorityCases = [
  ['add', [gp(0), gp(1), imm(1n)]],
  ['cmp', [gp(0), imm(1n)]],
  ['and', [gp(0), gp(1), imm(1n)]],
  ['tst', [gp(0), imm(1n)]],
  ['mov', [gp(0), imm(1n)]],
  ['movz', [gp(0), imm(1n)]],
  ['lsl', [gp(0), gp(1), imm(1n)]],
  ['extr', [gp(0), gp(1), gp(2), imm(1n)]],
  ['ubfm', [gp(0), gp(1), imm(1n), imm(1n)]],
];
const malformedValues = [
  '1',
  1,
  true,
  [1],
  { toString() { return '1'; } },
];
for (const malformed of malformedValues) {
  for (const [mnemonic, ops] of authorityCases) {
    const poisoned = ops.map((op) => op.k === 'imm' ? { ...op, value:malformed } : op);
    assertAuthorityFailure(lift(mnemonic, poisoned), `${mnemonic} ${typeof malformed}`);
  }
}

// Stateful accessors cannot validate as bigint and later substitute coercible
// evidence into either the integer or flag semantic lowering path.
const topLevelStateful = statefulImmediate();
assertAuthorityFailure(
  lift('add', [gp(0), gp(1), topLevelStateful.op]),
  'top-level stateful ADD immediate',
);

const directIntegerStateful = statefulImmediate();
assertAuthorityFailure(
  liftArm64IntegerEffects(instruction('add', [gp(0), gp(1), directIntegerStateful.op])),
  'direct integer stateful ADD immediate',
);
assert.equal(directIntegerStateful.reads(), 0, 'direct integer boundary must reject an accessor without invoking it');
assert.equal(directIntegerStateful.coercions(), 0, 'direct integer boundary must not invoke hostile coercion hooks');

const directFlagStateful = statefulImmediate();
assertAuthorityFailure(
  liftArm64FlagEffects(instruction('cmp', [gp(0), directFlagStateful.op])),
  'direct flag stateful CMP immediate',
);
assert.equal(directFlagStateful.reads(), 0, 'direct flag boundary must reject an accessor without invoking it');
assert.equal(directFlagStateful.coercions(), 0, 'direct flag boundary must not invoke hostile coercion hooks');

// ADR/ADRP are address-evidence forms, not scalar-immediate authority forms.
// Preserve their existing coercible-address parsing and range/alignment gate.
assertSemantic(
  liftArm64IntegerEffects(instruction('adr', [gp(0), imm('4100')], {
    address:0x1000n,
    pcRelTarget:0x1004n,
  })),
  'ADR string address evidence remains governed by address validation',
);

// The integer-family boundary must remain scoped: unrelated families are not
// claimed merely because malformed immediate evidence is present.
const foreignInstructionId = `issue-4848:foreign:${++seq}`;
assert.equal(
  liftArm64IntegerEffects({
    instructionId:foreignInstructionId,
    mnemonic:'ldr',
    mode:'a64',
    ops:[imm('1')],
    origin:{ instructionIds:[foreignInstructionId] },
  }),
  null,
  'integer authority gate must not claim a non-integer family',
);

console.log('issue-4848-arm64-integer-immediate-authority: PASS');
