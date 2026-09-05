import assert from 'node:assert/strict';

import { parseOperands } from '../../js/arm64.js';
import { validateMachineEffectBundle } from '../../js/semantics/effects/index.js';
import { liftArm64MachineEffects } from '../../js/targets/architecture/arm64/effects/index.js';

function instruction(mnemonic, operands, id) {
  return {
    instructionId:id,
    mnemonic,
    operands,
    opStr:operands,
    ops:parseOperands(operands),
    mode:'a64',
    origin:{ instructionIds:[id] },
  };
}

function accessFault(bundle, label) {
  assert.ok(bundle, `${label}: missing MachineEffects bundle`);
  assert.ok(['exact','exact-with-intrinsic'].includes(bundle.completeness), `${label}: unexpected completeness ${bundle.completeness}`);
  const faults = bundle.possibleFaults.filter((fault) => fault.kind === 'fp-advsimd-access-trap');
  assert.equal(faults.length, 1, `${label}: FP/AdvSIMD access trap must be represented exactly once`);
  assert.doesNotThrow(() => validateMachineEffectBundle(bundle), `${label}: emitted bundle must satisfy MachineEffects schema`);
  return faults[0];
}

function conditionalAccessTrap(bundle, label) {
  const fault = accessFault(bundle, label);
  assert.equal(fault.condition?.kind, 'architectural-access-check', `${label}: unresolved access trap must remain conditional`);
  assert.equal(fault.condition?.architecture, 'arm64', `${label}: wrong architecture authority`);
  assert.equal(fault.condition?.access, 'fp-advsimd', `${label}: wrong access class`);
  assert.equal(fault.condition?.check, 'CheckFPAdvSIMDEnabled', `${label}: wrong architectural check`);
  for (const control of ['PSTATE.EL','CPACR_EL1.FPEN','CPTR_EL2.FPEN','CPTR_EL2.TFP','CPTR_EL3.TFP']) {
    assert.ok(fault.condition.controls.includes(control), `${label}: missing access-control authority ${control}`);
  }
  assert.equal(fault.detail?.target, 'environment-dependent-exception-level', `${label}: unresolved trap target must not be fabricated`);
  assert.equal(fault.detail?.accessState, 'unknown', `${label}: unresolved architectural access must be marked unknown`);
  return bundle;
}

function disabledAccessTrap(bundle, label, target) {
  const fault = accessFault(bundle, label);
  assert.equal(fault.condition, undefined, `${label}: proven-disabled access must not remain environment-conditional`);
  assert.equal(fault.detail?.target, target, `${label}: wrong proven trap target`);
  assert.equal(fault.detail?.accessState, 'disabled', `${label}: proven-disabled access state must be explicit`);
  assert.equal(fault.detail?.check, 'CheckFPAdvSIMDEnabled', `${label}: wrong architectural check`);
  return bundle;
}

function allowedAccess(bundle, label) {
  assert.ok(bundle, `${label}: missing MachineEffects bundle`);
  assert.ok(['exact','exact-with-intrinsic'].includes(bundle.completeness), `${label}: unexpected completeness ${bundle.completeness}`);
  assert.equal(bundle.possibleFaults.some((fault) => fault.kind === 'fp-advsimd-access-trap'), false,
    `${label}: proven-allowed access must not retain an impossible FP/AdvSIMD access trap`);
  assert.doesNotThrow(() => validateMachineEffectBundle(bundle), `${label}: emitted bundle must satisfy MachineEffects schema`);
  return bundle;
}

for (const [mnemonic, operands] of [
  ['fadd', 's0, s1, s2'],
  ['fmov', 's0, s1'],
  ['fabs', 's0, s1'],
  ['fcmp', 's0, s1'],
  ['fcsel', 's0, s1, s2, eq'],
]) {
  const id = `issue-4201:fp:${mnemonic}`;
  const bundle = conditionalAccessTrap(liftArm64MachineEffects(instruction(mnemonic, operands, id)), id);
  assert.equal(bundle.metadata.family, 'arm64-fp', `${id}: scalar FP semantics must stay owned by FP family`);
}

const simd = conditionalAccessTrap(
  liftArm64MachineEffects(instruction('add', 'v0.4s, v1.4s, v2.4s', 'issue-4201:simd:add')),
  'issue-4201:simd:add',
);
assert.equal(simd.metadata.family, 'arm64-simd', 'Advanced SIMD integer semantics must receive the same architectural access gate');

const el0DisabledContext = {
  arm64AccessControl:{
    currentEL:0,
    el0InHost:false,
    cpacrEl1Fpen:0,
    el2Enabled:false,
    el3Implemented:false,
  },
};
disabledAccessTrap(
  liftArm64MachineEffects(instruction('fadd', 's0, s1, s2', 'issue-4201:el0:disabled'), el0DisabledContext),
  'issue-4201:el0:disabled',
  'EL1',
);

const el0AllowedContext = {
  arm64AccessControl:{
    currentEL:0,
    el0InHost:false,
    cpacrEl1Fpen:3,
    el2Enabled:false,
    el3Implemented:false,
  },
};
allowedAccess(
  liftArm64MachineEffects(instruction('fadd', 's0, s1, s2', 'issue-4201:el0:allowed'), el0AllowedContext),
  'issue-4201:el0:allowed',
);

const hostDisabledContext = {
  arm64AccessControl:{
    currentEL:0,
    el0InHost:true,
    el2Enabled:true,
    el2InHost:true,
    cptrEl2Fpen:1,
    el3Implemented:false,
  },
};
disabledAccessTrap(
  liftArm64MachineEffects(instruction('fadd', 's0, s1, s2', 'issue-4201:host:disabled'), hostDisabledContext),
  'issue-4201:host:disabled',
  'EL2',
);

const hostAllowedContext = {
  arm64AccessControl:{
    currentEL:0,
    el0InHost:true,
    el2Enabled:true,
    el2InHost:true,
    cptrEl2Fpen:3,
    el3Implemented:false,
  },
};
allowedAccess(
  liftArm64MachineEffects(instruction('fadd', 's0, s1, s2', 'issue-4201:host:allowed'), hostAllowedContext),
  'issue-4201:host:allowed',
);

conditionalAccessTrap(
  liftArm64MachineEffects(
    instruction('fadd', 's0, s1, s2', 'issue-4201:malformed-context'),
    { arm64AccessControl:{ currentEL:'0', el3Implemented:false } },
  ),
  'issue-4201:malformed-context',
);

const gpAdd = liftArm64MachineEffects(instruction('add', 'x0, x1, x2', 'issue-4201:integer:add'));
assert.ok(gpAdd);
assert.equal(gpAdd.metadata.family, 'arm64-integer');
assert.equal(gpAdd.possibleFaults.some((fault) => fault.kind === 'fp-advsimd-access-trap'), false,
  'ordinary GP integer instructions must not inherit the FP/AdvSIMD access gate');

const malformed = liftArm64MachineEffects(instruction('fadd', 's0, d1, s2', 'issue-4201:malformed:fadd'));
assert.ok(malformed);
assert.equal(malformed.completeness, 'partial');
assert.equal(malformed.possibleFaults.some((fault) => fault.kind === 'fp-advsimd-access-trap'), false,
  'malformed structured evidence must fail closed before acquiring architectural execution semantics');

console.log('issue #4201 ARM64 FP/AdvSIMD access-trap regression: PASS');
