import assert from 'node:assert/strict';

import { liftX86SystemRegisterMoveEffects } from '../../js/targets/architecture/x86_64/effects/system-register-move.js';

let instructionCode = 0x556500;

function register(name, access) {
  return { type:'register', register:{ id:name, registerId:name }, access };
}

function debugMove(debugRegister, direction) {
  instructionCode += 1;
  const debugIndex = Number(debugRegister.slice(2));
  const writesDebug = direction === 'write';
  const opcode = writesDebug ? 0x23 : 0x21;
  const modrm = 0xc0 | ((debugIndex & 7) << 3);
  return {
    instructionId:`issue-5565-${instructionCode}`,
    instructionCode,
    instructionFamily:'mov',
    opcodeName:'mov',
    mnemonic:'mov',
    mode:'long-64',
    address:0x556500n + BigInt(instructionCode),
    length:3,
    rawBytes:Uint8Array.of(0x0f, opcode, modrm),
    detailStatus:'complete',
    decoderSemanticVersion:'capstone-5-x86-structured-v2',
    detail:{
      abiContractVersion:'capstone-5-wasm32-x86-detail/v1',
      operandCount:2,
      operands:writesDebug
        ? [register(debugRegister, 'write'), register('rax', 'read')]
        : [register('rax', 'write'), register(debugRegister, 'read')],
    },
  };
}

for (const [debugRegister, aliasWhenClear] of [['dr4', 'dr6'], ['dr5', 'dr7']]) {
  for (const direction of ['read', 'write']) {
    const result = liftX86SystemRegisterMoveEffects(debugMove(debugRegister, direction));
    assert.equal(result.completeness, 'partial', `${direction} ${debugRegister} must fail closed without CR4.DE state`);
    assert.equal(result.unknownEffects?.reason, 'x86-debug-register-alias-state-unmodelled');
    assert.equal(result.operations.length, 0, 'unresolved DR4/DR5 state must not emit definite register effects');
    assert.equal(result.metadata?.privilegedRegister, debugRegister);
    assert.equal(result.metadata?.controlRegister, 'cr4');
    assert.equal(result.metadata?.controlField, 'DE');
    assert.equal(result.metadata?.aliasWhenClear, aliasWhenClear);
    assert.equal(result.metadata?.faultWhenSet, '#UD');
    assert.equal(result.metadata?.debugGeneralDetectPrecedesAccess, true);
    assert.ok(result.possibleFaults.some((fault) =>
      fault.kind === 'undefined-opcode'
      && fault.condition?.kind === 'x86-debug-register-alias-control'
      && fault.condition?.register === debugRegister
      && fault.condition?.controlRegister === 'cr4'
      && fault.condition?.field === 'DE'
      && fault.condition?.value === 1
      && fault.detail?.fault === '#UD'),
    `CR4.DE=1 must retain the #UD alternative for ${direction} ${debugRegister}`);
    assert.ok(result.possibleFaults.some((fault) =>
      fault.kind === 'debug-exception'
      && fault.condition?.kind === 'x86-debug-general-detect'
      && fault.detail?.fault === '#DB'),
    `DR7.GD pre-access #DB must remain represented for ${direction} ${debugRegister}`);
  }
}

// Ordinary architectural debug registers retain the existing exact summary and
// DR7.GD pre-access #DB alternative.
for (const debugRegister of ['dr0', 'dr3', 'dr6', 'dr7']) {
  for (const direction of ['read', 'write']) {
    const result = liftX86SystemRegisterMoveEffects(debugMove(debugRegister, direction));
    assert.equal(result.completeness, 'exact-with-intrinsic', `${direction} ${debugRegister} should remain exact`);
    assert.equal(result.metadata?.privilegedRegister, debugRegister);
    assert.ok(result.operations.length > 0);
    assert.ok(result.possibleFaults.some((fault) =>
      fault.kind === 'debug-exception'
      && fault.condition?.kind === 'x86-debug-general-detect'
      && fault.detail?.fault === '#DB'),
    `DR7.GD #DB ordering must remain represented for ${direction} ${debugRegister}`);
  }
}

console.log('issue-5565 x86 DR4/DR5 CR4.DE alias semantics: ok');
