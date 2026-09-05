import assert from 'node:assert/strict';

import { createX86DecodedInstruction } from '../../js/targets/architecture/x86_64/decoded-instruction.js';
import { liftX86MachineEffects } from '../../js/targets/architecture/x86_64/effects/index.js';
import { createCapstoneX86Session } from '../phase5/helpers/capstone-session.mjs';

function widthBits(value) {
  return value?.kind === 'temporary' ? value.valueType?.widthBits : value?.widthBits;
}

function repeatedIntrinsic(bundle) {
  const intrinsic = bundle.operations.find((operation) => operation.kind === 'intrinsic');
  assert.ok(intrinsic, 'repeated string intrinsic missing');
  assert.equal(intrinsic.metadata.summaryContractVersion, 'x86-repeated-string-summary/v1');
  assert.equal(intrinsic.metadata.inputRoles.length, intrinsic.effectSummary.inputs.length);
  return intrinsic;
}

function roleInput(intrinsic, role, kind) {
  const index = intrinsic.metadata.inputRoles.findIndex((entry) => entry?.role === role && entry?.kind === kind);
  assert.notEqual(index, -1, `${role}/${kind} input role missing`);
  return { descriptor:intrinsic.metadata.inputRoles[index], value:intrinsic.effectSummary.inputs[index] };
}

const session = await createCapstoneX86Session();
try {
  {
    const [decoded] = session.decode(Uint8Array.of(0x67,0xf3,0xa4), 0x620000n);
    assert.ok(decoded, 'addr32 rep movsb did not decode');
    assert.equal(decoded.detail.addressSizeBits, 32);
    const instruction = createX86DecodedInstruction({ ...decoded, instructionId:'issue-4189:addr32-rep-movsb' });
    const bundle = liftX86MachineEffects(instruction);
    assert.equal(bundle.completeness, 'exact-with-intrinsic');
    assert.equal(bundle.metadata.addressSizeBits, 32);

    const intrinsic = repeatedIntrinsic(bundle);
    for (const [role, semanticRegister, physicalRegister] of [
      ['count','ecx','rcx'],
      ['source','esi','rsi'],
      ['destination','edi','rdi'],
    ]) {
      const semantic = roleInput(intrinsic, role, 'semantic');
      assert.equal(semantic.descriptor.register, semanticRegister);
      assert.equal(semantic.descriptor.widthBits, 32);
      assert.equal(widthBits(semantic.value), 32, `${role} semantic input must be address-size width`);

      const preserve = roleInput(intrinsic, role, 'zero-count-preservation');
      assert.equal(preserve.descriptor.register, physicalRegister);
      assert.equal(preserve.descriptor.widthBits, 64);
      assert.equal(widthBits(preserve.value), 64, `${role} zero-count preservation must retain full physical state`);
    }

    const viewOps = bundle.operations.filter((operation) => operation.kind === 'value' && operation.metadata?.semantic === 'x86-repeated-string-address-state-view');
    assert.equal(viewOps.length, 1, 'addr32 projection must stay within the frozen repeated-summary operation budget');
    assert.equal(viewOps[0].opcode, 'x86-string-address-state-project32');
    assert.deepEqual(viewOps[0].metadata.projections.map((entry) => entry.role).sort(), ['count','destination','source']);
    assert.ok(viewOps[0].outputs.every((value) => value.valueType.widthBits === 32));
    assert.deepEqual(intrinsic.effectSummary.outputs.slice(0,3).map(widthBits), [64,64,64], 'outputs must represent zero-count preservation and nonzero zero-extension in one summary');
    assert.equal(intrinsic.metadata.count.view, 'ecx');
    assert.match(intrinsic.metadata.count.zeroCount, /preserve full RCX/);
    assert.match(intrinsic.metadata.direction.zeroCount, /full physical register values/);
    assert.equal(intrinsic.metadata.addressState.arithmetic, 'modulo 2^32');
    assert.match(intrinsic.metadata.addressState.outputPolicy, /full entry state when ECX is zero/);
    assert.ok(bundle.operations.length <= 20, 'addr32 summary must not weaken the frozen operation-count threshold');
  }



  for (const [prefix, repeatKind] of [[0xf3,'repe'],[0xf2,'repne']]) {
    const [decoded] = session.decode(Uint8Array.of(0x67,prefix,0xa6), 0x620020n + BigInt(prefix));
    assert.ok(decoded, `addr32 ${repeatKind} cmpsb did not decode`);
    assert.equal(decoded.detail.addressSizeBits, 32);
    const instruction = createX86DecodedInstruction({ ...decoded, instructionId:`issue-4189:addr32-${repeatKind}-cmpsb` });
    const bundle = liftX86MachineEffects(instruction);
    assert.equal(bundle.completeness, 'exact-with-intrinsic');
    const intrinsic = repeatedIntrinsic(bundle);
    assert.equal(intrinsic.metadata.repeatKind, repeatKind);
    assert.equal(roleInput(intrinsic, 'count', 'semantic').descriptor.register, 'ecx');
    assert.equal(widthBits(roleInput(intrinsic, 'count', 'semantic').value), 32);
    const flags = roleInput(intrinsic, 'compare-flags', 'zero-count-preservation');
    assert.equal(flags.descriptor.register, 'rflags');
    assert.equal(widthBits(flags.value), 64);
    assert.ok(bundle.operations.length <= 20, `${repeatKind} addr32 summary exceeded frozen operation-count threshold`);
  }

  {
    const [decoded] = session.decode(Uint8Array.of(0xf3,0xa4), 0x620010n);
    assert.ok(decoded, 'addr64 rep movsb did not decode');
    assert.equal(decoded.detail.addressSizeBits, 64);
    const instruction = createX86DecodedInstruction({ ...decoded, instructionId:'issue-4189:addr64-rep-movsb' });
    const bundle = liftX86MachineEffects(instruction);
    assert.equal(bundle.completeness, 'exact-with-intrinsic');
    const intrinsic = repeatedIntrinsic(bundle);

    for (const [role, register] of [['count','rcx'],['source','rsi'],['destination','rdi']]) {
      const semantic = roleInput(intrinsic, role, 'semantic');
      assert.equal(semantic.descriptor.register, register);
      assert.equal(semantic.descriptor.widthBits, 64);
      assert.equal(widthBits(semantic.value), 64);
      assert.equal(intrinsic.metadata.inputRoles.some((entry) => entry?.role === role && entry?.kind === 'zero-count-preservation'), false, `${role} addr64 must not gain a duplicate preservation input`);
    }
    assert.equal(bundle.operations.some((operation) => operation.kind === 'value' && operation.metadata?.semantic === 'x86-repeated-string-address-state-view'), false, 'addr64 arithmetic must remain unchanged');
  }
} finally {
  session.close();
}

console.log('issue 4189 x86 addr32 REP state authority: PASS');
