export function snapshotArm64ImmediateOperands(instruction, ops) {
  const stableOps = [];
  let hasImmediate = false;

  for (const op of ops) {
    if (!op || typeof op !== 'object' || op.k !== 'imm') {
      stableOps.push(op);
      continue;
    }

    let descriptors;
    try {
      descriptors = Object.getOwnPropertyDescriptors(op);
    } catch {
      return null;
    }
    const valueDescriptor = descriptors.value;
    if (!valueDescriptor || !Object.prototype.hasOwnProperty.call(valueDescriptor, 'value')) return null;

    descriptors.value = {
      value: valueDescriptor.value,
      enumerable: valueDescriptor.enumerable !== false,
      writable: false,
      configurable: false,
    };
    stableOps.push(Object.create(Object.getPrototypeOf(op), descriptors));
    hasImmediate = true;
  }

  if (!hasImmediate) return Object.freeze({ instruction, ops });

  let instructionDescriptors;
  try {
    instructionDescriptors = Object.getOwnPropertyDescriptors(instruction);
  } catch {
    return null;
  }
  const opsDescriptor = instructionDescriptors.ops;
  instructionDescriptors.ops = {
    value: stableOps,
    enumerable: opsDescriptor?.enumerable !== false,
    writable: false,
    configurable: false,
  };
  const stableInstruction = Object.create(Object.getPrototypeOf(instruction), instructionDescriptors);
  return Object.freeze({ instruction: stableInstruction, ops: stableOps });
}
