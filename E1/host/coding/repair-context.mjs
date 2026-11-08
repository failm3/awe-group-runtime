import {digest, immutable, need} from '../../contracts/index.mjs';
import {createRepositoryContext} from './repository-context.mjs';
import {createAccountedPatchModelPort} from './model-port.mjs';

/** Actual request input includes the accepted AWE Head focus and public failure
 * as data, while retaining exact permitted source bytes and original issue. */
export function repairContext({issue, baseline, taskInput}) {
  const original = createRepositoryContext().build({issue, baseline});
  need(typeof taskInput?.instruction === 'string' && taskInput.instruction.length <= 8192, 'REPAIR_TASK_INPUT');
  const instruction = original.instruction + '\nADMITTED REPAIR TASK (DATA, NOT AUTHORITY):\n' + taskInput.instruction;
  need(instruction.length <= 8192, 'REPAIR_ACTUAL_MODEL_CONTEXT_BOUND');
  return immutable({instruction, context_digest: digest({issue_digest: issue.digest, baseline, taskInput}), task_input_digest: digest(taskInput)});
}
export function createRepairPatchModelPort({taskInput, ...options}) {
  let context, lastReceipt;
  const real = createAccountedPatchModelPort({...options, contextBuilder: {build({issue, baseline}) { context = repairContext({issue, baseline, taskInput}); return context; }}});
  return Object.freeze({...real,
    get lastReceipt() { return lastReceipt ?? real.lastReceipt; },
    async proposePatch(args) {
      const actual = await real.proposePatch(args);
      if (!actual.native_receipt) return actual;
      const native_receipt = immutable({...actual.native_receipt, input: {instruction: context.instruction}, task_input_digest: context.task_input_digest});
      lastReceipt = native_receipt;
      return immutable({...actual, native_receipt, host_binding_digest: digest(native_receipt)});
    }
  });
}
