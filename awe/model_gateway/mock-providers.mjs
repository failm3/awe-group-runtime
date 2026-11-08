import {createMockAdapter} from '../providers/mock-adapter.mjs';
import {copy} from './profiles.mjs';
import {requireThat as need} from '../budget/money.mjs';
const witnesses=new WeakMap();
// Wrap the existing D06 sealed mock. No provider transport, callbacks or new attempt owner.
export function createRecordedMockProvider({provider,script=[],deferred=false}) {
  const mock=createMockAdapter({provider,script,deferred}),handle=Object.freeze({kind:'LLM01_RECORDED_D06_MOCK'});
  witnesses.set(handle,mock);
  return {providerMock:handle,control:Object.freeze({completeNext:()=>mock.control.completeNext()})};
}
export function recordedAdapter(handle) {
  const mock=witnesses.get(handle);need(mock,'SEALED_RECORDED_MOCK_REQUIRED');return mock.adapter;
}
export function observedMockCalls(handle,attemptIds) {
  const mock=witnesses.get(handle);need(mock,'SEALED_RECORDED_MOCK_REQUIRED');
  return copy(mock.control.calls().filter(x=>attemptIds.includes(x.attemptId)));
}
