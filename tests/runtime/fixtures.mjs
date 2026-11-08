import {fixture} from '../integration/fixtures.mjs';
import {digest} from '../../contracts/canonical.mjs';
import {createRuntimeAdapter, createRunRegistry} from '../../awe/runtime/adapter.mjs';
import {createFakeHermesTransport} from '../../awe/runtime/fake-hermes.mjs';

export async function runtimeFixture(options = {}) {
  const f = await fixture(options.integration);
  const registry = createRunRegistry(), transport = createFakeHermesTransport(options.transport);
  const configHash = digest({profile: 'd04-config-v1'}), manifestHash = digest({profile: 'd04-manifest-v1'});
  const args = {state: f.h.service, reader: f.h.state, supervisor: f.h.supervisor,
    bridge: options.bridgeTransform ? options.bridgeTransform(f.bridge) : f.bridge,
    clock: f.h.now, configHash, manifestHash, registry, transport};
  const adapter = createRuntimeAdapter(args);
  const descriptor = {id: f.tool.id, digest: f.tool.digest, input_schema_hash: f.tool.input_schema_hash,
    output_schema_hash: f.tool.output_schema_hash, action: f.tool.action, resource: f.tool.resource,
    effect_class: f.tool.effect_class, mode: 'SYNTHETIC_ONLY'};
  adapter.control.registerTool(JSON.stringify(descriptor));
  const grant = (id = 'run_parent', changes = {}) => {
    const task = f.task(), project = f.h.service.getProject(f.h.state, f.taskScope.project_id);
    return {schema_version: '1.0.0', contract: 'run-grant', request_id: 'req_runtime',
      correlation_id: 'corr_runtime', causation_id: null, actor: f.h.supervisor, scope: f.taskScope,
      epochs: project.epochs, spec: task.spec, created_at: f.h.now(), expected_revision: task.revision,
      run_id: id, parent_run_id: null, capabilities: [f.tool.id], deadline: '2026-11-05T12:00:09.000Z',
      budget_ref: digest({budget: 'synthetic-no-money'}), config_hash: configHash, manifest_hash: manifestHash,
      depth: 0, max_children: 1, max_physical_attempts: 1, ...changes};
  };
  const parent = grant('run_parent', options.parent);
  adapter.control.registerGrant(JSON.stringify(parent), 'act_worker');
  const launch = id => adapter.worker.launch(f.executorSession, id);
  const spawn = async (changes = {}, id = 'run_child') => {
    const child = grant(id, {parent_run_id: parent.run_id, depth: 1, max_children: 0,
      capabilities: parent.capabilities, max_physical_attempts: parent.max_physical_attempts, ...changes});
    adapter.control.registerGrant(JSON.stringify(child), 'act_worker'); return launch(id);
  };
  const admit = (id = 'run_child', prepared = {intent: f.intent, handle: f.handle}) => adapter.control.registerAdmission(id, prepared);
  return {...f, registry, transport, args, adapter, descriptor, grant, parent, launch, spawn, admit,
    exec: (id = 'run_child') => adapter.worker.executeTool(f.executorSession, id, f.opScope.operation_id),
    collect: (id = 'run_child') => adapter.worker.collectToolReceipt(f.executorSession, id, f.opScope.operation_id),
    finish: id => adapter.worker.complete(f.executorSession, id),
    cancelRun: id => adapter.worker.interrupt(f.executorSession, id),
    status: id => adapter.worker.status(f.executorSession, id)};
}

export async function ready(options) {
  const f = await runtimeFixture(options); await f.launch('run_parent'); await f.spawn(); f.admit(); return f;
}
