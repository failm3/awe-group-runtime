import {readFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';

export const readPlan = () => JSON.parse(readFileSync(new URL('./vm-egress-policy.json', import.meta.url)));
export const readProbes = () => JSON.parse(readFileSync(new URL('./acceptance-probes.json', import.meta.url)));
export function inspectPlan(plan, probes) {
  const errors = [];
  const check = (ok, reason) => { if (!ok) errors.push(reason); };
  check(plan.status === 'PROPOSED_NOT_ENFORCED' && plan.deployment_authorized === false &&
    plan.acceptance.real_isolation === 'NOT_RUN', 'HONEST_NOT_RUN_REQUIRED');
  check(plan.project_boundary === 'ONE_VM_PER_PROJECT' && plan.lifecycle.disposable &&
    plan.lifecycle.destroy_after_probe && ['host_mounts', 'live_workspace_mounts', 'host_devices'].every(k =>
      plan.lifecycle[k].length === 0) && !plan.lifecycle.container_socket, 'HOST_BOUNDARY');
  check(['default', 'ipv4', 'ipv6', 'tcp', 'udp', 'dns', 'metadata', 'loopback_host_gateway'].every(k =>
    plan.network[k] === 'DENY') && plan.network.egress_allowlist.length === 0 &&
    plan.network.ingress_allowlist.length === 0 && plan.network.provider_access === 'NONE' &&
    plan.network.proxy_environment === 'ABSENT', 'NETWORK_DEFAULT_DENY_PROPOSAL');
  check(plan.worker.os_identity === 'DISTINCT_UNPRIVILEGED_PER_PROJECT' &&
    ['capabilities', 'secret_handles', 'inherited_descriptors'].every(k => plan.worker[k].length === 0) &&
    !plan.worker.host_terminal && !plan.worker.control_plane_credentials, 'WORKER_PRIVILEGES');
  check(!plan.database.worker_direct_access && !plan.database.superuser && !plan.database.owner &&
    !plan.database.bypassrls && plan.database.force_rls, 'DATABASE_BOUNDARY');
  check(plan.storage.cross_project_mounts.length === 0 && plan.storage.project_volume === 'PRIVATE_EPHEMERAL' &&
    plan.storage.qa_hidden_volume === 'EXAMINER_ONLY_OUTSIDE_WORKER_CHECKOUT' &&
    plan.storage.local_qa_verdict === 'SEALED_FROM_EXAMINER_AND_AUDITOR' &&
    plan.storage.trace === 'PEP_METADATA_PROJECTION_ONLY', 'QA_STORAGE_BOUNDARY');
  check(plan.effect_gateway.mode === 'OFFLINE_RECORDER_ONLY' && plan.effect_gateway.direct_worker_dispatch === 'DENY' &&
    plan.effect_gateway.recheck_at_dispatch && !plan.effect_gateway.secrets_in_worker, 'EFFECT_GATEWAY');
  const required = ['VM01', 'NET01', 'NET02', 'FS01', 'DB01', 'IPC01', 'DATA01', 'QA01', 'PEP01', 'TOOL01'];
  check(probes.status === 'NOT_RUN' && probes.probes.length === required.length && required.every(id =>
    probes.probes.some(p => p.id === id && p.status === 'NOT_RUN' && p.required_evidence.length >= 2 && p.procedure)), 'PROBE_COVERAGE');
  return errors;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const probes = readProbes(), errors = inspectPlan(readPlan(), probes);
  console.log(JSON.stringify({status: errors.length ? 'FAIL' : 'DESIGN_CHECK_PASS', errors,
    live_vm_network_probes: 'NOT_RUN', pending_probes: probes.probes.map(p => p.id)}));
  if (errors.length) process.exitCode = 1;
}
