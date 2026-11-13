import {performance} from 'node:perf_hooks';
import {digest, immutable} from '../contracts/index.mjs';
import {MODEL_POLICY} from './schemas.mjs';
import {selectExecutor} from './registry.mjs';
import {runPinnedScript} from './canary.mjs';

/** One real bounded request, through the injected SAME A2 accounting port.
 * Caller must admit/publish/claim fixture.bootstrapPlan before invoking.
 */
export async function runMinimalBenchmark({broker, fixture, scope}) {
  const {registry, spec, grant, source, rubric, domainManifest, authority, contexts, bootstrapPlan} = fixture;
  const scriptSelection = selectExecutor({registry, spec, grant, task: {kind: 'deterministic', data_label: 'SYNTHETIC'}});
  const semanticSelection = selectExecutor({registry, spec, grant, task: {kind: 'head', data_label: 'SYNTHETIC'}});
  const started = performance.now();
  const script = runPinnedScript({registry, spec, grant, input: bootstrapPlan.tasks.find(x => x.task_id === 'parse_source').input});
  const script_latency_ms = Math.ceil(performance.now() - started);
  const head = await broker.generateHeadProposal({scope, spec, grant, source, domainManifest, authority, headContext: contexts.head, plan_id: bootstrapPlan.plan_id, revision: 2, previous_digest: digest(bootstrapPlan)});
  return immutable({version: 'awe.e1.minimal-model-benchmark/1', measured_at: new Date().toISOString(), manifest: {input_digest: digest(source), rubric_digest: digest(rubric), bootstrap_plan_digest: digest(bootstrapPlan), registry_digest: registry.digest, policy_digest: digest(MODEL_POLICY), source_build_digest: registry.source.build_digest, seed: 42, temperature: 0, full_5x3: 'NOT_RUN'}, selectors: {script: scriptSelection, semantic: semanticSelection}, rows: [{route: 'e1.code.parse', status: 'MEASURED', executor_kind: 'script', latency_ms: script_latency_ms, api_cost_micros: 0, artifact_digest: script.artifact_digest}, {route: MODEL_POLICY.route_id, status: head.evidence_level === 'LIVE_LOCAL_MODEL' && head.wire_attempts === 1 ? 'MEASURED' : head.evidence_level === 'OFFLINE_TEST_DOUBLE' ? 'OFFLINE_TEST_DOUBLE' : 'NOT_RUN', executor_kind: 'llm', decision: head.decision, usage: head.usage ?? null, api_cost_micros: 0, qa_verdict: 'PENDING_INDEPENDENT_QA'}, ...['qwen3-8b-mac', 'cloud-sol', 'cloud-terra', 'cloud-other', 'real-browser-qa'].map(route => ({route, status: 'NOT_RUN', reason: 'OUTSIDE_CURRENT_AUTHORIZATION_OR_CAPABILITY'}))], head, accepted: false, api_cost_micros: 0, infrastructure_cost: 'NOT_MEASURED', cost_per_accepted_result: 'NO_ACCEPTED_RESULT', quality_winner: 'NOT_ESTABLISHED'});
}
