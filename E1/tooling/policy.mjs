import {digest, immutable, need} from '../contracts/index.mjs';

const TYPES = ['script', 'program', 'local_llm', 'cloud_llm'];
/** Explainable choice only. The selected ref still needs real A1/A2 dispatch.
 * API debit is compared explicitly; local infrastructure cost is not claimed. */
export function chooseExecutor({request, candidates, grant, now = new Date().toISOString()}) {
  need(request && typeof request.capability_id === 'string' && /^sha256:[a-f0-9]{64}$/.test(request.quality_suite_digest) && Number.isSafeInteger(request.min_quality_score) && request.min_quality_score >= 0 && request.min_quality_score <= 1000 && Number.isSafeInteger(request.max_cost_micros) && request.max_cost_micros >= 0 && Array.isArray(candidates) && candidates.length <= 64, 'TOOL_SELECTION_REQUEST');
  const reviews = candidates.map(candidate => {
    const reasons = [], ref = candidate.descriptor?.ref ?? candidate.ref, permissions = candidate.descriptor?.permissions ?? candidate.permissions;
    if (!TYPES.includes(candidate.executor_type)) reasons.push('EXECUTOR_TYPE_UNKNOWN');
    if (!ref || !(ref.capability_id === request.capability_id || candidate.provides?.includes(request.capability_id))) reasons.push('CAPABILITY_MISMATCH');
    if (!ref || !grant || grant.revoked_at !== null || !(grant.issued_at <= now && now < grant.expires_at) || !grant.allowed_capabilities?.some(allowed => digest(allowed) === digest(ref))) reasons.push('NO_CURRENT_GRANT');
    if (!Array.isArray(permissions) || !permissions.every(permission => grant?.permissions?.includes(permission))) reasons.push('PERMISSION_DENIED');
    if ((candidate.descriptor?.effect_class ?? candidate.effect_class) !== 'NONE' || !grant?.allowed_effect_classes?.includes('NONE')) reasons.push('EFFECT_SCOPE_DENIED');
    if (!candidate.installed || !candidate.available || !(now < candidate.health_until)) reasons.push('UNAVAILABLE');
    if (candidate.quality?.suite_digest !== request.quality_suite_digest || !Number.isSafeInteger(candidate.quality?.score) || candidate.quality.score < request.min_quality_score || !Number.isSafeInteger(candidate.quality?.tests) || candidate.quality.tests < 1 || candidate.quality.passed !== candidate.quality.tests) reasons.push('QUALITY_NOT_PROVEN');
    const cost = candidate.cost;
    if (cost?.basis !== 'ACTUAL_API_DEBIT_MICROS' || cost.verified !== true || cost.currency !== 'USD' || !Number.isSafeInteger(cost.effective_actual_micros) || cost.effective_actual_micros < 0 || cost.effective_actual_micros > request.max_cost_micros) reasons.push('EFFECTIVE_COST_UNKNOWN_OR_OVER_CAP');
    const budget = grant?.budget_cap;
    if (!budget || !['USD', 'NONE'].includes(budget.currency) || !/^\d{1,18}$/.test(budget.amount_micros) || (budget.currency === 'NONE' && budget.amount_micros !== '0') || (Number.isSafeInteger(cost?.effective_actual_micros) && BigInt(cost.effective_actual_micros) > BigInt(budget.amount_micros))) reasons.push('GRANT_BUDGET_UNKNOWN_OR_OVER_CAP');
    if (!(candidate.descriptor?.data_classes ?? candidate.data_classes)?.includes(request.data_class) || !grant?.allowed_data_classes?.includes(request.data_class) || !(candidate.descriptor?.origins ?? candidate.origins)?.includes(request.origin) || !grant?.allowed_origins?.includes(request.origin)) reasons.push('DATA_OR_ORIGIN_DENIED');
    // Current E1 cloud actual-charge contract is BLOCKED. Listing a cloud model
    // or setting a candidate flag cannot override that technical boundary.
    if (candidate.executor_type === 'cloud_llm') reasons.push('CLOUD_FINANCIAL_BINDING_BLOCKED');
    return {capability_id: ref?.capability_id ?? 'UNKNOWN', ref_digest: ref ? digest(ref) : null, executor_type: candidate.executor_type ?? 'UNKNOWN', eligible: reasons.length === 0, reasons, quality_score: candidate.quality?.score ?? null, effective_actual_micros: cost?.effective_actual_micros ?? null};
  });
  const eligible = reviews.filter(row => row.eligible).sort((a, b) => a.effective_actual_micros - b.effective_actual_micros || b.quality_score - a.quality_score || TYPES.indexOf(a.executor_type) - TYPES.indexOf(b.executor_type) || a.ref_digest.localeCompare(b.ref_digest));
  return immutable({schema: 'awe.e1.executor-choice/1', semantic_need: request.capability_id, decision: eligible.length ? 'SELECTED' : 'BLOCKED', selected: eligible[0] ?? null, candidates: reviews,
    rule: 'GRANT_DATA_QUALITY_HEALTH_GATE_THEN_API_DEBIT_QUALITY_DETERMINISTIC_TIEBREAK', dispatch_authorized: false, infrastructure_cost_comparison: 'NOT_MEASURED'});
}
