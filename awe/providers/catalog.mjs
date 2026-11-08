// Evidence overlay: observations from submitted C, NOT live account eligibility.
export const FINOPS_SOURCE = 'baseline/sources/sources/AWE-GROUP-AUDITS/C-Tools/FINOPS-PROVIDERS.md';
export const providerEvidence = Object.freeze({
  'router.cheap': Object.freeze({role: 'INFERENCE_SELLER_OR_INTERMEDIARY_UNKNOWN', tariff: 'UNKNOWN', fees: 'UNKNOWN',
    context: 'UNKNOWN', compatibility: 'UNKNOWN', eligibility: 'UNKNOWN', region: 'UNKNOWN', privacy: 'UNKNOWN'}),
  OpenRouter: Object.freeze({role: 'INFERENCE_SELLER_OR_BYOK_GATEWAY', tariff: 'ACCOUNT_QUOTE_UNKNOWN', fees: 'ACCOUNT_FEES_UNKNOWN',
    compatibility: 'NOT_RUN', eligibility: 'UNKNOWN', region: 'UNKNOWN', privacy: 'ACCOUNT_POLICY_UNKNOWN'}),
  Requesty: Object.freeze({role: 'INFERENCE_SELLER_OR_BYOK_GATEWAY', tariff: 'MODEL_QUOTE_UNKNOWN', fees: 'MARKUP_VS_TOPUP_UNRESOLVED',
    compatibility: 'NOT_RUN', eligibility: 'UNKNOWN', region: 'UNKNOWN', privacy: 'ACCOUNT_POLICY_UNKNOWN'}),
  direct: Object.freeze({role: 'DIRECT_INFERENCE_SELLER', tariff: 'ACCOUNT_QUOTE_UNKNOWN', fees: 'TAX_FX_UNKNOWN',
    compatibility: 'NOT_RUN', eligibility: 'UNKNOWN', region: 'UNKNOWN', privacy: 'ACCOUNT_POLICY_UNKNOWN'})
});
