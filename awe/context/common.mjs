import {createHash} from 'node:crypto';
import {canonicalize, digest} from '../../contracts/canonical.mjs';

export {canonicalize, digest};
export const copy = value => JSON.parse(canonicalize(value));
export const bytesHash = bytes => 'sha256:' + createHash('sha256').update(bytes).digest('hex');
export const integer = value => Number.isSafeInteger(value) && value >= 0 && !Object.is(value, -0);
export function requireThat(condition, code) { if (!condition) throw new ContextError(code); }
export class ContextError extends Error {
  constructor(code) { super(code); this.code = code; }
}
const explanations = {
  CONTEXT_TOO_LARGE: ['Контекст превышает доступный бюджет.', 'Сократите необязательную историю или разделите задачу.'],
  PIN_SET_TOO_LARGE: ['Обязательные требования не помещаются.', 'Разделите задачу с сохранением критериев; требуется согласование.'],
  PROFILE_UNKNOWN: ['Параметры модели не подтверждены.', 'Проверьте профиль модели и правила подсчёта.'],
  TOKEN_COUNT_UNCERTAIN: ['Неизвестна верхняя граница оценки токенов.', 'Нужен проверенный адаптер подсчёта.'],
  RETRY_EXHAUSTED: ['Лимит повторов исчерпан.', 'Проверьте исходную ошибку и запросите решение владельца.'],
  OUTCOME_UNKNOWN: ['Результат операции неизвестен.', 'Сверьте операцию по прежнему идентификатору; повтор запрещён.'],
  PERMISSION_REVOKED: ['Доступ или версия контекста изменились.', 'Получите актуальное состояние и заново соберите контекст.']
};
export function failure(code, decision = 'DENY', refs = {}) {
  const [message_ru, next_action_ru] = explanations[code] ?? ['Сборка контекста остановлена: ' + code + '.', 'Проверьте доступные свидетельства и устраните причину.'];
  return {decision, code, physical_decision: 'DENY', message_ru, next_action_ru,
    actual_usage: null, actual_cost_micros: null, ...refs};
}
export function safeFailure(error) {
  const code = error instanceof ContextError ? error.code : error instanceof TypeError ? 'INPUT_INVALID' : 'DEPENDENCY_UNAVAILABLE';
  return failure(code, ['PROFILE_UNKNOWN', 'TOKEN_COUNT_UNCERTAIN', 'DEPENDENCY_UNAVAILABLE', 'PRICE_UNKNOWN'].includes(code) ? 'WAIT' : 'DENY');
}
export const scopeKey = state => digest({project_id: state.project_id, task_id: state.task_id,
  actor_id: state.actor_id, role: state.role, purpose: state.purpose});
export const authorityHash = state => digest(state);
