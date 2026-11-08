import {spawn} from 'node:child_process';
import {randomUUID} from 'node:crypto';
import {canonicalize} from '../contracts/index.mjs';
import {CoordinatorError, check} from './errors.mjs';
import {psqlInvocation} from './resource.mjs';

export const sqlJson = value => "convert_from(decode('" + Buffer.from(canonicalize(value), 'utf8').toString('hex') + "','hex'),'UTF8')::jsonb";

/** One real psql process and PostgreSQL backend per session. Commands are queued;
 * transaction() keeps BEGIN/operations/COMMIT on that same backend. No shell,
 * password environment, reconnect or automatic retry is involved. Transport loss
 * is ambiguous and callers must reconcile persisted state before continuing.
 */
export async function createPsqlSession(descriptor, {role = 'coordinator', timeout_ms = 15000, verify_marker = true} = {}) {
  const invocation = psqlInvocation(descriptor, role);
  check(Number.isSafeInteger(timeout_ms) && timeout_ms >= 100 && timeout_ms <= 120000, 'A2_DB_TIMEOUT');
  const child = spawn(invocation.executable, invocation.args, {stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true, env: {SystemRoot: process.env.SystemRoot, WINDIR: process.env.WINDIR, PATH: process.env.PATH, WSL_UTF8: '1'}});
  let buffer = '', stderr = '', pending = null, closed = false, failure = null, chain = Promise.resolve();
  const fail = error => { failure = error; closed = true; if (pending) { const current = pending; pending = null; clearTimeout(current.timer); current.reject(error); } };
  child.stderr.on('data', bytes => { stderr = (stderr + bytes.toString('utf8')).slice(-8192); });
  child.on('error', () => fail(new CoordinatorError('A2_DB_SPAWN')));
  child.on('exit', code => fail(new CoordinatorError('A2_DB_TRANSPORT_UNKNOWN', {exit_code: code, database_error: /A2_[A-Z_]+/.exec(stderr)?.[0] ?? null})));
  child.stdout.on('data', bytes => {
    buffer += bytes.toString('utf8');
    if (buffer.length > 4 * 1024 * 1024) { fail(new CoordinatorError('A2_DB_OUTPUT_LIMIT')); child.kill(); return; }
    let end;
    while ((end = buffer.indexOf('\n')) !== -1) {
      const line = buffer.slice(0, end).replace(/\r$/, ''); buffer = buffer.slice(end + 1);
      const request = pending; if (!request) continue;
      if (line === request.start) { request.started = true; continue; }
      if (line === request.end) { pending = null; clearTimeout(request.timer); request.resolve(request.lines.join('\n')); continue; }
      if (request.started) request.lines.push(line);
    }
  });
  async function raw(sql) {
    check(!closed && !pending, failure?.code ?? 'A2_DB_CLOSED');
    const id = randomUUID().replaceAll('-', ''), start = 'A2_BEGIN_' + id, end = 'A2_END_' + id;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { fail(new CoordinatorError('A2_DB_TIMEOUT_UNKNOWN')); child.kill(); }, timeout_ms);
      pending = {start, end, resolve, reject, timer, lines: [], started: false};
      child.stdin.write('\\echo ' + start + '\n' + sql + '\n\\echo ' + end + '\n', error => { if (error) fail(new CoordinatorError('A2_DB_WRITE_UNKNOWN')); });
    });
  }
  function queue(fn) { const result = chain.then(fn); chain = result.catch(() => {}); return result; }
  function parse(text) { const lines = text.split('\n').filter(Boolean); check(lines.length === 1, 'A2_DB_RESULT_FRAME'); try { return JSON.parse(lines[0]); } catch { throw new CoordinatorError('A2_DB_RESULT_JSON'); } }
  async function command(op, value) { check(/^[a-z_]+$/.test(op), 'A2_DB_OPERATION'); const result = parse(await raw("SELECT awe_e1_runtime.cloud_command('" + op + "'," + sqlJson(value) + ');')); if (result?.error) throw new CoordinatorError(result.error); return result; }
  const session = {
    kind: 'NATIVE_POSTGRESQL_PSQL_SESSION', role, resource_id: invocation.resource.resource_id,
    query(sql) { check(typeof sql === 'string' && sql.length <= 2 * 1024 * 1024, 'A2_SQL_LIMIT'); return queue(() => raw(sql)); },
    command(op, value) { return queue(() => command(op, value)); },
    quiesceLocalModel(value) { return queue(async()=>{const result=parse(await raw('SELECT awe_e1_runtime.quiesce_local_model('+sqlJson(value)+');'));if(result?.error)throw new CoordinatorError(result.error);return result;}); },
    provisionCloudBudget(value) { return queue(async()=>{const result=parse(await raw('SELECT awe_e1_runtime.provision_cloud_budget('+sqlJson(value)+');'));if(result?.error)throw new CoordinatorError(result.error);return result;}); },
    transaction(callback) { return queue(async () => {
      await raw('BEGIN;');
      try { const value = await callback({query: raw, command}); await raw('COMMIT;'); return value; }
      catch (error) { if (!closed) { try { await raw('ROLLBACK;'); } catch {} } throw error; }
    }); },
    async close() { await chain; if (!closed) { closed = true; child.stdin.end('\\quit\n'); } },
    abort() { child.kill(); }
  };
  try {
    const identity = parse(await raw("SELECT jsonb_build_object('database',current_database(),'role',session_user,'port',current_setting('port')::int,'version',current_setting('server_version_num')::int);"));
    check(identity.database === invocation.resource.database && identity.role === invocation.resource.roles[role].database_role && identity.port === 5433 && identity.version >= 180000 && identity.version < 190000, 'A2_DB_IDENTITY');
    if (verify_marker) {
      const marker = parse(await raw("SELECT awe_e1_runtime.resource_info();"));
      check(marker.resource_id === invocation.resource.resource_id && marker.pgdata === invocation.resource.pgdata && marker.socket_directory === invocation.resource.socket_directory, 'A2_DB_RESOURCE_MARKER');
    }
    return Object.freeze(session);
  } catch (error) { child.kill(); throw error; }
}
