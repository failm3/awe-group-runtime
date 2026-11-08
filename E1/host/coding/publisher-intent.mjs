import fs from 'node:fs';
import path from 'node:path';
import {digest, immutable, need} from '../../contracts/index.mjs';

/** Durable local intent only. There is deliberately no GitHub transport here. */
export function createLocalDraftIntentPublisher({directory}) {
  need(path.isAbsolute(directory), 'CODING_INTENT_DIRECTORY');
  fs.mkdirSync(directory, {recursive: true});
  need(!fs.lstatSync(directory).isSymbolicLink() && fs.realpathSync(directory) === path.resolve(directory), 'CODING_INTENT_DIRECTORY');
  return Object.freeze({kind: 'SCOPED_DRAFT_PR_INTENT_PUBLISHER', mode: 'LIVE_SCOPED_HOST', async prepareDraftIntent({intent, intent_digest, qa}) {
    need(digest(intent) === intent_digest && qa.verdict === 'PASS' && intent.qa_digest === digest(qa) && intent.draft === true && intent.automatic_merge === false && intent.production_release === false, 'CODING_INTENT_SCOPE');
    const filename = path.join(directory, intent_digest.slice(7) + '.json');
    const record = immutable({schema: 'awe.e1.local-draft-intent/1', status: 'DRAFT_PR_INTENT', intent, intent_digest, qa, external_mutations: 0});
    if (fs.existsSync(filename)) need(fs.lstatSync(filename).isFile() && !fs.lstatSync(filename).isSymbolicLink() && digest(JSON.parse(fs.readFileSync(filename, 'utf8'))) === digest(record), 'CODING_INTENT_CONFLICT');
    else fs.writeFileSync(filename, JSON.stringify(record, null, 2) + '\n', {flag: 'wx', mode: 0o600});
    need(digest(JSON.parse(fs.readFileSync(filename, 'utf8'))) === digest(record), 'CODING_INTENT_READBACK');
    return immutable({status: record.status, intent_digest, external_mutations: 0});
  }});
}
