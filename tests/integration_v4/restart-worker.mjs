import fs from 'node:fs';
import path from 'node:path';
import {restoreCheckpoint} from '../../awe/integration_v4/checkpoint.mjs';
const directory=fs.realpathSync(process.argv[2]),root=fs.realpathSync('INT-04/sandbox');
if(!directory.startsWith(root+path.sep))throw Error('RESTORE_PATH_DENIED');
const r=restoreCheckpoint(directory),task=r.storage.read(db=>db.projects.prj_alpha.tasks.task_one);
process.stdout.write(JSON.stringify({recovery:r.recovery,resumable:r.resumable,accepted:r.accepted,restore_pending:task.restore_pending,
 ledger_recovery:r.ledger.inspect().recoveryRequired,operation:r.ledger.operation('op-one'),bundle_hash:r.checkpoint.bundle?.reference.file_hash??null,physical_decision:'DENY'})+'\n');
