import fs from 'node:fs';
import {createPsqlSession,applyCoordinatorMigrations} from '../coordinator/index.mjs';
if(process.argv[2]!=='--authorized-e1-only'||process.argv.length!==4)throw Error('Pass --authorized-e1-only and the host-owned resource descriptor path');
const file=process.argv[3],st=fs.lstatSync(file);if(!st.isFile()||st.isSymbolicLink()||st.size>65536)throw Error('E1_RESOURCE_FILE');
const db=await createPsqlSession(JSON.parse(fs.readFileSync(file,'utf8')),{role:'admin',verify_marker:false});
try{console.log(JSON.stringify({schema:'awe.e1.migration-run/1',resource_id:db.resource_id,migrations:await applyCoordinatorMigrations(db),external_effects:0}));}finally{await db.close();}
