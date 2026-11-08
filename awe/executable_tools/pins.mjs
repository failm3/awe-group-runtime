import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {ensure,bytesDigest,digest,freeze,exact} from './protocol.mjs';
export const ROOT=fileURLToPath(new URL('../../',import.meta.url));
export const PINNED_FILES=['awe/executable_tools/protocol.mjs','awe/executable_tools/scope.mjs','awe/executable_tools/programs.mjs','awe/executable_tools/pins.mjs','awe/executable_tools/process.mjs','awe/executable_tools/verification.mjs','awe/executable_tools/host.mjs','awe/executable_tools/facade.mjs','awe/tool_registry/common.mjs','awe/policy/json.mjs','contracts/canonical.mjs','TOOLS-02/child-guard.cjs'];
export function loadPins(){
 const lock=JSON.parse(fs.readFileSync(path.join(ROOT,'TOOLS-02/runtime-lock.json'),'utf8'));
 exact(lock,['contract','node_version','files','binaries']);ensure(lock.contract==='tools02.runtime/1'&&lock.node_version===process.version,'TOOLS_RUNTIME_VERSION');
 ensure(JSON.stringify(lock.files.map(f=>f.path).sort())===JSON.stringify([...PINNED_FILES].sort()),'TOOLS_RUNTIME_FILES');
 exact(lock.binaries,['node','python','git']);ensure(fs.realpathSync(lock.binaries.node.path)===fs.realpathSync(process.execPath),'TOOLS_RUNTIME_NODE');
 return freeze(lock);
}
export function verifyPins(lock,binary){
 for(const f of lock.files){const p=path.join(ROOT,f.path);ensure(!fs.lstatSync(p).isSymbolicLink()&&bytesDigest(fs.readFileSync(p))===f.digest,'TOOLS_SOURCE_DRIFT');}
 const b=lock.binaries[binary];ensure(b&&path.isAbsolute(b.path)&&fs.realpathSync(b.path)===b.path&&bytesDigest(fs.readFileSync(b.path))===b.digest,'TOOLS_BINARY_DRIFT');return b.path;
}
export const runtimeDigest=lock=>digest(lock);
