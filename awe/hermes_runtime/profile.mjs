import {readFileSync,mkdirSync,writeFileSync,lstatSync,existsSync,realpathSync} from 'node:fs';
import {resolve,join,relative,isAbsolute} from 'node:path';
import {fileURLToPath} from 'node:url';
import {digest,need,same,freeze} from './protocol.mjs';
export const sourceRoot=fileURLToPath(new URL('../../',import.meta.url));
export const profile=freeze(JSON.parse(readFileSync(new URL('./profile.json',import.meta.url),'utf8')));
const config=readFileSync(new URL('./config.yaml',import.meta.url),'utf8');
const sourceLock=JSON.parse(readFileSync(new URL('./hermes-source-lock.json',import.meta.url),'utf8'));
export const configHash=digest({profile,hermes_config:config});
export const manifestHash=digest({hermes:profile.hermes,source_lock:sourceLock,protocol:'rt01/1'});
// No user-selectable config override can enable E1 dispatch.
export function requireOffline(p=profile){need(same(p,profile)&&p.mode==='E0_OFFLINE'&&p.physical_decision==='DENY','PROFILE_NOT_ADMITTED');}
export function bootstrap(destination) {
 requireOffline();need(process.version==='v24.21.0','PINNED_NODE_REQUIRED');
 const allowed=realpathSync(join(sourceRoot,'RT-01')),target=resolve(destination),rel=relative(allowed,target);
 need(rel!==''&&!rel.startsWith('..')&&!isAbsolute(rel),'PROFILE_PATH_DENIED');
 let cursor=allowed;
 for(const part of rel.split(/[\\/]/)){cursor=join(cursor,part);if(existsSync(cursor))need(!lstatSync(cursor).isSymbolicLink(),'PROFILE_LINK_DENIED');}
 need(!existsSync(target),'CLEAN_PROFILE_REQUIRED');mkdirSync(target,{recursive:true});
 const files={'config.yaml':config,'profile.json':JSON.stringify(profile,null,2)+'\n','hermes-source-lock.json':JSON.stringify(sourceLock,null,2)+'\n','environment.json':JSON.stringify(cleanEnvironment(target),null,2)+'\n','pins.json':JSON.stringify({configHash,manifestHash},null,2)+'\n'};
 for(const [name,body]of Object.entries(files))writeFileSync(join(target,name),body,{flag:'wx'});
 return freeze({mode:profile.mode,target,configHash,manifestHash,real_hermes:'REAL_HERMES_NOT_RUN',physical_decision:'DENY'});
}
export function cleanEnvironment(home) {
 // An allowlist constructed from scratch. No PATH, credentials, proxies, Python
 // site config, NODE_OPTIONS, inherited Hermes profile, or mutable global caches.
 const root=resolve(home);
 return {HERMES_HOME:root,HERMES_CONFIG:join(root,'config.yaml'),HOME:root,USERPROFILE:root,
 XDG_CACHE_HOME:join(root,'cache'),UV_CACHE_DIR:join(root,'cache/uv'),PIP_CACHE_DIR:join(root,'cache/pip'),
 PYTHONNOUSERSITE:'1',PYTHONDONTWRITEBYTECODE:'1',UV_OFFLINE:'1',PIP_NO_INDEX:'1',TZ:'UTC',AWE_PHYSICAL_DECISION:'DENY'};
}
