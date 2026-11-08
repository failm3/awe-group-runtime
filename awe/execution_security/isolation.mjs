import {isIP} from 'node:net';
import {need,freeze,copy,digest} from './common.mjs';
export function relativePath(path){
 need(typeof path==='string'&&path.length<=240&&/^[a-zA-Z0-9_/-]+(?:\.[a-zA-Z0-9_-]+)?$/.test(path),'PATH_DENIED');
 need(!path.startsWith('/')&&path.split('/').every(p=>p&&p!=='.'&&p!=='..'&&!/^(con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\.|$)/i.test(p)),'PATH_DENIED');return path;
}
export function destination(url,domains){
 need(typeof url==='string'&&url.length<=2048&&/^https:\/\/[a-z0-9.-]+(?:\/[^\\\s#]*)?$/.test(url),'DESTINATION_DENIED');
 const u=new URL(url);need(!u.username&&!u.password&&!u.port&&!isIP(u.hostname)&&domains.includes(u.hostname),'DESTINATION_DENIED');
 need(!['localhost','metadata.google.internal'].includes(u.hostname)&&!u.hostname.endsWith('.local'),'DESTINATION_DENIED');return u.hostname;
}
/** Compiler for a future disposable sandbox, not an OS sandbox or launch API. */
export function compileIsolation(manifest,payload){
 for(const p of manifest.paths)relativePath(p);
 if(Object.hasOwn(payload,'path'))need(manifest.paths.includes(relativePath(payload.path)),'PATH_SCOPE_DENIED');
 if(Object.hasOwn(payload,'url'))destination(payload.url,manifest.domains);
 return freeze({profile:'SEC01_ISOLATION_V1',mode:'E0_OFFLINE',launch_authorized:false,physical_decision:'DENY',manifest_hash:digest(manifest),
  filesystem:{project_id:manifest.project_id,relative_paths:copy(manifest.paths),symlinks:'DENY',reparse_points:'DENY',host_mounts:[],resolver:'BROKER_OPEN_HANDLE_NOFOLLOW_REQUIRED'},
  process:{uid:'DEDICATED_UNPRIVILEGED_PER_PROJECT',shell:'DENY',spawn:'DENY',packages:'DENY',host_ipc:'DENY',resource_limits:'REQUIRED_BEFORE_E1'},
  network:{default:'DENY',direct_dns:'DENY',ipv6:'DENY',browser:'DENY',proxy_env:'DENY',domains:copy(manifest.domains),broker:'PINNED_PUBLIC_IP_TLS_NO_REDIRECT_REQUIRED'},
  secrets:{model_context:'DENY',logs:'DENY',injection:'TRUSTED_EXECUTOR_ONLY'}});
}
