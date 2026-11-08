const actionPins=new Set(['actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683','actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020']);
export function inspectWorkflow(source) {
 const errors=[];
 const uses=[...source.matchAll(/uses:\s*([^\s#]+)/g)].map(m=>m[1]);
 if(uses.length!==2||uses.some(x=>!actionPins.has(x))) errors.push('UNPINNED_OR_UNKNOWN_ACTION');
 if(/secrets\s*[.\[]|pull_request_target|environment\s*:|write-all|id-token|deploy|curl |wget |npm (install|ci)|npx /i.test(source)) errors.push('FORBIDDEN_CI_CAPABILITY');
 if(!source.includes('persist-credentials: false')||!source.includes('contents: read')) errors.push('CI_PERMISSION_BOUNDARY');
 if(!source.includes('AWE_OFFLINE=1 node baseline/run-checks.mjs')) errors.push('OFFLINE_JOB_REQUIRED');
 const jobNames=[...(source.split('\njobs:\n')[1]??'').matchAll(/^  ([a-z][a-z0-9-]+):$/gm)].map(m=>m[1]);
 if(jobNames.length!==1||jobNames[0]!=='contracts-baseline') errors.push('ONLY_D01_JOB_ALLOWED');
 return errors;
}
export function inspectDependencies(pkg,lock,sbom) {
 const errors=[];
 if(Object.keys(pkg.dependencies??{}).length||Object.keys(pkg.devDependencies??{}).length||Object.keys(pkg.optionalDependencies??{}).length) errors.push('DEPENDENCY_PROPOSAL_REQUIRED');
 if(Object.keys(lock.packages??{}).join(',')!=='') errors.push('LOCK_CONTAINS_DEPENDENCY');
 if(pkg.version!==lock.version||pkg.engines.node!=='24.21.0') errors.push('VERSION_DRIFT');
 if(sbom.bomFormat!=='CycloneDX'||sbom.version!==1||sbom.metadata.component.version!==pkg.version||sbom.components.length!==0) errors.push('SBOM_DRIFT');
 return errors;
}
export function detectSyntheticSecret(text) {
 // Small offline regression detector, not a general credential scanner.
 return new RegExp('AWE_'+'TEST_'+'SECRET_[A-Z0-9]{16,}').test(text)||/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/.test(text);
}
export function allowedPath(path) {
 return /^(contracts\/|baseline\/|tests\/contracts\/|\.github\/workflows\/ci[.]yml$)/.test(path)
  || ['README.md','package.json','package-lock.json','.npmrc','.node-version','.gitignore','.gitattributes'].includes(path);
}
