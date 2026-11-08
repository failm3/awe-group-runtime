import {bytesHash, copy, digest, need} from './common.mjs';

// CR-D08-02: existing D07 scoped reader, checked against a host-bound current descriptor.
// The token/readHead closures belong to the host. No arbitrary URL/path/tool execution.
export function createD07ArtifactReader({artifacts, token, readHead}) {
  return Object.freeze({read(reference) {
    const head=readHead(); need(head && !head.then && digest(head)===digest(reference),'ARTIFACT_STALE');
    const response=artifacts.read(token,JSON.stringify({artifact_id:reference.artifact.artifact_id,
      version:reference.version,path:reference.path}));
    need(response?.ok===true,'ARTIFACT_UNAVAILABLE');
    const value=response.value,bytes=Buffer.from(value.bytes_base64,'base64');
    need(digest(value.artifact)===digest(reference.artifact) && value.version===reference.version && value.path===reference.path
      && bytes.length===reference.bytes && bytesHash(bytes)===reference.file_hash,'ARTIFACT_CHANGED');
    return bytes;
  }});
}

export function createInt02EvidenceReader({readChain,readCompletion,readModelOperation,readSources=()=>[],readOpinions=()=>null}) {
  return Object.freeze({read() {
    const e={chain:readChain(),completion:readCompletion(),model_operation:readModelOperation(),sources:readSources(),opinions:readOpinions()};
    need(Object.values(e).every(v=>!v?.then),'SYNC_EVIDENCE_REQUIRED');return copy(e);
  }});
}
