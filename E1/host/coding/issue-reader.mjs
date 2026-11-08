import {digest, immutable, need, exact} from '../../contracts/index.mjs';

/** A host-authenticated snapshot is intentionally labelled as a snapshot, not
 * as evidence of live GitHub API ingestion. No worker-supplied text is read. */
export function createIssueReader({snapshot, expectedDigest}) {
  exact(snapshot, ['repository', 'issue_number', 'title', 'body']);
  const pinned = immutable({...snapshot, digest: digest(snapshot)});
  need(pinned.digest === expectedDigest, 'CODING_BRIEF_PIN');
  need(typeof pinned.title === 'string' && pinned.title.length <= 512 && typeof pinned.body === 'string' && Buffer.byteLength(pinned.body) <= 16384, 'CODING_BRIEF_BOUND');
  return Object.freeze({kind: 'SCOPED_GITHUB_ISSUE_READER', mode: 'LIVE_SCOPED_HOST', input_origin: 'SNAPSHOT_INPUT',
    async readIssue({repository, issue_number}) {
      need(digest(repository) === digest(pinned.repository) && issue_number === pinned.issue_number, 'CODING_ISSUE_SCOPE');
      need(digest(snapshot) === expectedDigest, 'CODING_BRIEF_CHANGED');
      return pinned;
    }
  });
}
