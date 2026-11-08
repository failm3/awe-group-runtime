export {InfraError} from './errors.mjs';
export {INFRA_SCHEMA, COMPOSITION, RELEASE, SOURCE_COMMIT, E0_RUNTIME_COMMIT, PRINCIPAL_ROLES, LIVE_BLOCKERS,
  validateInfraConfig, loadInfraConfig, validateProjectId, normalizeOrigin, configScope, preflight, withLocalRoot} from './config.mjs';
export {LOCAL_ROOT, canonicalLocalPath, assertStorageRoot, assertScopedPath} from './paths.mjs';
export {createReleaseManifest, validateReleaseManifest, sanitizedStatus} from './manifest.mjs';
export {createScopedVault} from './vault.mjs';
export {createFixtureSupervisor, FIXTURE_CHILD_PATH, FIXTURE_GUARD_PATH} from './lifecycle.mjs';
export {createFixtureObjectStore} from './storage.mjs';
export {migrationPlan} from './migrations.mjs';
