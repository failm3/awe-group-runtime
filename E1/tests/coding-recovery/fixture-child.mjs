import fs from 'node:fs';
import {createRecoverableModelPort} from '../../host/coding/recovery.mjs';
import {confirmed, modelPort, modelArgs, now} from './fixtures.mjs';
const config = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const state = JSON.parse(fs.readFileSync(config.state, 'utf8'));
const wrapped = createRecoverableModelPort({directory: config.directory, project_id: 'fixture_project', readNativeState: async () => state, clock: () => now,
  modelPort: modelPort(async () => { const result = confirmed(state); fs.writeFileSync(config.state, JSON.stringify(state)); return result; }),
  onModelPersisted() { process.exit(90); }});
await wrapped.proposePatch(modelArgs());
process.exit(91);
