import {scenarios, runScenario} from './scenarios.mjs';
const results = [];
for (const scenario of scenarios) results.push(await runScenario(scenario));
console.log(JSON.stringify({schema_version: 'd05-acceptance-v1', results}, null, 2));
