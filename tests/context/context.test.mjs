import test from 'node:test';
import {scenarios, runScenario} from './scenarios.mjs';
for (const scenario of scenarios) test(`${scenario.id} ${scenario.expected}`, async () => { await runScenario(scenario); });
