import {jointFixture} from './harness.mjs';
console.log(JSON.stringify(await (await jointFixture()).workflow(),null,2));
