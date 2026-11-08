import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {assertRgaDependencySearchPaths} from '../../tooling/local-execution.mjs';

test('RGA rejects rg.exe in both prepended search directories without executing either file', () => {
  const folder = fs.mkdtempSync(path.join(os.tmpdir(), 'awe-rga-shadow-')), tool = path.join(folder, 'rga.exe'), lib = path.join(folder, 'lib');
  fs.mkdirSync(lib); fs.writeFileSync(tool, 'OFFLINE NONEXECUTABLE FIXTURE');
  try {
    assert.doesNotThrow(() => assertRgaDependencySearchPaths(tool));
    for (const directory of [folder, lib]) {
      const shadow = path.join(directory, 'rg.exe'); fs.writeFileSync(shadow, 'UNVERIFIED DEPENDENCY FIXTURE');
      assert.throws(() => assertRgaDependencySearchPaths(tool), /TOOL_DEPENDENCY_SHADOW/); fs.unlinkSync(shadow);
    }
  } finally { fs.unlinkSync(tool); fs.rmdirSync(lib); fs.rmdirSync(folder); }
});
