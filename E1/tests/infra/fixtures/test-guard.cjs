'use strict';
// Only the C1 fixed fixture is allowed to fork; there is no database/model path.
const nativeFork = require('node:child_process').fork;
require('../../../infra/fixture-guard.cjs');
const path = require('node:path');
const Module = require('node:module');
const cp = require('node:child_process');
const childPath = path.resolve(__dirname, '../../../infra/fixture-worker.mjs');
const guardPath = path.resolve(__dirname, '../../../infra/fixture-guard.cjs');
cp.fork = (filename, args, options) => {
  if (filename !== childPath || !Array.isArray(args) || args.length || options?.execPath !== process.execPath ||
      JSON.stringify(options.execArgv) !== JSON.stringify(['--require', guardPath]) || options.windowsHide !== true ||
      options.env?.AWE_E1_FIXTURE !== '1' || Object.keys(options.env).some(key => !['AWE_E1_FIXTURE', 'SystemRoot'].includes(key))) throw new Error('C1_TEST_PROCESS_DISABLED');
  return nativeFork(filename, args, options);
};
Module.syncBuiltinESMExports();
