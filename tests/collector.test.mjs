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
  it('collects evidence for suspicious fixture discovering on-disk fixture package files', async () => {
    const base = await loadProjectInputs(SUSPICIOUS_BASE, 'base');
    const head = await loadProjectInputs(SUSPICIOUS_HEAD, 'head');
    const diff = compareLockfiles(base.lockfile, head.lockfile);

    // Pass headDir so collector auto-discovers package-files/mock-telemetry-reporter/setup.js
    const evidence = await collectEvidence(diff, '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', {
      mode: 'fixture',
      headDir: SUSPICIOUS_HEAD,
      popularPackages: ['picocolors', 'express']
    });

    assert.equal(evidence.schemaVersion, '1.0');
    assert.equal(evidence.mode, 'fixture');
    assert.ok(evidence.observations.length > 0);

    const ruleIds = evidence.observations.map((o) => o.ruleId);
    assert.ok(ruleIds.includes('LIFECYCLE_SCRIPT_ADDED'));
    assert.ok(ruleIds.includes('ENVIRONMENT_ACCESS'));
    assert.ok(ruleIds.includes('NETWORK_OPERATION'));

    // Check that provenance metadata is preserved
    const suspiciousPkg = evidence.packages.find((p) => p.name === 'mock-telemetry-reporter');
    assert.ok(suspiciousPkg.provenance);
    assert.equal(suspiciousPkg.provenance.isSynthetic, true);
  });

  it('collects evidence for live public benign package with preserved provenance', async () => {
    const base = await loadProjectInputs(BENIGN_BASE, 'base');
    const head = await loadProjectInputs(BENIGN_HEAD, 'head');
    const diff = compareLockfiles(base.lockfile, head.lockfile);

    const evidence = await collectEvidence(diff, '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', {
      mode: 'live',
      popularPackages: ['lodash', 'express']
    });

    assert.equal(evidence.mode, 'live');
    assert.equal(evidence.collectionStatus, 'complete');

    // Confirm real source record was fetched from registry.npmjs.org
    const liveSource = evidence.sources.find((s) => s.sourceType === 'live');
    assert.ok(liveSource);
    assert.match(liveSource.pathOrUrl, /https:\/\/registry\.npmjs\.org\//);

    // Confirm provenance is preserved on ms package
    const msEntry = evidence.packages.find((p) => p.name === 'ms');
    assert.ok(msEntry);
    assert.ok(msEntry.provenance);
    assert.equal(typeof msEntry.provenance.maintainersCount, 'number');
    assert.ok(msEntry.provenance.publishedAt);
  });

  it('flags missing required integrity in lockfile as incomplete evidence', async () => {
    const diffWithoutIntegrity = {
      packages: [
        {
          name: 'missing-hash-pkg',
          location: 'node_modules/missing-hash-pkg',
          changeType: 'added',
          isDirect: true,
          integrity: null // Missing!
        }
      ]
    };

    const evidence = await collectEvidence(diffWithoutIntegrity, '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', {
      mode: 'fixture'
    });

    assert.equal(evidence.collectionStatus, 'incomplete');
    const missingObs = evidence.observations.find((o) => o.ruleId === 'UNSUPPORTED_OR_INCOMPLETE');
    assert.ok(missingObs);
    assert.match(missingObs.explanation, /Missing required integrity hash/);
  });

  it('flags artifact URL discrepancy between lockfile resolved URL and registry tarball URL', async () => {
    const diffDiscrepancy = {
      packages: [
        {
          name: 'ms',
          version: '2.1.3',
          location: 'node_modules/ms',
          changeType: 'added',
          isDirect: true,
          integrity: 'sha512-6FlzubTLZG3J2a/NVCAleEhjzq5oxgHyaCU9yYXvcLsvoVaHJq/s5xXI6/XXP6tz7R9xAOtHnSO/tXtF3WRTlA==',
          resolved: 'https://registry.yarnpkg.com/ms/-/ms-2.1.3.tgz' // Differs from registry.npmjs.org!
        }
      ]
    };

    const evidence = await collectEvidence(diffDiscrepancy, '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', {
      mode: 'live'
    });

    const discrepancyObs = evidence.observations.find((o) => o.ruleId === 'ARTIFACT_INTEGRITY_MISMATCH');
    assert.ok(discrepancyObs);
    assert.match(discrepancyObs.explanation, /does not match registry metadata tarball URL/);
  });
});
