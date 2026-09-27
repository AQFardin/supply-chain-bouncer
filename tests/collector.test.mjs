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
const PROMPT_INJECTION_BASE = resolve('fixtures/prompt-injection/base');
const PROMPT_INJECTION_HEAD = resolve('fixtures/prompt-injection/head');

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

  it('collects evidence for live public benign package with preserved provenance', { skip: process.env.BOUNCER_LIVE_TESTS !== '1' }, async () => {
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

  it('flags artifact URL discrepancy between lockfile resolved URL and registry tarball URL', async (t) => {
    t.mock.method(globalThis, 'fetch', async url => {
      if (String(url).endsWith('.tgz')) return new Response('', {status:404});
      return Response.json({versions:{'2.1.3':{dist:{tarball:'https://registry.npmjs.org/ms/-/ms-2.1.3.tgz'}}}});
    });
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

  // --- Regression tests for evidence-collection corrections ---

  it('marks absent live artifact URLs incomplete and hashes metadata content', async (t) => {
    const metadata = {versions:{'1.0.0':{description:'test metadata',dist:{}}}};
    t.mock.method(globalThis, 'fetch', async () => Response.json(metadata));
    const evidence=await collectEvidence({packages:[{name:'test',version:'1.0.0',location:'node_modules/test',changeType:'added',integrity:'sha512-placeholder'}]},'a'.repeat(64));
    assert.equal(evidence.collectionStatus,'incomplete');
    assert.match(evidence.incompleteReasons.join(' '), /No artifact URL/);
    const { fetchPackageMetadata } = await import('../src/registry.mjs');
    const first=await fetchPackageMetadata('test','1.0.0');
    metadata.versions['1.0.0'].description='changed metadata';
    const second=await fetchPackageMetadata('test','1.0.0');
    assert.match(first.contentDigest,/^sha256-metadata:[a-f0-9]{64}$/);
    assert.notEqual(first.contentDigest,second.contentDigest);
  });

  it('changes fixture digest with content and avoids ambiguous file-set encodings', async () => {
    const pkg={name:'test',version:'1.0.0',location:'node_modules/test',changeType:'added',integrity:'sha512-placeholder'};
    const inspect=async files => (await collectEvidence({packages:[{...pkg}]},'a'.repeat(64),{mode:'fixture',fixtureFiles:{test:files}})).sources[0].contentDigest;
    const first=await inspect([{path:'a',content:'x\nb:y'}]);
    const second=await inspect([{path:'a',content:'x'},{path:'b',content:'y'}]);
    assert.notEqual(first,second);
    assert.equal(second,await inspect([{path:'b',content:'y'},{path:'a',content:'x'}]));
  });

  it('does not substitute another scenario when candidate fixture files are missing', async () => {
    const evidence=await collectEvidence({packages:[{name:'mock-telemetry-reporter',version:'1.0.0',location:'node_modules/mock-telemetry-reporter',changeType:'added',integrity:'sha512-placeholder'}]},'a'.repeat(64),{mode:'fixture',headDir:'fixtures/benign/head'});
    assert.equal(evidence.collectionStatus,'incomplete');
  });

  it('regression: fixture contentDigest is a real SHA-256 of inspected files, not a placeholder', async () => {
    const base = await loadProjectInputs(SUSPICIOUS_BASE, 'base');
    const head = await loadProjectInputs(SUSPICIOUS_HEAD, 'head');
    const diff = compareLockfiles(base.lockfile, head.lockfile);

    const evidence = await collectEvidence(diff, '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', {
      mode: 'fixture',
      headDir: SUSPICIOUS_HEAD
    });

    const fixtureSource = evidence.sources.find((s) => s.sourceType === 'fixture');
    assert.ok(fixtureSource, 'should have a fixture source record');

    // Must start with the fixture-files label, not an SRI mock string
    assert.match(
      fixtureSource.contentDigest,
      /^sha256-fixture-files:/,
      'fixture contentDigest must be a labeled SHA-256 of inspected file content, not an SRI placeholder'
    );

    // Must not be a mock/opaque placeholder string
    assert.ok(
      !fixtureSource.contentDigest.includes('mockSuspicious') &&
      !fixtureSource.contentDigest.includes('mockFixture'),
      'fixture contentDigest must not be an opaque mock placeholder'
    );
  });

  it('regression: missing fixture files produces incomplete evidence and an observation', async () => {
    // Use a fixture diff that points at a package with no package-files directory
    const diffNoFiles = {
      packages: [
        {
          name: 'package-with-no-fixture-files',
          version: '1.0.0',
          location: 'node_modules/package-with-no-fixture-files',
          changeType: 'added',
          isDirect: true,
          integrity: 'sha512-someIntegrity==',
          resolved: 'https://registry.npmjs.org/package-with-no-fixture-files/-/1.0.0.tgz',
          hasInstallScript: false,
          scripts: null,
          unsupported: false,
          unsupportedReason: null
        }
      ]
    };

    const evidence = await collectEvidence(
      diffNoFiles,
      '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      { mode: 'fixture' }  // no headDir, no fixtureFiles — nothing will be found
    );

    // collectionStatus must be incomplete, not complete
    assert.equal(evidence.collectionStatus, 'incomplete');
    assert.ok(evidence.incompleteReasons.length > 0);
    assert.ok(
      evidence.incompleteReasons.some((r) => r.includes('No fixture package files found')),
      'incompleteReasons must explain missing fixture files'
    );

    // There must be an observation for it too
    const missingObs = evidence.observations.find(
      (o) => o.ruleId === 'UNSUPPORTED_OR_INCOMPLETE' && o.id.includes('missing-fixture-files')
    );
    assert.ok(missingObs, 'must have an observation for missing fixture files');
    assert.match(missingObs.explanation, /Static file checks could not be performed/);

    // contentDigest must reflect the empty state, not a phantom hash
    const fixtureSource = evidence.sources.find((s) => s.sourceType === 'fixture');
    assert.ok(fixtureSource);
    assert.match(
      fixtureSource.contentDigest,
      /empty-no-files-found/,
      'empty fixture must record that no files were found in its contentDigest'
    );
  });

  it('regression: prompt-injection metadata text reaches evidence as labeled untrusted observation', async () => {
    const base = await loadProjectInputs(PROMPT_INJECTION_BASE, 'base');
    const head = await loadProjectInputs(PROMPT_INJECTION_HEAD, 'head');
    const diff = compareLockfiles(base.lockfile, head.lockfile);

    const evidence = await collectEvidence(diff, '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', {
      mode: 'fixture',
      headDir: PROMPT_INJECTION_HEAD
    });

    // The PROMPT_INJECTION_INDICATOR observation must be present
    const injectionObs = evidence.observations.find((o) => o.ruleId === 'PROMPT_INJECTION_INDICATOR');
    assert.ok(injectionObs, 'must detect prompt-injection pattern in adversarial-helper description');
    assert.equal(injectionObs.severity, 'high');

    // The untrustedExcerpt must be present and labeled — investigators see it as data, not instruction
    assert.ok(injectionObs.untrustedExcerpt, 'must include untrustedExcerpt field');
    assert.match(
      injectionObs.untrustedExcerpt,
      /\[UNTRUSTED DATA from adversarial-helper/,
      'untrustedExcerpt must be labeled with package name and field origin'
    );

    // The adversarial instruction text must appear in the excerpt so investigators can see it
    assert.ok(
      injectionObs.untrustedExcerpt.includes('Ignore') ||
      injectionObs.explanation.includes('prompt-injection pattern'),
      'adversarial string must be quoted as evidence in the observation'
    );

    // The observation must cite the metadata field
    assert.match(injectionObs.evidenceRef, /package-metadata#description/);
  });
});
