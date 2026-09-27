import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { resolve, join } from 'node:path';
import { writeFile, rm, mkdir } from 'node:fs/promises';
import { computeFileSha256, computeSubjectDigest, loadProjectInputs } from '../src/input.mjs';

const SAMPLE_APP_DIR = resolve('examples/sample-app');
const BENIGN_BASE_DIR = resolve('fixtures/benign/base');
const BENIGN_HEAD_DIR = resolve('fixtures/benign/head');

describe('Input Loader & Hasher Tests', () => {
  it('computes sha256 of an existing file accurately', async () => {
    const hash = await computeFileSha256(join(SAMPLE_APP_DIR, 'package.json'));
    assert.match(hash, /^[a-f0-9]{64}$/);
  });

  it('returns null when computing sha256 of a non-existent file', async () => {
    const hash = await computeFileSha256(join(SAMPLE_APP_DIR, 'non-existent-file.json'));
    assert.equal(hash, null);
  });

  it('computes deterministic subjectDigest for base and head directories', async () => {
    const res1 = await computeSubjectDigest(BENIGN_BASE_DIR, BENIGN_HEAD_DIR);
    const res2 = await computeSubjectDigest(BENIGN_BASE_DIR, BENIGN_HEAD_DIR);

    assert.equal(res1.subjectDigest, res2.subjectDigest);
    assert.match(res1.subjectDigest, /^[a-f0-9]{64}$/);
    assert.equal(res1.inputs.length, 4);
  });

  it('changes subjectDigest if candidate files differ', async () => {
    const resBaseHead = await computeSubjectDigest(BENIGN_BASE_DIR, BENIGN_HEAD_DIR);
    const resBaseBase = await computeSubjectDigest(BENIGN_BASE_DIR, BENIGN_BASE_DIR);

    assert.notEqual(resBaseHead.subjectDigest, resBaseBase.subjectDigest);
  });

  it('loads valid project inputs successfully with lockfileVersion 3', async () => {
    const inputs = await loadProjectInputs(SAMPLE_APP_DIR, 'sample');
    assert.equal(inputs.packageJson.name, 'sample-app');
    assert.equal(inputs.lockfile.lockfileVersion, 3);
    assert.match(inputs.manifestHash, /^[a-f0-9]{64}$/);
    assert.match(inputs.lockfileHash, /^[a-f0-9]{64}$/);
  });

  it('fails with explicit error if directory does not exist', async () => {
    await assert.rejects(
      () => loadProjectInputs('fixtures/non-existent-dir', 'test'),
      /Directory does not exist/
    );
  });

  it('fails with explicit error if lockfileVersion is not 3', async () => {
    // Create temporary directory with lockfileVersion: 2
    const tempDir = resolve('tests/temp-v2-test');
    await mkdir(tempDir, { recursive: true });
    try {
      await writeFile(join(tempDir, 'package.json'), JSON.stringify({ name: 'temp-app' }));
      await writeFile(join(tempDir, 'package-lock.json'), JSON.stringify({ lockfileVersion: 2, packages: {} }));

      await assert.rejects(
        () => loadProjectInputs(tempDir, 'temp'),
        /Unsupported lockfileVersion 2/
      );
    } finally {
      await rm(tempDir, { recursive: true, force: true });
    }
  });

  it('detects and rejects npm-shrinkwrap.json', async () => {
    const tempDir = resolve('tests/temp-shrinkwrap-test');
    await mkdir(tempDir, { recursive: true });
    try {
      await writeFile(join(tempDir, 'package.json'), JSON.stringify({ name: 'temp-app' }));
      await writeFile(join(tempDir, 'package-lock.json'), JSON.stringify({ lockfileVersion: 3, packages: {} }));
      await writeFile(join(tempDir, 'npm-shrinkwrap.json'), JSON.stringify({ lockfileVersion: 3 }));

      await assert.rejects(
        () => loadProjectInputs(tempDir, 'shrinkwrap-test'),
        /npm-shrinkwrap\.json detected/
      );
    } finally {
      await rm(tempDir, { recursive: true, force: true });
    }
  });
});
