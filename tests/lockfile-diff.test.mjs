import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { loadProjectInputs } from '../src/input.mjs';
import { compareLockfiles, checkUnsupportedSource, classifyDirectness } from '../src/lockfile-diff.mjs';

const BENIGN_BASE = resolve('fixtures/benign/base');
const BENIGN_HEAD = resolve('fixtures/benign/head');
const SUSPICIOUS_BASE = resolve('fixtures/suspicious/base');
const SUSPICIOUS_HEAD = resolve('fixtures/suspicious/head');

describe('Lockfile Comparator Engine Tests', () => {
  it('returns zero changed packages for identical lockfiles', async () => {
    const base = await loadProjectInputs(BENIGN_BASE, 'base');
    const diff = compareLockfiles(base.lockfile, base.lockfile);

    assert.equal(diff.summary.totalChanged, 0);
    assert.equal(diff.packages.every((p) => p.changeType === 'unchanged'), true);
  });

  it('correctly identifies direct additions and version bumps in benign fixture', async () => {
    const base = await loadProjectInputs(BENIGN_BASE, 'base');
    const head = await loadProjectInputs(BENIGN_HEAD, 'head');
    const diff = compareLockfiles(base.lockfile, head.lockfile);

    assert.equal(diff.summary.totalChanged, 2);
    assert.equal(diff.summary.addedDirect, 1);
    assert.equal(diff.summary.changedDirect, 1);

    // Check version bump on ms: 2.1.2 -> 2.1.3
    const msPkg = diff.packages.find((p) => p.name === 'ms');
    assert.ok(msPkg);
    assert.equal(msPkg.changeType, 'changed');
    assert.equal(msPkg.previousVersion, '2.1.2');
    assert.equal(msPkg.version, '2.1.3');
    assert.equal(msPkg.isDirect, true);

    // Check direct addition of picocolors
    const picoPkg = diff.packages.find((p) => p.name === 'picocolors');
    assert.ok(picoPkg);
    assert.equal(picoPkg.changeType, 'added');
    assert.equal(picoPkg.version, '1.1.1');
    assert.equal(picoPkg.isDirect, true);
  });

  it('correctly classifies transitive dependencies vs direct dependencies', () => {
    const directNames = new Set(['express', 'axios']);

    // Direct root dependency
    const resDirect = classifyDirectness('node_modules/express', directNames);
    assert.equal(resDirect.isDirect, true);
    assert.equal(resDirect.packageName, 'express');

    // Hoisted transitive dependency (not in direct list)
    const resHoisted = classifyDirectness('node_modules/qs', directNames);
    assert.equal(resHoisted.isDirect, false);
    assert.equal(resHoisted.packageName, 'qs');

    // Nested transitive dependency
    const resNested = classifyDirectness('node_modules/express/node_modules/cookie', directNames);
    assert.equal(resNested.isDirect, false);
    assert.equal(resNested.packageName, 'cookie');
  });

  it('correctly tracks added transitive dependencies in lockfile v3 packages map', () => {
    const baseLockfile = {
      lockfileVersion: 3,
      packages: {
        '': {
          dependencies: { 'my-lib': '1.0.0' }
        },
        'node_modules/my-lib': {
          version: '1.0.0'
        }
      }
    };

    const headLockfile = {
      lockfileVersion: 3,
      packages: {
        '': {
          dependencies: { 'my-lib': '1.0.0' }
        },
        'node_modules/my-lib': {
          version: '1.0.0'
        },
        'node_modules/my-lib/node_modules/transitive-child': {
          version: '2.0.0',
          resolved: 'https://registry.npmjs.org/transitive-child/-/transitive-child-2.0.0.tgz'
        }
      }
    };

    const diff = compareLockfiles(baseLockfile, headLockfile);
    assert.equal(diff.summary.totalChanged, 1);
    assert.equal(diff.summary.addedTransitive, 1);

    const child = diff.packages.find((p) => p.name === 'transitive-child');
    assert.ok(child);
    assert.equal(child.isDirect, false);
    assert.equal(child.location, 'node_modules/my-lib/node_modules/transitive-child');
  });

  it('detects package removal', () => {
    const baseLockfile = {
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { oldPkg: '1.0.0' } },
        'node_modules/oldPkg': { version: '1.0.0' }
      }
    };
    const headLockfile = {
      lockfileVersion: 3,
      packages: {
        '': { dependencies: {} }
      }
    };

    const diff = compareLockfiles(baseLockfile, headLockfile);
    assert.equal(diff.summary.removed, 1);
    const removedPkg = diff.packages.find((p) => p.name === 'oldPkg');
    assert.ok(removedPkg);
    assert.equal(removedPkg.changeType, 'removed');
  });

  it('preserves multiple coexisting versions at distinct locations', () => {
    const baseLockfile = { lockfileVersion: 3, packages: { '': {} } };
    const headLockfile = {
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { debug: '4.3.4', legacyTool: '1.0.0' } },
        'node_modules/debug': { version: '4.3.4' },
        'node_modules/legacyTool': { version: '1.0.0' },
        'node_modules/legacyTool/node_modules/debug': { version: '2.6.9' }
      }
    };

    const diff = compareLockfiles(baseLockfile, headLockfile);
    const debugEntries = diff.packages.filter((p) => p.name === 'debug');
    assert.equal(debugEntries.length, 2);

    const rootDebug = debugEntries.find((p) => p.location === 'node_modules/debug');
    assert.equal(rootDebug.version, '4.3.4');
    assert.equal(rootDebug.isDirect, true);

    const nestedDebug = debugEntries.find((p) => p.location === 'node_modules/legacyTool/node_modules/debug');
    assert.equal(nestedDebug.version, '2.6.9');
    assert.equal(nestedDebug.isDirect, false);
  });

  it('detects changed integrity hash as a modification', () => {
    const baseLockfile = {
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { pkg: '1.0.0' } },
        'node_modules/pkg': { version: '1.0.0', integrity: 'sha512-originalHash==' }
      }
    };
    const headLockfile = {
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { pkg: '1.0.0' } },
        'node_modules/pkg': { version: '1.0.0', integrity: 'sha512-tamperedHash==' }
      }
    };

    const diff = compareLockfiles(baseLockfile, headLockfile);
    const pkg = diff.packages.find((p) => p.name === 'pkg');
    assert.ok(pkg);
    assert.equal(pkg.changeType, 'changed');
    assert.equal(pkg.previousIntegrity, 'sha512-originalHash==');
    assert.equal(pkg.integrity, 'sha512-tamperedHash==');
  });

  it('flags unsupported sources: git, file, link, and non-standard registries', () => {
    const gitCheck = checkUnsupportedSource('git+https://github.com/foo/bar.git');
    assert.equal(gitCheck.unsupported, true);
    assert.equal(gitCheck.unsupportedReason, 'GIT_DEPENDENCY_UNSUPPORTED');

    const fileCheck = checkUnsupportedSource('file:../local-pkg');
    assert.equal(fileCheck.unsupported, true);
    assert.equal(fileCheck.unsupportedReason, 'LOCAL_FILE_DEPENDENCY_UNSUPPORTED');

    const linkCheck = checkUnsupportedSource('link:../local-pkg');
    assert.equal(linkCheck.unsupported, true);
    assert.equal(linkCheck.unsupportedReason, 'SYMLINK_DEPENDENCY_UNSUPPORTED');

    const foreignRegistry = checkUnsupportedSource('http://evil-npm.internal/tarball.tgz');
    assert.equal(foreignRegistry.unsupported, true);
    assert.match(foreignRegistry.unsupportedReason, /NON_STANDARD_REGISTRY_SOURCE/);

    const validNpm = checkUnsupportedSource('https://registry.npmjs.org/picocolors/-/picocolors-1.1.1.tgz');
    assert.equal(validNpm.unsupported, false);
    assert.equal(validNpm.unsupportedReason, null);
  });

  it('detects lifecycle scripts in suspicious fixture', async () => {
    const base = await loadProjectInputs(SUSPICIOUS_BASE, 'base');
    const head = await loadProjectInputs(SUSPICIOUS_HEAD, 'head');
    const diff = compareLockfiles(base.lockfile, head.lockfile);

    const suspiciousPkg = diff.packages.find((p) => p.name === 'mock-telemetry-reporter');
    assert.ok(suspiciousPkg);
    assert.equal(suspiciousPkg.hasInstallScript, true);
  });
});
