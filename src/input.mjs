import { readFile, stat } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { createHash } from 'node:crypto';

/**
 * Computes SHA-256 hash of raw file bytes.
 * @param {string} filePath 
 * @returns {Promise<string|null>} Hex hash or null if file absent
 */
export async function computeFileSha256(filePath) {
  try {
    const content = await readFile(filePath);
    return createHash('sha256').update(content).digest('hex');
  } catch (err) {
    if (err.code === 'ENOENT') {
      return null;
    }
    throw err;
  }
}

/**
 * Computes a deterministic canonical subject digest over base and candidate manifest/lockfiles.
 * @param {string} baseDir 
 * @param {string} headDir 
 * @returns {Promise<{ subjectDigest: string, inputs: Array<{ label: string, path: string, sha256: string }> }>}
 */
export async function computeSubjectDigest(baseDir, headDir) {
  const files = [
    { label: 'base:package.json', path: resolve(baseDir, 'package.json') },
    { label: 'base:package-lock.json', path: resolve(baseDir, 'package-lock.json') },
    { label: 'head:package.json', path: resolve(headDir, 'package.json') },
    { label: 'head:package-lock.json', path: resolve(headDir, 'package-lock.json') }
  ];

  const inputs = [];
  const hasher = createHash('sha256');

  for (const item of files) {
    const digest = await computeFileSha256(item.path);
    const hashValue = digest || 'ABSENT';
    inputs.push({ label: item.label, path: item.path, sha256: hashValue });
    hasher.update(`${item.label}:${hashValue}\n`);
  }

  const subjectDigest = hasher.digest('hex');
  return { subjectDigest, inputs };
}

/**
 * Validates and loads inputs for a single project state (base or candidate).
 * @param {string} dir 
 * @param {string} label 
 * @returns {Promise<{ dir: string, packageJson: object, lockfile: object, manifestHash: string, lockfileHash: string }>}
 */
export async function loadProjectInputs(dir, label = 'project') {
  const resolvedDir = resolve(dir);

  // Check directory existence
  try {
    const dirStat = await stat(resolvedDir);
    if (!dirStat.isDirectory()) {
      throw new Error(`Path is not a directory: ${resolvedDir}`);
    }
  } catch (err) {
    if (err.code === 'ENOENT') {
      throw new Error(`Directory does not exist for ${label}: ${resolvedDir}`);
    }
    throw err;
  }

  // Detect npm-shrinkwrap.json (takes precedence over package-lock.json)
  const shrinkwrapPath = join(resolvedDir, 'npm-shrinkwrap.json');
  try {
    await stat(shrinkwrapPath);
    throw new Error(
      `npm-shrinkwrap.json detected in ${resolvedDir}. Shrinkwrap takes precedence over package-lock.json and is unsupported.`
    );
  } catch (err) {
    if (err.code !== 'ENOENT') throw err;
  }

  const manifestPath = join(resolvedDir, 'package.json');
  const lockfilePath = join(resolvedDir, 'package-lock.json');

  // Read raw files
  let rawManifest, rawLockfile;
  try {
    rawManifest = await readFile(manifestPath, 'utf8');
  } catch (err) {
    throw new Error(`Missing package.json in ${resolvedDir} (${label}): ${err.message}`);
  }

  try {
    rawLockfile = await readFile(lockfilePath, 'utf8');
  } catch (err) {
    throw new Error(`Missing package-lock.json in ${resolvedDir} (${label}): ${err.message}`);
  }

  // Parse JSON strictly
  let packageJson, lockfile;
  try {
    packageJson = JSON.parse(rawManifest);
  } catch (err) {
    throw new Error(`Malformed JSON in ${manifestPath}: ${err.message}`);
  }

  try {
    lockfile = JSON.parse(rawLockfile);
  } catch (err) {
    throw new Error(`Malformed JSON in ${lockfilePath}: ${err.message}`);
  }

  // Enforce lockfileVersion 3
  if (lockfile.lockfileVersion !== 3) {
    throw new Error(
      `Unsupported lockfileVersion ${lockfile.lockfileVersion} in ${lockfilePath}. Supply Chain Bouncer requires lockfile version 3.`
    );
  }

  if (!lockfile.packages || typeof lockfile.packages !== 'object') {
    throw new Error(`Invalid lockfile in ${lockfilePath}: missing "packages" object.`);
  }

  const manifestHash = createHash('sha256').update(rawManifest).digest('hex');
  const lockfileHash = createHash('sha256').update(rawLockfile).digest('hex');

  return {
    dir: resolvedDir,
    packageJson,
    lockfile,
    manifestHash,
    lockfileHash
  };
}
