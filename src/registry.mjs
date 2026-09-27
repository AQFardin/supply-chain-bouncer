import { createHash } from 'node:crypto';
import { ARCHIVE_LIMITS } from './archive.mjs';

const ALLOWED_REGISTRY_HOSTS = ['registry.npmjs.org', 'registry.yarnpkg.com'];

/**
 * Validates that a registry URL belongs to an allowed HTTPS registry host.
 * @param {string} urlString 
 * @returns {URL}
 */
export function validateRegistryUrl(urlString) {
  let parsed;
  try {
    parsed = new URL(urlString);
  } catch {
    throw new Error(`Invalid registry URL: "${urlString}"`);
  }

  if (parsed.protocol !== 'https:') {
    throw new Error(`Insecure registry protocol "${parsed.protocol}". Only HTTPS is permitted.`);
  }

  if (parsed.username || parsed.password) {
    throw new Error('Registry URLs containing embedded credentials are forbidden.');
  }

  if (!ALLOWED_REGISTRY_HOSTS.includes(parsed.hostname)) {
    throw new Error(`Registry host "${parsed.hostname}" is not in the allowed registry allowlist.`);
  }

  return parsed;
}

/**
 * Fetches package metadata from public npm registry or local fixture adapter.
 * @param {string} packageName 
 * @param {string} version 
 * @param {object} options { mode: 'live' | 'fixture', fixtureData: object, timeoutMs: number }
 * @returns {Promise<object>} Normalized metadata record
 */
export async function fetchPackageMetadata(packageName, version, options = {}) {
  const mode = options.mode || 'live';
  const timeoutMs = options.timeoutMs || 15000;

  if (mode === 'fixture') {
    // Return fixture metadata if provided
    if (options.fixtureMetadata && options.fixtureMetadata[packageName]) {
      return options.fixtureMetadata[packageName];
    }

    // Default synthetic fixture metadata
    return {
      packageName,
      version,
      publishedAt: '2026-09-01T00:00:00.000Z',
      maintainersCount: 1,
      repositoryUrl: 'https://github.com/example/mock-repo',
      tarballUrl: `https://registry.npmjs.org/${packageName}/-/${packageName}-${version}.tgz`,
      integrity: 'sha512-mockFixtureIntegrity==',
      hasAttestation: false,
      isSynthetic: true
    };
  }

  // Live registry mode
  const encodedName = packageName.startsWith('@')
    ? `@${encodeURIComponent(packageName.slice(1))}`
    : encodeURIComponent(packageName);
  const registryUrl = `https://registry.npmjs.org/${encodedName}`;

  validateRegistryUrl(registryUrl);

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(registryUrl, {
      signal: controller.signal,
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'supply-chain-bouncer/0.1.0'
      }
    });

    if (!response.ok) {
      throw new Error(`Registry responded with HTTP ${response.status}: ${response.statusText}`);
    }

    const doc = await response.json();
    const versionObj = doc.versions && doc.versions[version];

    if (!versionObj) {
      throw new Error(`Version ${version} of package "${packageName}" not found on registry.`);
    }

    const dist = versionObj.dist || {};
    const time = doc.time || {};
    const maintainers = doc.maintainers || versionObj.maintainers || [];

    return {
      packageName,
      version,
      publishedAt: time[version] || null,
      maintainersCount: Array.isArray(maintainers) ? maintainers.length : 0,
      repositoryUrl: typeof versionObj.repository === 'string'
        ? versionObj.repository
        : (versionObj.repository && versionObj.repository.url) || null,
      tarballUrl: dist.tarball || null,
      integrity: dist.integrity || null,
      hasAttestation: Boolean(dist.attestations || dist.signatures),
      scripts: versionObj.scripts || {},
      isSynthetic: false
    };
  } catch (err) {
    if (err.name === 'AbortError') {
      throw new Error(`Registry request timed out after ${timeoutMs}ms for "${packageName}"`);
    }
    throw err;
  } finally {
    clearTimeout(timeoutId);
  }
}

/**
 * Fetches package tarball artifact from registry.
 * @param {string} tarballUrl 
 * @param {object} options 
 * @returns {Promise<Buffer>}
 */
export async function fetchPackageArtifact(tarballUrl, options = {}) {
  const mode = options.mode || 'live';
  const timeoutMs = options.timeoutMs || 20000;

  if (mode === 'fixture') {
    if (options.fixtureArtifact) {
      return options.fixtureArtifact;
    }
    return Buffer.from('');
  }

  validateRegistryUrl(tarballUrl);

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(tarballUrl, {
      signal: controller.signal,
      headers: { 'User-Agent': 'supply-chain-bouncer/0.1.0' }
    });

    if (!response.ok) {
      throw new Error(`Artifact download HTTP ${response.status}: ${response.statusText}`);
    }

    const contentLength = parseInt(response.headers.get('content-length') || '0', 10);
    if (contentLength > ARCHIVE_LIMITS.MAX_COMPRESSED_SIZE) {
      throw new Error(`Artifact size (${contentLength} bytes) exceeds limit (${ARCHIVE_LIMITS.MAX_COMPRESSED_SIZE} bytes)`);
    }

    const arrayBuffer = await response.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);

    if (buffer.length > ARCHIVE_LIMITS.MAX_COMPRESSED_SIZE) {
      throw new Error(`Downloaded artifact (${buffer.length} bytes) exceeds limit`);
    }

    return buffer;
  } catch (err) {
    if (err.name === 'AbortError') {
      throw new Error(`Artifact download timed out after ${timeoutMs}ms`);
    }
    throw err;
  } finally {
    clearTimeout(timeoutId);
  }
}
