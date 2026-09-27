import { createHash } from 'node:crypto';
import { readdir, readFile, stat } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { fetchPackageMetadata, fetchPackageArtifact } from './registry.mjs';
import { inspectTgzArchive } from './archive.mjs';
import { runStaticChecks } from './checks/index.mjs';

/**
 * Computes a deterministic SHA-256 digest over a set of in-memory file records.
 * Used to produce a real contentDigest for fixture file sets rather than
 * using opaque lockfile SRI strings as a proxy.
 * @param {Array<{ path: string, content: string }>} files
 * @returns {string} hex SHA-256
 */
function hashFileSet(files) {
  const hasher = createHash('sha256');
  // Sort by path for determinism
  const sorted = [...files].sort((a, b) => a.path.localeCompare(b.path));
  for (const f of sorted) {
    hasher.update(`${f.path}:${f.content}\n`);
  }
  return `sha256-${hasher.digest('hex')}`;
}

/**
 * Reads all files from a directory recursively for fixture inspection.
 */
async function readDirectoryFilesRecursively(dirPath, baseSubPath = '') {
  const files = [];
  try {
    const entries = await readdir(dirPath, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = join(dirPath, entry.name);
      const relPath = baseSubPath ? join(baseSubPath, entry.name) : entry.name;
      if (entry.isDirectory()) {
        const subFiles = await readDirectoryFilesRecursively(fullPath, relPath);
        files.push(...subFiles);
      } else if (entry.isFile()) {
        const content = await readFile(fullPath, 'utf8');
        files.push({
          path: relPath.replace(/\\/g, '/'),
          content,
          size: Buffer.byteLength(content, 'utf8')
        });
      }
    }
  } catch {}
  return files;
}

/**
 * Discovers local fixture package files associated with candidate packages.
 */
export async function discoverFixturePackageFiles(packageName, headDir, options = {}) {
  // 1. Explicit fixture files supplied in options
  if (options.fixtureFiles && options.fixtureFiles[packageName]) {
    return options.fixtureFiles[packageName];
  }

  // 2. Candidate directories relative to headDir
  const candidateDirs = [];
  if (headDir) {
    const resolvedHead = resolve(headDir);
    candidateDirs.push(join(resolvedHead, '..', 'package-files', packageName));
    candidateDirs.push(join(resolvedHead, 'package-files', packageName));
    candidateDirs.push(join(resolvedHead, 'node_modules', packageName));
  }

  // 3. Known fixture directories in workspace
  candidateDirs.push(resolve('fixtures/suspicious/package-files', packageName));
  candidateDirs.push(resolve('fixtures/legitimate-install-script/package-files', packageName));
  candidateDirs.push(resolve('fixtures/prompt-injection/package-files', packageName));

  for (const dir of candidateDirs) {
    try {
      const dirStat = await stat(dir);
      if (dirStat.isDirectory()) {
        const files = await readDirectoryFilesRecursively(dir);
        if (files.length > 0) return files;
      }
    } catch {}
  }

  return [];
}

/**
 * Coordinates static evidence collection for a dependency diff.
 * @param {object} diffResult Output from lockfile-diff.mjs
 * @param {string} subjectDigest SHA-256 over raw input files
 * @param {object} options
 * @returns {Promise<object>} Evidence bundle matching schemas/evidence.schema.json
 */
export async function collectEvidence(diffResult, subjectDigest, options = {}) {
  const mode = options.mode || 'live';
  const popularPackages = options.popularPackages || [];
  const policy = options.policy || {};
  const runId = options.runId || `run-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const headDir = options.headDir || null;

  // Policy digest
  const policyDigest = createHash('sha256')
    .update(JSON.stringify(policy))
    .digest('hex');

  const changedPackages = diffResult.packages.filter((p) => p.changeType !== 'unchanged');
  const allObservations = [];
  const allSources = [];
  const unknowns = [];
  const incompleteReasons = [];

  for (const pkg of changedPackages) {
    if (pkg.changeType === 'removed') {
      // Removed packages require explanation, but no artifact fetching
      allSources.push({
        sourceType: mode === 'fixture' ? 'fixture' : 'live',
        pathOrUrl: `lockfile:${pkg.location}`,
        retrievalTime: new Date().toISOString(),
        contentDigest: pkg.previousIntegrity || 'sha256-removed'
      });
      continue;
    }

    if (pkg.unsupported) {
      // Flag unsupported source immediately
      incompleteReasons.push(`Unsupported dependency source for ${pkg.name}: ${pkg.unsupportedReason}`);
      const observations = runStaticChecks(pkg, [], { popularPackages });
      allObservations.push(...observations);
      allSources.push({
        sourceType: 'fixture',
        pathOrUrl: pkg.resolved || `unsupported:${pkg.name}`,
        retrievalTime: new Date().toISOString(),
        contentDigest: 'unsupported-source-digest'
      });
      continue;
    }

    // Flag missing required integrity in lockfile for added or changed packages
    if ((pkg.changeType === 'added' || pkg.changeType === 'changed') && !pkg.integrity) {
      allObservations.push({
        id: `obs-${pkg.name}-missing-integrity`,
        packageLocation: pkg.location,
        packageName: pkg.name,
        ruleId: 'UNSUPPORTED_OR_INCOMPLETE',
        severity: 'high',
        evidenceRef: 'package-lock.json#integrity',
        explanation: `Missing required integrity hash in lockfile for ${pkg.name}@${pkg.version}. An absent integrity value cannot establish artifact verification under MVP policy.`
      });
      incompleteReasons.push(`Missing required integrity hash for ${pkg.name}@${pkg.version}`);
    }

    // Process supported package
    try {
      let files = [];
      let actualIntegrity = null;
      let metadata = {};

      if (mode === 'fixture') {
        // Fixture mode: read fixture files from options or package-files directory
        files = await discoverFixturePackageFiles(pkg.name, headDir, options);

        // FIX 2: Flag missing fixture content as incomplete evidence rather than silently continuing.
        // A fixture with no discoverable files cannot verify behavior — this is incomplete evidence.
        if (files.length === 0) {
          incompleteReasons.push(
            `No fixture package files found for ${pkg.name}@${pkg.version}. ` +
            `Behavioral evidence is incomplete — file discovery returned empty set.`
          );
          allObservations.push({
            id: `obs-${pkg.name}-missing-fixture-files`,
            packageLocation: pkg.location,
            packageName: pkg.name,
            ruleId: 'UNSUPPORTED_OR_INCOMPLETE',
            severity: 'high',
            evidenceRef: `fixture:${pkg.name}@${pkg.version}`,
            explanation: `No fixture package files were found for ${pkg.name}@${pkg.version}. Static file checks could not be performed. Evidence is incomplete.`
          });
        }

        metadata = await fetchPackageMetadata(pkg.name, pkg.version, {
          mode: 'fixture',
          fixtureMetadata: options.fixtureMetadata
        });

        // FIX 1: Compute a real SHA-256 over actual inspected fixture file content.
        // This clearly distinguishes synthetic fixture integrity from verified artifact integrity.
        // Label: "sha256-fixture-files:<hex>" so investigators can see this is not a registry download.
        const fixtureContentDigest = files.length > 0
          ? `sha256-fixture-files:${hashFileSet(files).replace('sha256-', '')}`
          : 'sha256-fixture-files:empty-no-files-found';
        // Do NOT set actualIntegrity for fixture mode: fixtureContentDigest is a hash of fixture
        // file content, not a downloaded-artifact SRI value. Passing it to the integrity-mismatch
        // check would produce spurious critical observations against the lockfile SRI string.
        actualIntegrity = null;

        allSources.push({
          sourceType: 'fixture',
          pathOrUrl: `fixture:${pkg.name}@${pkg.version}`,
          retrievalTime: new Date().toISOString(),
          // Real hash of inspected content; NOT a downloaded-artifact integrity value
          contentDigest: fixtureContentDigest
        });
      } else {
        // Live registry mode
        metadata = await fetchPackageMetadata(pkg.name, pkg.version, { mode: 'live' });

        // Validate artifact identity: compare lockfile resolved URL vs registry metadata tarball URL
        const targetTarballUrl = pkg.resolved || metadata.tarballUrl;
        if (pkg.resolved && metadata.tarballUrl && pkg.resolved !== metadata.tarballUrl) {
          allObservations.push({
            id: `obs-${pkg.name}-artifact-url-discrepancy`,
            packageLocation: pkg.location,
            packageName: pkg.name,
            ruleId: 'ARTIFACT_INTEGRITY_MISMATCH',
            severity: 'high',
            evidenceRef: 'package-lock.json#resolved',
            explanation: `Lockfile resolved artifact URL ("${pkg.resolved}") does not match registry metadata tarball URL ("${metadata.tarballUrl}"). Possible alternate registry or dependency redirection.`
          });
          incompleteReasons.push(`Artifact URL discrepancy for ${pkg.name}: lockfile resolves to ${pkg.resolved}, registry reports ${metadata.tarballUrl}`);
        }

        if (targetTarballUrl) {
          const tarballBuffer = await fetchPackageArtifact(targetTarballUrl, { mode: 'live' });
          const inspection = inspectTgzArchive(tarballBuffer);
          files = inspection.files;
          actualIntegrity = inspection.integrity;

          // Check if archive inspection was truncated
          if (inspection.truncated) {
            allObservations.push({
              id: `obs-${pkg.name}-archive-truncated`,
              packageLocation: pkg.location,
              packageName: pkg.name,
              ruleId: 'UNSUPPORTED_OR_INCOMPLETE',
              severity: 'critical',
              evidenceRef: targetTarballUrl,
              explanation: `Archive inspection was truncated: ${inspection.truncationReason}. Potential oversized artifact.`
            });
            incompleteReasons.push(`Archive inspection truncated for ${pkg.name}: ${inspection.truncationReason}`);
          }

          // Check if any files were omitted due to text size limits
          if (inspection.omittedFiles && inspection.omittedFiles.length > 0) {
            pkg.omittedCoverage = inspection.omittedFiles.map((f) => f.path);
            for (const omitted of inspection.omittedFiles) {
              allObservations.push({
                id: `obs-${pkg.name}-omitted-${omitted.path.replace(/[^a-zA-Z0-9]/g, '_')}`,
                packageLocation: pkg.location,
                packageName: pkg.name,
                ruleId: 'UNSUPPORTED_OR_INCOMPLETE',
                severity: 'high',
                evidenceRef: `${targetTarballUrl}#${omitted.path}`,
                explanation: `Coverage omitted for file "${omitted.path}": ${omitted.reason}.`
              });
              incompleteReasons.push(`Coverage omitted for ${pkg.name}/${omitted.path}: exceeds text inspection limit`);
            }
          }

          allSources.push({
            sourceType: 'live',
            pathOrUrl: targetTarballUrl,
            retrievalTime: new Date().toISOString(),
            contentDigest: actualIntegrity
          });
        }
      }

      // Preserve provenance evidence for upcoming Bob Provenance Auditor
      pkg.provenance = {
        publishedAt: metadata.publishedAt || null,
        maintainersCount: typeof metadata.maintainersCount === 'number' ? metadata.maintainersCount : 0,
        repositoryUrl: metadata.repositoryUrl || null,
        hasAttestation: Boolean(metadata.hasAttestation),
        tarballUrl: metadata.tarballUrl || pkg.resolved || null,
        isSynthetic: Boolean(metadata.isSynthetic)
      };

      allSources.push({
        sourceType: mode === 'fixture' ? 'synthetic' : 'live',
        pathOrUrl: `https://registry.npmjs.org/${pkg.name}`,
        retrievalTime: new Date().toISOString(),
        contentDigest: metadata.integrity || pkg.integrity || 'metadata-record'
      });

      // Merge package scripts if available from metadata or fixture files
      if (metadata.scripts && !pkg.scripts) {
        pkg.scripts = metadata.scripts;
      }

      // FIX 3: Extract text metadata fields (description, etc.) from fixture package.json
      // and pass them to static checks so prompt-injection patterns are detected.
      // These fields are treated as untrusted data; the check surfaces labeled excerpts.
      const pkgJsonFile = files.find((f) => f.path === 'package.json');
      let metadataDescription = metadata.description || null;
      if (pkgJsonFile && !pkg.scripts) {
        try {
          const parsed = JSON.parse(pkgJsonFile.content);
          if (parsed.scripts) pkg.scripts = parsed.scripts;
          // Prefer fixture package.json description over synthetic metadata default
          if (parsed.description && !metadataDescription) {
            metadataDescription = parsed.description;
          }
        } catch {}
      } else if (pkgJsonFile) {
        // Parse for description even when scripts already set
        try {
          const parsed = JSON.parse(pkgJsonFile.content);
          if (parsed.description && !metadataDescription) {
            metadataDescription = parsed.description;
          }
        } catch {}
      }

      // Build metadata fields object for prompt-injection and other metadata checks
      const metadataFields = {};
      if (metadataDescription) metadataFields.description = metadataDescription;

      // Run deterministic static checks
      const pkgObservations = runStaticChecks(pkg, files, {
        actualIntegrity,
        popularPackages,
        metadataFields
      });
      allObservations.push(...pkgObservations);

    } catch (err) {
      incompleteReasons.push(`Failed to collect evidence for ${pkg.name}@${pkg.version}: ${err.message}`);
      allObservations.push({
        id: `obs-${pkg.name}-fetch-error`,
        packageLocation: pkg.location,
        packageName: pkg.name,
        ruleId: 'UNSUPPORTED_OR_INCOMPLETE',
        severity: 'high',
        evidenceRef: 'registry-fetch',
        explanation: `Evidence collection error: ${err.message}`
      });
    }
  }

  // Explicit unknowns
  unknowns.push('Runtime dynamic effects were not executed or observed.');
  unknowns.push('Full cryptographic npm provenance was not verified (adapter extension pending).');
  if (incompleteReasons.length > 0) {
    unknowns.push(...incompleteReasons);
  }

  // Collection status determination
  const hasCritical = allObservations.some((o) => o.severity === 'critical');
  const hasIncomplete = incompleteReasons.length > 0 || allObservations.some((o) => o.ruleId === 'UNSUPPORTED_OR_INCOMPLETE');

  let collectionStatus = 'complete';
  if (hasCritical) {
    collectionStatus = 'quarantine';
  } else if (hasIncomplete) {
    collectionStatus = 'incomplete';
  }

  return {
    schemaVersion: '1.0',
    runId,
    mode,
    subjectDigest,
    scannerVersion: '0.1.0',
    policyDigest,
    collectionStatus,
    incompleteReasons,
    packages: diffResult.packages,
    observations: allObservations,
    unknowns,
    sources: allSources
  };
}
