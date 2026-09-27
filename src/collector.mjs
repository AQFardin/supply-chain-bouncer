import { createHash } from 'node:crypto';
import { fetchPackageMetadata, fetchPackageArtifact } from './registry.mjs';
import { inspectTgzArchive } from './archive.mjs';
import { runStaticChecks } from './checks/index.mjs';

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

    // Process supported package
    try {
      let files = [];
      let actualIntegrity = null;
      let metadata = {};

      if (mode === 'fixture') {
        // Fixture mode: read provided mock files or metadata
        if (options.fixtureFiles && options.fixtureFiles[pkg.name]) {
          files = options.fixtureFiles[pkg.name];
        }
        metadata = await fetchPackageMetadata(pkg.name, pkg.version, {
          mode: 'fixture',
          fixtureMetadata: options.fixtureMetadata
        });
        actualIntegrity = pkg.integrity || 'sha512-mockFixtureIntegrity==';

        allSources.push({
          sourceType: 'fixture',
          pathOrUrl: `fixture:${pkg.name}@${pkg.version}`,
          retrievalTime: new Date().toISOString(),
          contentDigest: pkg.integrity || createHash('sha256').update(pkg.name).digest('hex')
        });
      } else {
        // Live registry mode
        metadata = await fetchPackageMetadata(pkg.name, pkg.version, { mode: 'live' });

        if (metadata.tarballUrl) {
          const tarballBuffer = await fetchPackageArtifact(metadata.tarballUrl, { mode: 'live' });
          const inspection = inspectTgzArchive(tarballBuffer);
          files = inspection.files;
          actualIntegrity = inspection.integrity;

          allSources.push({
            sourceType: 'live',
            pathOrUrl: metadata.tarballUrl,
            retrievalTime: new Date().toISOString(),
            contentDigest: actualIntegrity
          });
        }
      }

      // Merge registry scripts if available and missing on package diff
      if (metadata.scripts && !pkg.scripts) {
        pkg.scripts = metadata.scripts;
      }

      // Run deterministic static checks
      const pkgObservations = runStaticChecks(pkg, files, {
        actualIntegrity,
        popularPackages
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

  // Collection status
  const hasCritical = allObservations.some((o) => o.severity === 'critical');
  const hasIncomplete = incompleteReasons.length > 0;
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
