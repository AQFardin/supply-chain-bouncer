import {
  checkNameNearMatch,
  checkLifecycleScripts,
  analyzePackageFiles
} from './rules.mjs';

/**
 * Runs all deterministic static checks for a package instance.
 * @param {object} packageDiff 
 * @param {Array<{ path: string, content: string }>} files 
 * @param {object} options 
 * @returns {Array<object>} Array of deterministic observations with stable IDs
 */
export function runStaticChecks(packageDiff, files = [], options = {}) {
  const observations = [];
  const popularPackages = options.popularPackages || [];
  const packageName = packageDiff.name;
  const packageLocation = packageDiff.location;

  // 1. Typosquat / near-name match check on added packages
  if (packageDiff.changeType === 'added' && packageName) {
    const nearMatches = checkNameNearMatch(packageName, popularPackages);
    for (const match of nearMatches) {
      observations.push({
        id: `obs-${packageName}-typosquat-${observations.length + 1}`,
        packageLocation,
        packageName,
        ruleId: match.ruleId,
        severity: match.severity,
        evidenceRef: `package.json#name`,
        explanation: match.explanation
      });
    }
  }

  // 2. Lifecycle script checks
  const scriptChecks = checkLifecycleScripts(packageDiff);
  for (const s of scriptChecks) {
    observations.push({
      id: `obs-${packageName}-script-${observations.length + 1}`,
      packageLocation,
      packageName,
      ruleId: s.ruleId,
      severity: s.severity,
      evidenceRef: `package.json#scripts.${s.scriptType || 'install'}`,
      explanation: s.explanation
    });
  }

  // 3. Artifact integrity check
  if (options.actualIntegrity && packageDiff.integrity) {
    if (options.actualIntegrity !== packageDiff.integrity) {
      observations.push({
        id: `obs-${packageName}-integrity-mismatch`,
        packageLocation,
        packageName,
        ruleId: 'ARTIFACT_INTEGRITY_MISMATCH',
        severity: 'critical',
        evidenceRef: `package-lock.json#integrity`,
        explanation: `Integrity hash mismatch: expected "${packageDiff.integrity}", computed "${options.actualIntegrity}". Possible artifact tampering or registry discrepancy.`
      });
    }
  }

  // 4. Unsupported source check
  if (packageDiff.unsupported) {
    observations.push({
      id: `obs-${packageName}-unsupported-source`,
      packageLocation,
      packageName,
      ruleId: 'UNSUPPORTED_OR_INCOMPLETE',
      severity: 'high',
      evidenceRef: `package-lock.json#resolved`,
      explanation: `Package source is unsupported by MVP policy: ${packageDiff.unsupportedReason}. Requires manual operator verification.`
    });
  }

  // 5. Code pattern checks across files
  const fileObservations = analyzePackageFiles(files);
  for (const f of fileObservations) {
    observations.push({
      id: `obs-${packageName}-${f.ruleId.toLowerCase()}-${observations.length + 1}`,
      packageLocation,
      packageName,
      ruleId: f.ruleId,
      severity: f.severity,
      evidenceRef: f.evidenceRef,
      explanation: f.explanation
    });
  }

  return observations;
}
