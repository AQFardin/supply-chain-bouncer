/**
 * Checks if a resolved URL or version string indicates an unsupported dependency source.
 * @param {string|null} resolved 
 * @param {string|null} version 
 * @returns {{ unsupported: boolean, unsupportedReason: string|null }}
 */
export function checkUnsupportedSource(resolved = '', version = '') {
  const target = (resolved || version || '').trim();

  if (target.startsWith('git+') || target.startsWith('git://') || target.startsWith('github:')) {
    return { unsupported: true, unsupportedReason: 'GIT_DEPENDENCY_UNSUPPORTED' };
  }
  if (target.startsWith('file:')) {
    return { unsupported: true, unsupportedReason: 'LOCAL_FILE_DEPENDENCY_UNSUPPORTED' };
  }
  if (target.startsWith('link:')) {
    return { unsupported: true, unsupportedReason: 'SYMLINK_DEPENDENCY_UNSUPPORTED' };
  }

  // Check registry host if an HTTP URL is present
  if (resolved && (resolved.startsWith('http://') || resolved.startsWith('https://'))) {
    try {
      const url = new URL(resolved);
      const allowedHosts = ['registry.npmjs.org', 'registry.yarnpkg.com'];
      if (!allowedHosts.includes(url.hostname)) {
        return {
          unsupported: true,
          unsupportedReason: `NON_STANDARD_REGISTRY_SOURCE: ${url.hostname}`
        };
      }
    } catch {
      return { unsupported: true, unsupportedReason: 'INVALID_RESOLVED_URL' };
    }
  }

  return { unsupported: false, unsupportedReason: null };
}

/**
 * Extracts the declared root direct dependencies from a lockfile v3 packages map.
 * @param {object} rootPackageObj packages[""]
 * @returns {Set<string>}
 */
export function extractRootDirectDepNames(rootPackageObj = {}) {
  const names = new Set();
  const depBuckets = [
    rootPackageObj.dependencies,
    rootPackageObj.devDependencies,
    rootPackageObj.optionalDependencies,
    rootPackageObj.peerDependencies
  ];

  for (const bucket of depBuckets) {
    if (bucket && typeof bucket === 'object') {
      for (const name of Object.keys(bucket)) {
        names.add(name);
      }
    }
  }

  return names;
}

/**
 * Determines whether a lockfile package key represents a direct dependency.
 * Top-level "node_modules/<name>" is direct only if <name> was declared in the root package.
 * Nested paths like "node_modules/a/node_modules/b" are always transitive.
 * @param {string} locationKey 
 * @param {Set<string>} directDepNames 
 * @returns {{ isDirect: boolean, packageName: string }}
 */
export function classifyDirectness(locationKey, directDepNames) {
  // Strip leading "node_modules/"
  const segments = locationKey.split('node_modules/').filter(Boolean);
  const packageName = segments[segments.length - 1] || locationKey;

  // If there are multiple node_modules segments, it is nested transitive
  if (segments.length > 1) {
    return { isDirect: false, packageName };
  }

  // If single segment, check if it was declared in root direct dependencies
  const isDirect = directDepNames.has(packageName);
  return { isDirect, packageName };
}

/**
 * Compares two lockfile v3 objects and returns a comprehensive diff.
 * @param {object} baseLockfile 
 * @param {object} headLockfile 
 * @returns {object} Structured diff result
 */
export function compareLockfiles(baseLockfile, headLockfile) {
  const basePackages = (baseLockfile && baseLockfile.packages) || {};
  const headPackages = (headLockfile && headLockfile.packages) || {};

  const headDirectNames = extractRootDirectDepNames(headPackages[''] || {});
  const baseDirectNames = extractRootDirectDepNames(basePackages[''] || {});

  // Collect all unique location keys across both lockfiles, excluding the root project key ""
  const allLocations = new Set([
    ...Object.keys(basePackages).filter((k) => k !== ''),
    ...Object.keys(headPackages).filter((k) => k !== '')
  ]);

  const packageDiffs = [];

  for (const location of Array.from(allLocations).sort()) {
    const baseEntry = basePackages[location];
    const headEntry = headPackages[location];

    if (!baseEntry && headEntry) {
      // Added
      const { isDirect, packageName } = classifyDirectness(location, headDirectNames);
      const sourceCheck = checkUnsupportedSource(headEntry.resolved, headEntry.version);

      packageDiffs.push({
        name: headEntry.name || packageName,
        version: headEntry.version || null,
        previousVersion: null,
        location,
        changeType: 'added',
        isDirect,
        isDev: Boolean(headEntry.dev),
        isOptional: Boolean(headEntry.optional),
        resolved: headEntry.resolved || null,
        integrity: headEntry.integrity || null,
        previousIntegrity: null,
        hasInstallScript: Boolean(headEntry.hasInstallScript),
        scripts: headEntry.scripts || null,
        unsupported: sourceCheck.unsupported,
        unsupportedReason: sourceCheck.unsupportedReason
      });
    } else if (baseEntry && !headEntry) {
      // Removed
      const { isDirect, packageName } = classifyDirectness(location, baseDirectNames);

      packageDiffs.push({
        name: baseEntry.name || packageName,
        version: null,
        previousVersion: baseEntry.version || null,
        location,
        changeType: 'removed',
        isDirect,
        isDev: Boolean(baseEntry.dev),
        isOptional: Boolean(baseEntry.optional),
        resolved: null,
        integrity: null,
        previousIntegrity: baseEntry.integrity || null,
        hasInstallScript: Boolean(baseEntry.hasInstallScript),
        scripts: baseEntry.scripts || null,
        unsupported: false,
        unsupportedReason: null
      });
    } else if (baseEntry && headEntry) {
      // Exists in both — check for modifications
      const { isDirect, packageName } = classifyDirectness(location, headDirectNames);
      const isVersionChanged = baseEntry.version !== headEntry.version;
      const isResolvedChanged = baseEntry.resolved !== headEntry.resolved;
      const isIntegrityChanged = baseEntry.integrity !== headEntry.integrity;
      const isScriptChanged = Boolean(baseEntry.hasInstallScript) !== Boolean(headEntry.hasInstallScript);

      const hasChanged = isVersionChanged || isResolvedChanged || isIntegrityChanged || isScriptChanged;
      const changeType = hasChanged ? 'changed' : 'unchanged';

      const sourceCheck = checkUnsupportedSource(headEntry.resolved, headEntry.version);

      packageDiffs.push({
        name: headEntry.name || baseEntry.name || packageName,
        version: headEntry.version || null,
        previousVersion: baseEntry.version || null,
        location,
        changeType,
        isDirect,
        isDev: Boolean(headEntry.dev),
        isOptional: Boolean(headEntry.optional),
        resolved: headEntry.resolved || null,
        integrity: headEntry.integrity || null,
        previousIntegrity: baseEntry.integrity || null,
        hasInstallScript: Boolean(headEntry.hasInstallScript),
        scripts: headEntry.scripts || null,
        unsupported: sourceCheck.unsupported,
        unsupportedReason: sourceCheck.unsupportedReason
      });
    }
  }

  // Summary counts
  const changedOnly = packageDiffs.filter((p) => p.changeType !== 'unchanged');
  const summary = {
    totalEvaluated: packageDiffs.length,
    totalChanged: changedOnly.length,
    added: packageDiffs.filter((p) => p.changeType === 'added').length,
    addedDirect: packageDiffs.filter((p) => p.changeType === 'added' && p.isDirect).length,
    addedTransitive: packageDiffs.filter((p) => p.changeType === 'added' && !p.isDirect).length,
    changed: packageDiffs.filter((p) => p.changeType === 'changed').length,
    changedDirect: packageDiffs.filter((p) => p.changeType === 'changed' && p.isDirect).length,
    changedTransitive: packageDiffs.filter((p) => p.changeType === 'changed' && !p.isDirect).length,
    removed: packageDiffs.filter((p) => p.changeType === 'removed').length,
    unsupportedCount: packageDiffs.filter((p) => p.unsupported).length
  };

  return {
    summary,
    packages: packageDiffs
  };
}
