/**
 * Computes Levenshtein distance between two strings.
 * @param {string} a 
 * @param {string} b 
 * @returns {number}
 */
export function levenshteinDistance(a, b) {
  const an = a.length;
  const bn = b.length;
  if (an === 0) return bn;
  if (bn === 0) return an;

  const matrix = Array.from({ length: bn + 1 }, () => new Array(an + 1));
  for (let i = 0; i <= an; i++) matrix[0][i] = i;
  for (let j = 0; j <= bn; j++) matrix[j][0] = j;

  for (let j = 1; j <= bn; j++) {
    for (let i = 1; i <= an; i++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      matrix[j][i] = Math.min(
        matrix[j - 1][i] + 1,       // deletion
        matrix[j][i - 1] + 1,       // insertion
        matrix[j - 1][i - 1] + cost // substitution
      );
    }
  }
  return matrix[bn][an];
}

/**
 * Searches code text line by line for regex patterns and extracts matching line numbers and snippets.
 * @param {string} content 
 * @param {RegExp} pattern 
 * @param {string} filePath 
 * @param {number} maxMatches 
 * @returns {Array<{ line: number, snippet: string, match: string }>}
 */
export function findMatchesInContent(content, pattern, filePath = '', maxMatches = 5) {
  const matches = [];
  if (!content || typeof content !== 'string') return matches;

  const lines = content.split(/\r?\n/);
  for (let idx = 0; idx < lines.length; idx++) {
    const line = lines[idx];
    const match = line.match(pattern);
    if (match) {
      matches.push({
        line: idx + 1,
        snippet: line.trim().slice(0, 140),
        match: match[0]
      });
      if (matches.length >= maxMatches) break;
    }
  }
  return matches;
}

/**
 * Rule: NAME_NEAR_MATCH
 * Compares added package name with the popular packages reference list.
 * Only flags near matches (distance 1 or 2, or prefix/suffix typosquatting). Exact matches are not typosquats.
 */
export function checkNameNearMatch(packageName, popularPackages = []) {
  const findings = [];
  const normalized = packageName.toLowerCase().replace(/^@[^/]+\//, ''); // strip scope

  for (const popular of popularPackages) {
    const normPopular = popular.toLowerCase().replace(/^@[^/]+\//, '');
    if (normalized === normPopular) {
      // Exact match is not a typosquat
      continue;
    }

    const dist = levenshteinDistance(normalized, normPopular);
    if (dist <= 2 && Math.abs(normalized.length - normPopular.length) <= 2) {
      findings.push({
        ruleId: 'NAME_NEAR_MATCH',
        severity: 'medium',
        popularPackage: popular,
        distance: dist,
        explanation: `Package name "${packageName}" is very similar to popular package "${popular}" (edit distance: ${dist}). Review for potential typosquatting.`
      });
    }
  }
  return findings;
}

/**
 * Rule: LIFECYCLE_SCRIPT_ADDED and INSTALL_COMMAND_CHANGED
 */
export function checkLifecycleScripts(packageDiff) {
  const findings = [];
  const scriptFields = ['preinstall', 'install', 'postinstall', 'prepare'];

  const headScripts = (packageDiff.scripts) || {};
  const prevScripts = (packageDiff.previousScripts) || {};

  for (const field of scriptFields) {
    const headCmd = headScripts[field];
    const prevCmd = prevScripts[field];

    if (headCmd && !prevCmd) {
      findings.push({
        ruleId: 'LIFECYCLE_SCRIPT_ADDED',
        severity: 'medium',
        scriptType: field,
        command: headCmd,
        explanation: `Newly introduced lifecycle script "${field}": "${headCmd}". Review installation behavior.`
      });
    } else if (headCmd && prevCmd && headCmd !== prevCmd) {
      findings.push({
        ruleId: 'INSTALL_COMMAND_CHANGED',
        severity: 'medium',
        scriptType: field,
        oldCommand: prevCmd,
        newCommand: headCmd,
        explanation: `Lifecycle script "${field}" changed from "${prevCmd}" to "${headCmd}".`
      });
    }
  }

  // Also check hasInstallScript boolean flag from lockfile v3
  if (packageDiff.hasInstallScript && findings.length === 0 && packageDiff.changeType === 'added') {
    findings.push({
      ruleId: 'LIFECYCLE_SCRIPT_ADDED',
      severity: 'medium',
      scriptType: 'install',
      command: 'declared hasInstallScript in lockfile',
      explanation: 'Package declares an install lifecycle script in lockfile v3 descriptors.'
    });
  }

  return findings;
}

/**
 * Static code patterns across files
 */
const PATTERNS = {
  ENVIRONMENT_ACCESS: {
    ruleId: 'ENVIRONMENT_ACCESS',
    severity: 'medium',
    pattern: /\b(?:process\.env|getenv|system\.getenv)\b/,
    description: 'References environment variables which may access sensitive credentials'
  },
  NETWORK_OPERATION: {
    ruleId: 'NETWORK_OPERATION',
    severity: 'medium',
    pattern: /(?:https?\.request|fetch\s*\(|\baxios\b|\bnode-fetch\b|\bcurl\b|\bwget\b|\bnet\.connect\b|new\s+WebSocket\b|\bdgram\.createSocket\b)/,
    description: 'Initiates network or socket operations'
  },
  PROCESS_EXECUTION: {
    ruleId: 'PROCESS_EXECUTION',
    severity: 'high',
    pattern: /(?:\bchild_process\b|\bexecSync\s*\(|\bspawnSync\s*\(|\bexecFile\s*\(|(?<!\.)\bexec\s*\(|(?<!\.)\bspawn\s*\()/,
    description: 'Executes external system processes or shell commands'
  },
  DYNAMIC_EXECUTION: {
    ruleId: 'DYNAMIC_EXECUTION',
    severity: 'high',
    pattern: /(?:\beval\s*\(|new\s+Function\s*\(|\bvm\.runInContext\b|\bvm\.runInThisContext\b)/,
    description: 'Uses dynamic code evaluation (eval / Function constructor)'
  },
  OBFUSCATION_INDICATOR: {
    ruleId: 'OBFUSCATION_INDICATOR',
    severity: 'high',
    pattern: /(?:\\x[0-9a-fA-F]{2}){4,}|(?:Buffer\.from\s*\([^,]+,\s*['"]base64['"]\))|(?:atob\s*\(|unescape\s*\()/,
    description: 'Contains obfuscated hex escape sequences, base64 payload decoding, or encoded strings'
  }
};

/**
 * Analyzes file contents of a package for code heuristics without running code.
 * @param {Array<{ path: string, content: string }>} files 
 * @returns {Array<object>} Static observations
 */
export function analyzePackageFiles(files = []) {
  const observations = [];

  for (const file of files) {
    // Only inspect scripts / code files
    const isCode = /\.(m?js|cjs|ts|sh|bash|py|ps1|bat|cmd)$/i.test(file.path);
    if (!isCode) continue;

    for (const [key, rule] of Object.entries(PATTERNS)) {
      const matches = findMatchesInContent(file.content, rule.pattern, file.path);
      if (matches.length > 0) {
        for (const m of matches) {
          observations.push({
            ruleId: rule.ruleId,
            severity: rule.severity,
            filePath: file.path,
            line: m.line,
            evidenceRef: `${file.path}#L${m.line}`,
            snippet: m.snippet,
            explanation: `${rule.description} at line ${m.line}: "${m.snippet}"`
          });
        }
      }
    }
  }

  return observations;
}
