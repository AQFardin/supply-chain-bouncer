import { readFile, writeFile } from 'node:fs/promises';
import { resolve, join } from 'node:path';

/**
 * Escapes characters that have special meaning in HTML to prevent XSS.
 * All untrusted package text, filenames, observation snippets, and AI inferences must be escaped.
 * @param {string|null|undefined} str 
 * @returns {string} Safe HTML string
 */
export function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Determines the top 3 key reasons supporting the overall recommendation.
 * @param {object} evidence 
 * @param {object|null} findings 
 * @returns {Array<string>} Top 3 reasons
 */
export function deriveKeyReasons(evidence, findings = null) {
  const reasons = [];

  // 1. Critical or high observations from deterministic evidence
  const criticalObs = evidence.observations.filter((o) => o.severity === 'critical');
  const highObs = evidence.observations.filter((o) => o.severity === 'high');
  const mediumObs = evidence.observations.filter((o) => o.severity === 'medium');

  for (const obs of [...criticalObs, ...highObs, ...mediumObs]) {
    if (reasons.length >= 3) break;
    reasons.push(`${obs.packageName} (${obs.ruleId}): ${obs.explanation}`);
  }

  // 2. High severity findings from Bob subagents if available
  if (findings && Array.isArray(findings.investigations)) {
    for (const inv of findings.investigations) {
      if (reasons.length >= 3) break;
      if (Array.isArray(inv.findings)) {
        for (const f of inv.findings) {
          if (reasons.length >= 3) break;
          if (f.severity === 'critical' || f.severity === 'high') {
            reasons.push(`[${inv.role}] ${f.observation} — ${f.interpretation}`);
          }
        }
      }
    }
  }

  // 3. Fallbacks if clean or fewer reasons
  if (reasons.length === 0) {
    if (evidence.collectionStatus === 'complete' && evidence.observations.length === 0) {
      reasons.push('No suspicious lifecycle scripts, network operations, or process calls detected.');
      reasons.push('All downloaded artifact bytes matched published registry and lockfile integrity.');
      reasons.push('Package version bump follows standard semver progression without typosquat flags.');
    } else if (evidence.incompleteReasons && evidence.incompleteReasons.length > 0) {
      for (const inc of evidence.incompleteReasons) {
        if (reasons.length >= 3) break;
        reasons.push(`Coverage limitation: ${inc}`);
      }
    }
  }

  while (reasons.length < 3 && reasons.length > 0) {
    if (evidence.collectionStatus === 'complete') {
      reasons.push('Deterministic evidence collection completed successfully across all changed packages.');
    } else {
      reasons.push('Requires manual operator review to verify safety before approval.');
    }
  }

  return reasons.slice(0, 3);
}

/**
 * Builds normalized report data structure from evidence and optional findings/decision.
 * @param {object} evidence 
 * @param {object|null} findings 
 * @param {object|null} decision 
 * @param {string} runDir 
 * @returns {object} Report data conforming to schemas/report.schema.json
 */
export function buildReportData(evidence, findings = null, decision = null, runDir = '') {
  // Determine overall recommendation
  let overallRecommendation = 'ALLOW';

  if (decision && decision.decision) {
    overallRecommendation = decision.decision;
  } else if (findings && findings.aggregateRecommendation) {
    overallRecommendation = findings.aggregateRecommendation;
  } else {
    // Deterministic fallback based on evidence
    const hasCritical = evidence.observations.some((o) => o.severity === 'critical');
    const hasHigh = evidence.observations.some((o) => o.severity === 'high');
    const hasMedium = evidence.observations.some((o) => o.severity === 'medium');

    if (hasCritical || evidence.collectionStatus === 'quarantine') {
      overallRecommendation = 'BLOCK';
    } else if (hasHigh || hasMedium || evidence.collectionStatus === 'incomplete') {
      overallRecommendation = 'QUARANTINE';
    } else {
      overallRecommendation = 'ALLOW';
    }
  }

  const keyReasons = deriveKeyReasons(evidence, findings);

  let reviewStatus = 'Awaiting human review';
  if (decision && decision.decision) {
    reviewStatus = `Decided: ${decision.decision} by ${decision.reviewerLabel || 'reviewer'} (${decision.mode || 'mode'}) at ${decision.createdAt || ''}`;
  }

  const reviewCmd = runDir
    ? `node src/cli.mjs review --run "${runDir}" --interactive --mode trusted-local-demo`
    : `node src/cli.mjs review --run <run-dir> --interactive --mode trusted-local-demo`;

  return {
    schemaVersion: '1.0',
    runId: evidence.runId || `run-${Date.now()}`,
    subjectDigest: evidence.subjectDigest,
    generatedAt: new Date().toISOString(),
    mode: evidence.mode || 'live',
    collectionStatus: evidence.collectionStatus || 'complete',
    overallRecommendation,
    keyReasons,
    packages: evidence.packages || [],
    investigations: (findings && findings.investigations) || null,
    observations: evidence.observations || [],
    unknowns: evidence.unknowns || [],
    reviewStatus,
    reviewCommand: reviewCmd,
    decision: decision || null
  };
}

/**
 * Renders a self-contained, offline-ready HTML report conforming to Section 9 layout.
 * @param {object} report 
 * @returns {string} Rendered HTML
 */
export function renderHtmlReport(report) {
  const recBadgeClass =
    report.overallRecommendation === 'ALLOW'
      ? 'badge-allow'
      : report.overallRecommendation === 'BLOCK'
      ? 'badge-block'
      : 'badge-quarantine';

  // Packages table rows
  const packageRows = report.packages.map((pkg) => {
    const directBadge = pkg.isDirect
      ? '<span class="badge badge-direct">DIRECT</span>'
      : '<span class="badge badge-transitive">TRANSITIVE</span>';
    
    const changeBadge = `<span class="badge badge-change">${escapeHtml(pkg.changeType.toUpperCase())}</span>`;
    const scriptIndicator = pkg.hasInstallScript ? '⚠️ Yes' : 'No';
    const versionDiff = `${escapeHtml(pkg.previousVersion || 'none')} &rarr; <strong>${escapeHtml(pkg.version || 'none')}</strong>`;
    
    const prov = pkg.provenance || {};
    const provSummary = prov.publishedAt
      ? `${escapeHtml(prov.publishedAt.slice(0, 10))} (${escapeHtml(prov.maintainersCount || 1)} maintainers)`
      : 'N/A';

    return `
      <tr>
        <td><strong>${escapeHtml(pkg.name)}</strong></td>
        <td>${changeBadge}</td>
        <td>${directBadge}</td>
        <td>${versionDiff}</td>
        <td><code>${escapeHtml(pkg.location)}</code></td>
        <td>${scriptIndicator}</td>
        <td>${provSummary}</td>
        <td><code class="code-mono">${escapeHtml((pkg.integrity || '').slice(0, 24))}...</code></td>
      </tr>
    `;
  }).join('');

  // Observations snippets
  const observationsList = report.observations.length === 0
    ? '<p class="text-muted">Zero suspicious static patterns or integrity mismatches observed.</p>'
    : report.observations.map((obs) => {
        const severityClass = `sev-${escapeHtml(obs.severity)}`;
        const snippetBlock = obs.snippet
          ? `<pre class="code-snippet"><code>${escapeHtml(obs.snippet)}</code></pre>`
          : '';

        return `
          <div class="card-item ${severityClass}">
            <div class="item-header">
              <span class="badge badge-${escapeHtml(obs.severity)}">${escapeHtml(obs.severity.toUpperCase())}</span>
              <strong>${escapeHtml(obs.packageName)}</strong> &mdash; <code>${escapeHtml(obs.ruleId)}</code>
              <span class="text-muted text-sm">${escapeHtml(obs.evidenceRef || '')}</span>
            </div>
            <div class="item-body">
              <p>${escapeHtml(obs.explanation)}</p>
              ${snippetBlock}
            </div>
          </div>
        `;
      }).join('');

  // Investigations cards (Bob's 3 roles)
  let investigationsSection = '';
  if (report.investigations && report.investigations.length > 0) {
    const roleCards = report.investigations.map((inv) => {
      const findingsList = (inv.findings || []).map((f) => `
        <div class="finding-box">
          <div class="finding-header">
            <span class="badge badge-${escapeHtml(f.severity)}">${escapeHtml(f.severity.toUpperCase())}</span>
            <strong>Observation:</strong> ${escapeHtml(f.observation)}
          </div>
          <p><strong>Interpretation:</strong> ${escapeHtml(f.interpretation)}</p>
          ${f.benignExplanation ? `<p class="text-muted"><strong>Benign Context:</strong> ${escapeHtml(f.benignExplanation)}</p>` : ''}
          <p><strong>Suggested Action:</strong> ${escapeHtml(f.suggestedAction)}</p>
        </div>
      `).join('');

      return `
        <div class="investigator-card">
          <div class="inv-header">
            <h4>Role: ${escapeHtml(inv.role)}</h4>
            <span class="badge badge-${escapeHtml(inv.recommendation.toLowerCase())}">${escapeHtml(inv.recommendation)}</span>
          </div>
          <div class="inv-findings">${findingsList || '<p class="text-muted">No findings reported by this role.</p>'}</div>
        </div>
      `;
    }).join('');

    investigationsSection = `
      <section class="section">
        <h2>4. Coordinated Bob Investigator Results</h2>
        <div class="investigators-grid">${roleCards}</div>
      </section>
    `;
  } else {
    investigationsSection = `
      <section class="section">
        <h2>4. Bob Investigator Results</h2>
        <div class="callout callout-info">
          <p><strong>Awaiting Bob Agent Review:</strong> Run the <code>supply-chain-bouncer</code> skill in Bob IDE against this evidence bundle to coordinate the Typosquat Detective, Provenance Auditor, and Behavior Analyst.</p>
        </div>
      </section>
    `;
  }

  // Key reasons list
  const reasonsList = report.keyReasons.map((r) => `<li>${escapeHtml(r)}</li>`).join('');

  // Unknowns list
  const unknownsList = (report.unknowns || []).map((u) => `<li>${escapeHtml(u)}</li>`).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Supply Chain Bouncer — Evidence & Review Report</title>
  <style>
    :root {
      --bg: #0f172a;
      --surface: #1e293b;
      --surface-border: #334155;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --accent-allow: #10b981;
      --accent-quarantine: #f59e0b;
      --accent-block: #ef4444;
      --primary: #38bdf8;
      --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: var(--font); background: var(--bg); color: var(--text); padding: 2rem; line-height: 1.5; }
    .container { max-width: 1200px; margin: 0 auto; }
    header { display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 1px solid var(--surface-border); padding-bottom: 1.5rem; margin-bottom: 2rem; }
    h1 { font-size: 1.75rem; font-weight: 700; color: var(--text); }
    .subtitle { color: var(--text-muted); font-size: 0.9rem; margin-top: 0.25rem; }
    .meta-badges { display: flex; gap: 0.5rem; flex-wrap: wrap; }
    
    .badge { display: inline-block; padding: 0.25rem 0.6rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; }
    .badge-allow { background: rgba(16, 185, 129, 0.2); color: var(--accent-allow); border: 1px solid var(--accent-allow); }
    .badge-quarantine { background: rgba(245, 158, 11, 0.2); color: var(--accent-quarantine); border: 1px solid var(--accent-quarantine); }
    .badge-block { background: rgba(239, 68, 68, 0.2); color: var(--accent-block); border: 1px solid var(--accent-block); }
    .badge-direct { background: rgba(56, 189, 248, 0.15); color: var(--primary); }
    .badge-transitive { background: rgba(148, 163, 184, 0.15); color: var(--text-muted); }
    .badge-change { background: var(--surface-border); color: var(--text); }
    .badge-critical { background: rgba(239, 68, 68, 0.25); color: #fca5a5; }
    .badge-high { background: rgba(249, 115, 22, 0.25); color: #fdba74; }
    .badge-medium { background: rgba(245, 158, 11, 0.25); color: #fde68a; }
    .badge-low { background: rgba(56, 189, 248, 0.2); color: #bae6fd; }

    .banner { background: var(--surface); border: 2px solid var(--surface-border); border-radius: 0.75rem; padding: 1.5rem; margin-bottom: 2rem; display: flex; gap: 1.5rem; align-items: center; }
    .banner.ALLOW { border-color: var(--accent-allow); }
    .banner.QUARANTINE { border-color: var(--accent-quarantine); }
    .banner.BLOCK { border-color: var(--accent-block); }
    .verdict-tag { font-size: 1.75rem; font-weight: 800; padding: 0.75rem 1.5rem; border-radius: 0.5rem; text-align: center; }
    .verdict-tag.ALLOW { background: var(--accent-allow); color: #000; }
    .verdict-tag.QUARANTINE { background: var(--accent-quarantine); color: #000; }
    .verdict-tag.BLOCK { background: var(--accent-block); color: #fff; }
    
    .reasons-box h3 { font-size: 1rem; margin-bottom: 0.5rem; color: var(--text); }
    .reasons-box ul { margin-left: 1.25rem; font-size: 0.95rem; color: var(--text-muted); }
    .reasons-box li { margin-bottom: 0.25rem; }

    .section { background: var(--surface); border: 1px solid var(--surface-border); border-radius: 0.75rem; padding: 1.5rem; margin-bottom: 1.5rem; }
    .section h2 { font-size: 1.15rem; font-weight: 700; margin-bottom: 1rem; border-bottom: 1px solid var(--surface-border); padding-bottom: 0.5rem; color: var(--primary); }

    table { width: 100%; border-collapse: collapse; font-size: 0.875rem; }
    th { text-align: left; padding: 0.75rem; border-bottom: 2px solid var(--surface-border); color: var(--text-muted); }
    td { padding: 0.75rem; border-bottom: 1px solid var(--surface-border); }
    tr:last-child td { border-bottom: none; }
    
    .card-item { background: rgba(15, 23, 42, 0.6); border: 1px solid var(--surface-border); border-radius: 0.5rem; padding: 1rem; margin-bottom: 0.75rem; border-left: 4px solid var(--text-muted); }
    .card-item.sev-critical { border-left-color: var(--accent-block); }
    .card-item.sev-high { border-left-color: #f97316; }
    .card-item.sev-medium { border-left-color: var(--accent-quarantine); }
    .item-header { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.5rem; flex-wrap: wrap; }
    .code-snippet { background: #000; padding: 0.75rem; border-radius: 0.35rem; font-size: 0.8rem; overflow-x: auto; margin-top: 0.5rem; color: #a5f3fc; }
    .code-mono { font-family: monospace; font-size: 0.8rem; }
    
    .investigators-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 1rem; }
    .investigator-card { background: rgba(15, 23, 42, 0.7); border: 1px solid var(--surface-border); border-radius: 0.5rem; padding: 1rem; }
    .inv-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem; border-bottom: 1px solid var(--surface-border); padding-bottom: 0.5rem; }
    .finding-box { background: rgba(30, 41, 59, 0.7); padding: 0.75rem; border-radius: 0.35rem; margin-bottom: 0.5rem; font-size: 0.85rem; }
    .finding-box p { margin-top: 0.25rem; }

    .callout { padding: 1rem; border-radius: 0.5rem; border-left: 4px solid; margin-top: 0.5rem; font-size: 0.9rem; }
    .callout-info { background: rgba(56, 189, 248, 0.1); border-left-color: var(--primary); }
    .terminal-box { background: #000; border: 1px solid var(--surface-border); border-radius: 0.5rem; padding: 1rem; font-family: monospace; color: #4ade80; font-size: 0.875rem; margin-top: 0.5rem; overflow-x: auto; }
    .text-sm { font-size: 0.75rem; }
    .text-muted { color: var(--text-muted); }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h1>Supply Chain Bouncer &mdash; Dependency Review</h1>
        <p class="subtitle">Run ID: <code>${escapeHtml(report.runId)}</code> &bull; Subject: <code>${escapeHtml(report.subjectDigest.slice(0, 16))}...</code></p>
      </div>
      <div class="meta-badges">
        <span class="badge ${recBadgeClass}">${escapeHtml(report.overallRecommendation)}</span>
        <span class="badge badge-change">MODE: ${escapeHtml(report.mode.toUpperCase())}</span>
        <span class="badge badge-change">STATUS: ${escapeHtml(report.collectionStatus.toUpperCase())}</span>
      </div>
    </header>

    <!-- 1. Recommendation & Top 3 Key Reasons -->
    <div class="banner ${escapeHtml(report.overallRecommendation)}">
      <div class="verdict-tag ${escapeHtml(report.overallRecommendation)}">
        ${escapeHtml(report.overallRecommendation)}
      </div>
      <div class="reasons-box">
        <h3>Top Findings &amp; Recommendation Rationale</h3>
        <ul>${reasonsList}</ul>
      </div>
    </div>

    <!-- 2. Human Review & Decision Mechanism -->
    <section class="section">
      <h2>1. Human Review Decision Status</h2>
      <p><strong>Current State:</strong> <span class="badge ${recBadgeClass}">${escapeHtml(report.reviewStatus)}</span></p>
      <p class="text-muted" style="margin-top: 0.5rem;">To record an approved, quarantined, or blocked human decision against this exact input snapshot, run the review command in your terminal:</p>
      <div class="terminal-box">${escapeHtml(report.reviewCommand)}</div>
    </section>

    <!-- 3. Packages Table -->
    <section class="section">
      <h2>2. Changed Dependencies (${report.packages.length} instances)</h2>
      <div style="overflow-x: auto;">
        <table>
          <thead>
            <tr>
              <th>Package Name</th>
              <th>Change</th>
              <th>Direct/Transitive</th>
              <th>Version Diff</th>
              <th>Location</th>
              <th>Install Script</th>
              <th>Provenance Metadata</th>
              <th>Integrity SRI</th>
            </tr>
          </thead>
          <tbody>${packageRows}</tbody>
        </table>
      </div>
    </section>

    <!-- 4. Investigator Results -->
    ${investigationsSection}

    <!-- 5. Static Observations & Cited Evidence -->
    <section class="section">
      <h2>3. Deterministic Static Observations (${report.observations.length})</h2>
      <div>${observationsList}</div>
    </section>

    <!-- 6. Unknowns & Coverage Limitations -->
    <section class="section">
      <h2>5. Coverage Limits &amp; Explicit Unknowns</h2>
      <ul style="margin-left: 1.25rem; color: var(--text-muted); font-size: 0.9rem;">${unknownsList}</ul>
    </section>

    <!-- 7. Remediation Guidance -->
    <section class="section">
      <h2>6. Remediation &amp; Compatibility Guidance</h2>
      <p style="font-size: 0.9rem; color: var(--text-muted);">
        If a package is held under <strong>QUARANTINE</strong> or <strong>BLOCK</strong>:
      </p>
      <ul style="margin-left: 1.25rem; color: var(--text-muted); font-size: 0.9rem; margin-top: 0.5rem;">
        <li><strong>Replace:</strong> Ask Bob to recommend a reviewed alternative package with matching functionality.</li>
        <li><strong>Rollback:</strong> Remove the dependency declaration and revert lockfile changes with scripts disabled.</li>
        <li><strong>Approve with Rationale:</strong> If the lifecycle script or observation is expected (e.g. native compilation), record an ALLOW decision citing the benign explanation.</li>
      </ul>
    </section>
  </div>
</body>
</html>`;
}

/**
 * Loads run inputs from a directory and generates report.json and report.html.
 * @param {string} runDir Directory containing evidence.json and optional findings.json / decision.json
 * @returns {Promise<{ reportJsonPath: string, reportHtmlPath: string, reportData: object }>}
 */
export async function generateReport(runDir) {
  const resolvedDir = resolve(runDir);
  const evidencePath = join(resolvedDir, 'evidence.json');

  let rawEvidence;
  try {
    rawEvidence = await readFile(evidencePath, 'utf8');
  } catch (err) {
    throw new Error(`Cannot generate report: missing evidence.json in ${resolvedDir}: ${err.message}`);
  }

  const evidence = JSON.parse(rawEvidence);

  // Read optional findings.json (from Bob investigation)
  let findings = null;
  try {
    const rawFindings = await readFile(join(resolvedDir, 'findings.json'), 'utf8');
    findings = JSON.parse(rawFindings);
  } catch {}

  // Read optional decision.json (from human review)
  let decision = null;
  try {
    const rawDecision = await readFile(join(resolvedDir, 'decision.json'), 'utf8');
    decision = JSON.parse(rawDecision);
  } catch {}

  const reportData = buildReportData(evidence, findings, decision, resolvedDir);
  const htmlContent = renderHtmlReport(reportData);

  const reportJsonPath = join(resolvedDir, 'report.json');
  const reportHtmlPath = join(resolvedDir, 'report.html');

  await writeFile(reportJsonPath, JSON.stringify(reportData, null, 2), 'utf8');
  await writeFile(reportHtmlPath, htmlContent, 'utf8');

  return {
    reportJsonPath,
    reportHtmlPath,
    reportData
  };
}
