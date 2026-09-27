import { createHash } from 'node:crypto';
import { readFile, readdir, lstat, realpath } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { computeSubjectDigest, loadProjectInputs } from './input.mjs';
import { compareLockfiles } from './lockfile-diff.mjs';
import { discoverFixturePackageFiles } from './collector.mjs';
import { validateRegistryUrl } from './registry.mjs';
import { buildReportData } from './report.mjs';

export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export const MODE = 'trusted-local-demo';
export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
export const digestEntries = entries => sha256(JSON.stringify(entries));
export const terminalText = value => String(value).replace(/[\x00-\x08\x0b-\x1f\x7f-\x9f]/g, '').replace(/[\u202a-\u202e\u2066-\u2069]/g, '');

export class ReviewError extends Error {
  constructor(message, exitCode = 3) { super(message); this.exitCode = exitCode; }
}

export function requireLocalMode(mode = MODE, env = process.env) {
  if (mode !== MODE) throw new ReviewError('Only trusted-local-demo is implemented. Signing is not supported.');
  if (['CI', 'GITHUB_ACTIONS', 'GITLAB_CI', 'TF_BUILD', 'BUILD_BUILDID', 'JENKINS_URL'].some(key => env[key] && !['0', 'false'].includes(env[key].toLowerCase()))) {
    throw new ReviewError('trusted-local-demo is local only and cannot authorize a CI job.');
  }
}

async function bytes(path, optional = false) {
  try { return await readFile(path); }
  catch (err) { if (optional && err.code === 'ENOENT') return null; throw new ReviewError(`Cannot read required file: ${path}`); }
}

export async function readJson(path, optional = false) {
  const raw = await bytes(path, optional);
  if (raw === null) return { raw: null, data: null };
  try { return { raw, data: JSON.parse(raw.toString('utf8')) }; }
  catch { throw new ReviewError(`Malformed JSON: ${path}`); }
}

// These files describe the installed scanner release, including this local extension.
async function releaseFiles(dir, prefix = '') {
  const entries = [];
  for (const item of (await readdir(dir, { withFileTypes: true })).sort((a, b) => a.name < b.name ? -1 : 1)) {
    const label = prefix + item.name;
    if (item.isSymbolicLink()) throw new ReviewError(`Unsupported scanner symlink: ${label}`);
    if (item.isDirectory()) entries.push(...await releaseFiles(join(dir, item.name), label + '/'));
    else if (item.isFile()) entries.push([label, sha256(await bytes(join(dir, item.name)))]);
  }
  return entries;
}

function validatePolicy(policy) {
  if (policy?.schemaVersion !== '1.0' || !Array.isArray(policy.rules) || !policy.gate?.allowedModes?.includes(MODE)) {
    throw new ReviewError('Unsupported policy or trusted-local-demo is disabled.');
  }
  const seen = new Set();
  for (const rule of policy.rules) {
    if (!rule.id || seen.has(rule.id) || !['ALLOW', 'QUARANTINE', 'BLOCK'].includes(rule.action) || typeof rule.hardViolation !== 'boolean') {
      throw new ReviewError('Invalid or duplicate policy rule.');
    }
    seen.add(rule.id);
  }
}

function checkProject(project) {
  if (project.packageJson.workspaces || project.lockfile.packages['']?.workspaces) throw new ReviewError('Workspaces are unsupported; use one dependency root.');
  for (const bucket of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
    const manifest = Object.entries(project.packageJson[bucket] || {}).sort();
    const lock = Object.entries(project.lockfile.packages['']?.[bucket] || {}).sort();
    if (JSON.stringify(manifest) !== JSON.stringify(lock)) throw new ReviewError(`Manifest and lockfile root ${bucket} differ; rescan consistent inputs.`);
  }
  if (Object.values(project.lockfile.packages).some(entry => entry.link)) throw new ReviewError('Linked dependencies are unsupported.');
}

function checkNpmrc(raw) {
  if (!raw) return;
  for (const line of raw.toString('utf8').split(/\r?\n/).map(s => s.trim())) {
    if (!line || line.startsWith('#') || line.startsWith(';')) continue;
    if (/^ignore-scripts\s*=\s*true$/i.test(line)) continue;
    if (/^registry\s*=\s*https:\/\/(registry\.npmjs\.org|registry\.yarnpkg\.com)\/?$/i.test(line)) continue;
    throw new ReviewError('Unsupported project .npmrc setting. Only the public registry and ignore-scripts=true are supported.');
  }
}

/** Read current bytes every time; never accept a cached report as permission. */
export async function loadReviewContext({ base, head, run, mode = MODE, env = process.env }) {
  requireLocalMode(mode, env);
  if (!base || !head || !run) throw new ReviewError('--base, --head and --run are required.');
  const baseDir = await realpath(resolve(base));
  const headDir = await realpath(resolve(head));
  const runDir = await realpath(resolve(run));
  const baseInputs = await loadProjectInputs(baseDir, 'base');
  const headInputs = await loadProjectInputs(headDir, 'candidate');
  checkProject(baseInputs); checkProject(headInputs);
  const subject = await computeSubjectDigest(baseDir, headDir);
  const evidenceFile = await readJson(join(runDir, 'evidence.json'));
  const findingsFile = await readJson(join(runDir, 'findings.json'), true);
  const policyFile = await readJson(join(ROOT, 'policy/policy.json'));
  const packageFile = await readJson(join(ROOT, 'package.json'));
  const evidence = evidenceFile.data;
  const findings = findingsFile.data;
  const policy = policyFile.data;
  validatePolicy(policy);
  // Reuses the existing strict schemas, role uniqueness and citation checks.
  const report = buildReportData(evidence, findings);
  if (evidence.schemaVersion !== '1.0' || findings?.schemaVersion && findings.schemaVersion !== '1.0' || findings?.investigations.some(i => i.schemaVersion !== '1.0')) {
    throw new ReviewError('Unsupported evidence or investigation schema version.');
  }
  if (evidence.subjectDigest !== subject.subjectDigest) throw new ReviewError('Evidence is stale: dependency inputs changed. Rescan and investigate again.', 2);
  if (evidence.policyDigest !== sha256(JSON.stringify(policy))) throw new ReviewError('Evidence uses a different policy. Rescan and investigate again.', 2);
  if (evidence.scannerVersion !== packageFile.data.version) throw new ReviewError('Evidence uses a different scanner version. Rescan and investigate again.', 2);

  const diff = compareLockfiles(baseInputs.lockfile, headInputs.lockfile);
  const columns = ['name', 'location', 'version', 'previousVersion', 'changeType', 'isDirect', 'resolved', 'integrity'];
  const projection = packages => packages.map(pkg => columns.map(key => pkg[key] ?? null)).sort((a, b) => a[1] < b[1] ? -1 : 1);
  if (JSON.stringify(projection(diff.packages)) !== JSON.stringify(projection(evidence.packages))) throw new ReviewError('Evidence package coverage does not match the current lockfile diff.');

  const hardBlocks = [];
  const incomplete = [...(evidence.incompleteReasons || [])];
  if (evidence.collectionStatus !== 'complete') incomplete.push(`Collection status: ${evidence.collectionStatus}`);
  if (!report.investigationComplete) incomplete.push('All three Bob investigators must complete before ALLOW.');
  for (const inv of findings?.investigations || []) {
    for (const pkg of diff.packages.filter(pkg => ['added', 'changed'].includes(pkg.changeType))) {
      const packageRefs = [`evidence.packages[${pkg.location}]`];
      if (diff.packages.filter(p => p.name === pkg.name).length === 1) packageRefs.push(`evidence.packages[${pkg.name}]`);
      const observationRefs = evidence.observations.filter(obs => obs.packageLocation === pkg.location).map(obs => obs.id);
      if (!inv.findings.some(f => f.evidenceIds.some(id => [...packageRefs, ...observationRefs].includes(id)))) incomplete.push(`${inv.role}: no package-specific evidence cited for ${pkg.location}`);
    }
  }
  if (evidence.mode === 'cached') incomplete.push('Cached evidence is unsupported by this local gate; rescan in live or fixture mode.');
  for (const obs of evidence.observations) {
    if (obs.ruleId === 'ARTIFACT_INTEGRITY_MISMATCH') hardBlocks.push(`${obs.id}: artifact integrity mismatch`);
    if (obs.ruleId === 'UNSUPPORTED_OR_INCOMPLETE') incomplete.push(`${obs.id}: required evidence missing or unsupported`);
    for (const rule of policy.rules.filter(rule => rule.hardViolation)) {
      if (rule.id === obs.ruleId || rule.id.replace(/^(BLOCK|QUARANTINE|FLAG)_/, '') === obs.ruleId) {
        (rule.action === 'BLOCK' ? hardBlocks : rule.action === 'QUARANTINE' ? incomplete : []).push(`${rule.id}: ${obs.id}`);
      }
    }
  }

  const fixtureEntries = [];
  for (const pkg of diff.packages.filter(pkg => ['added', 'changed'].includes(pkg.changeType))) {
    if (pkg.unsupported) incomplete.push(`${pkg.name}: unsupported source`);
    try { validateRegistryUrl(pkg.resolved); } catch { incomplete.push(`${pkg.name}: unsupported registry URL`); }
    if (!pkg.integrity) incomplete.push(`${pkg.name}: missing lockfile integrity`);
    if (evidence.packages.find(p => p.location === pkg.location)?.omittedCoverage?.length) incomplete.push(`${pkg.name}: omitted file coverage`);
    if (evidence.mode === 'fixture') {
      const files = await discoverFixturePackageFiles(pkg.name, headDir);
      const digest = sha256(files.sort((a, b) => a.path < b.path ? -1 : 1).map(f => JSON.stringify([f.path, f.content]) + '\n').join(''));
      fixtureEntries.push([pkg.location, digest]);
      const source = evidence.sources.find(s => s.sourceType === 'fixture' && s.pathOrUrl === `fixture:${pkg.name}@${pkg.version}`);
      if (!files.length || source?.contentDigest !== `sha256-fixture-files:${digest}`) incomplete.push(`${pkg.name}: fixture bytes are missing or differ from the collected source`);
    } else if (evidence.mode === 'live') {
      const sri = /^sha512-([A-Za-z0-9+/]{86}==)$/.exec(pkg.integrity || '');
      const source = evidence.sources.find(s => s.sourceType === 'live' && s.pathOrUrl === pkg.resolved);
      if (!sri || Buffer.from(sri[1], 'base64').toString('base64') !== sri[1]) incomplete.push(`${pkg.name}: invalid SHA-512 integrity`);
      else if (!source) incomplete.push(`${pkg.name}: missing verified artifact source`);
      else if (source.contentDigest !== pkg.integrity) hardBlocks.push(`${pkg.name}: artifact digest differs from lockfile integrity`);
    }
    const metadata = evidence.sources.find(s => s.pathOrUrl === `https://registry.npmjs.org/${pkg.name}` && s.sourceType === (evidence.mode === 'fixture' ? 'synthetic' : 'live'));
    if (!metadata || !/^sha256-metadata:[a-f0-9]{64}$/.test(metadata.contentDigest)) incomplete.push(`${pkg.name}: missing metadata source digest`);
  }

  // Fixed ordered contract. Nested release/fixture lists have sorted paths only.
  const entries = [
    ['contract', sha256('supply-chain-bouncer-local-review-v1')],
    ['base:directory', sha256(baseDir)], ['head:directory', sha256(headDir)],
    ...subject.inputs.map(input => [input.label, input.sha256])
  ];
  for (const [label, dir] of [['base', baseDir], ['head', headDir]]) {
    for (const name of ['.npmrc', 'npm-shrinkwrap.json']) {
      const raw = await bytes(join(dir, name), true);
      if (name === '.npmrc') checkNpmrc(raw);
      entries.push([`${label}:${name}`, raw === null ? 'ABSENT' : sha256(raw)]);
    }
  }
  entries.push(
    ['policy:policy.json', sha256(policyFile.raw)],
    ['policy:popular-packages.json', sha256(await bytes(join(ROOT, 'policy/popular-packages.json')))],
    ['scanner:package.json', sha256(packageFile.raw)]
  );
  const scannerLock = await bytes(join(ROOT, 'package-lock.json'), true);
  entries.push(
    ['scanner:package-lock.json', scannerLock === null ? 'ABSENT' : sha256(scannerLock)],
    ['scanner:release', digestEntries([...await releaseFiles(join(ROOT, 'src'), 'src/'), ...await releaseFiles(join(ROOT, 'schemas'), 'schemas/')])],
    ['run:evidence.json', sha256(evidenceFile.raw)],
    ['run:findings.json', findingsFile.raw === null ? 'ABSENT' : sha256(findingsFile.raw)],
    ['fixture:files', digestEntries(fixtureEntries)]
  );
  return { baseDir, headDir, runDir, evidence, findings, report, entries, subjectDigest: subject.subjectDigest, reviewDigest: digestEntries(entries), hardBlocks: [...new Set(hardBlocks)], incomplete: [...new Set(incomplete)] };
}

export async function assertNewFile(path) {
  try { await lstat(path); }
  catch (err) { if (err.code === 'ENOENT') return; throw err; }
  throw new ReviewError(`Refusing to overwrite an existing file: ${path}`);
}
