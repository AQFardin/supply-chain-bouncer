import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cp, mkdtemp, mkdir, readFile, writeFile, rm, access } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve, relative, isAbsolute } from 'node:path';
import { spawnSync } from 'node:child_process';
import { ROOT, digestEntries, loadReviewContext, sha256 } from '../src/review-state.mjs';
import { evaluateGate, gateWithMarker } from '../src/gate.mjs';
import { reviewInteractively } from '../src/menu.mjs';

async function fixture(t) {
  const dir = await mkdtemp(join(tmpdir(), 'bouncer-local-gate-'));
  t.after(async () => {
    const rel = relative(resolve(tmpdir()), resolve(dir));
    assert.ok(rel && !rel.startsWith('..') && !isAbsolute(rel));
    await rm(dir, { recursive: true, force: true });
  });
  await cp(join(ROOT, 'fixtures/suspicious'), join(dir, 'fixture'), { recursive: true });
  await mkdir(join(dir, 'run'));
  for (const name of ['evidence.json', 'findings.json']) await cp(join(ROOT, 'reports/demo/suspicious-fixture', name), join(dir, 'run', name));
  return { base: join(dir, 'fixture/base'), head: join(dir, 'fixture/head'), run: join(dir, 'run'), decision: join(dir, 'test-decision.json'), env: {}, dir };
}

async function update(path, change) {
  const data = JSON.parse(await readFile(path, 'utf8'));
  change(data);
  await writeFile(path, JSON.stringify(data, null, 2));
}

async function review(options, choice = 'ALLOW', extra = {}) {
  // Automated test answers, never a real human approval or Bob session.
  const answers = [choice, 'Automated test only: accept synthetic fixture warnings.', 'automated-test'];
  let transcript = '';
  const saved = await reviewInteractively(options, { ask: async () => { assert.ok(answers.length, 'unexpected extra menu prompt'); return answers.shift(); }, write: text => { transcript += text; }, ...extra });
  return { ...saved, transcript };
}

async function rebindDecision(options, mutate) {
  await update(options.decision, mutate);
  const hash = sha256(await readFile(options.decision));
  await update(options.decision + '.binding.json', binding => { binding.decisionDigest = hash; });
}

test('review defaults to QUARANTINE, shows hashes, evidence and Bob advice, and writes compatible records', async t => {
  const options = await fixture(t);
  const saved = await review(options, '');
  assert.equal(saved.decision.decision, 'QUARANTINE');
  assert.match(saved.transcript, /SYNTHETIC FIXTURE/);
  assert.match(saved.transcript, /Bob recommendation: BLOCK/);
  assert.match(saved.transcript, /base:package-lock.json/);
  assert.match(saved.transcript, /obs-mock-telemetry-reporter/);
  assert.match(saved.transcript, /timestamp predates evidence/);
  assert.equal((await evaluateGate(options)).exitCode, 2);
});

test('ALLOW accepts complete reviewable warnings; marker exists only after gate success', async t => {
  const options = await fixture(t);
  await review(options);
  const marker = join(options.dir, 'permitted.txt');
  assert.equal((await gateWithMarker(options, marker)).exitCode, 0);
  assert.match(await readFile(marker, 'utf8'), /No package code was executed/);
});

test('human BLOCK returns 4 and prevents the harmless downstream marker', async t => {
  const options = await fixture(t);
  await review(options, 'BLOCK');
  const marker = join(options.dir, 'withheld.txt');
  assert.equal((await gateWithMarker(options, marker)).exitCode, 4);
  await assert.rejects(access(marker));
});

test('missing or malformed decision or binding never passes', async t => {
  const options = await fixture(t);
  assert.equal((await evaluateGate(options)).exitCode, 2);
  await writeFile(options.decision, '{');
  assert.equal((await evaluateGate(options)).exitCode, 2);
  await rm(options.decision);
  await review(options);
  await rm(options.decision + '.binding.json');
  assert.equal((await evaluateGate(options)).exitCode, 2);
});

for (const [label, target] of [
  ['candidate lockfile', o => join(o.head, 'package-lock.json')],
  ['base manifest', o => join(o.base, 'package.json')],
  ['evidence bytes', o => join(o.run, 'evidence.json')],
  ['findings bytes', o => join(o.run, 'findings.json')]
]) test(`even whitespace changes in ${label} invalidate approval`, async t => {
  const options = await fixture(t);
  await review(options);
  const path = target(options);
  await writeFile(path, (await readFile(path, 'utf8')) + '\n');
  assert.equal((await evaluateGate(options)).exitCode, 2);
});

test('adding an optional .npmrc changes the binding', async t => {
  const options = await fixture(t);
  await review(options);
  await writeFile(join(options.head, '.npmrc'), 'ignore-scripts=true\n');
  assert.equal((await evaluateGate(options)).exitCode, 2);
});

test('changed fixture bytes invalidate approval without executing target code', async t => {
  const options = await fixture(t);
  await review(options);
  await writeFile(join(options.dir, 'fixture/package-files/mock-telemetry-reporter/setup.js'), '// changed inert text');
  assert.equal((await evaluateGate(options)).exitCode, 2);
});

test('missing investigators and incomplete collections cannot be allowed even with a matching forged local decision', async t => {
  for (const type of ['incomplete', 'missing', 'failed']) {
    const options = await fixture(t);
    if (type === 'incomplete') await update(join(options.run, 'evidence.json'), e => { e.collectionStatus = 'incomplete'; e.incompleteReasons = ['test: incomplete collection']; });
    if (type === 'missing') await rm(join(options.run, 'findings.json'));
    if (type === 'failed') await update(join(options.run, 'findings.json'), f => { f.investigations[0].status = 'failed'; });
    await review(options, 'QUARANTINE');
    await rebindDecision(options, d => { d.decision = 'ALLOW'; });
    assert.equal((await evaluateGate(options)).exitCode, 3);
  }
});

test('integrity mismatch is a hard BLOCK that even a matching ALLOW cannot override', async t => {
  const options = await fixture(t);
  await update(join(options.run, 'evidence.json'), e => { e.observations.push({id:'test-integrity', ruleId:'ARTIFACT_INTEGRITY_MISMATCH', severity:'critical', explanation:'test mismatch'}); });
  await review(options, 'BLOCK');
  await rebindDecision(options, d => { d.decision = 'ALLOW'; });
  assert.equal((await evaluateGate(options)).exitCode, 4);
});

test('menu rejects ALLOW on incomplete input, invalid choice and blank reason/reviewer', async t => {
  const options = await fixture(t);
  await update(join(options.run, 'evidence.json'), e => { e.collectionStatus = 'incomplete'; });
  const answers = ['ALLOW', 'WRONG', '', ' ', 'ab', 'Test reason', ' ', 'test-reviewer'];
  const saved = await reviewInteractively(options, { ask: async () => { assert.ok(answers.length); return answers.shift(); }, write: () => {} });
  assert.equal(saved.decision.decision, 'QUARANTINE');
  assert.equal(saved.decision.reason, 'Test reason');
});

test('inputs changing during the human menu produce no saved approval', async t => {
  const options = await fixture(t);
  let calls = 0;
  await assert.rejects(reviewInteractively(options, { write: () => {}, ask: async () => {
    calls++;
    if (calls === 1) return 'ALLOW';
    if (calls === 2) { await writeFile(join(options.head, '.npmrc'), '# changed during review\n'); return 'test reason'; }
    return 'test-reviewer';
  } }), /Inputs changed during review/);
  await assert.rejects(access(options.decision));
  await assert.rejects(access(options.decision + '.binding.json'));
});

test('existing decisions and markers are never overwritten', async t => {
  const options = await fixture(t);
  await review(options);
  const original = await readFile(options.decision, 'utf8');
  await assert.rejects(review(options, 'BLOCK'), /Refusing to overwrite/);
  assert.equal(await readFile(options.decision, 'utf8'), original);
  await assert.rejects(gateWithMarker(options, options.decision), /Refusing to overwrite/);
});

test('tampered decisions, wrong mode, future time, expiry and extra fields fail closed', async t => {
  for (const mutate of [
    d => { d.mode = 'signed-local'; },
    d => { d.createdAt = '9999-01-01T00:00:00.000Z'; },
    d => { d.expiresAt = '2000-01-01T00:00:00.000Z'; },
    d => { d.extra = true; },
    d => { d.reason = '   '; }
  ]) {
    const options = await fixture(t);
    await review(options);
    await rebindDecision(options, mutate);
    assert.equal((await evaluateGate(options)).exitCode, 2);
  }
  const options = await fixture(t);
  await review(options);
  await update(options.decision, d => { d.decision = 'BLOCK'; });
  assert.equal((await evaluateGate(options)).exitCode, 2);
});

test('old binding cannot drop or change scanner/policy/reference-data hashes', async t => {
  for (const label of ['policy:policy.json', 'policy:popular-packages.json', 'scanner:release']) {
    const options = await fixture(t);
    await review(options);
    await update(options.decision + '.binding.json', b => {
      b.entries.find(entry => entry[0] === label)[1] = 'a'.repeat(64);
      b.reviewDigest = digestEntries(b.entries);
    });
    assert.equal((await evaluateGate(options)).exitCode, 2);
  }
});

test('forged citations, duplicate roles and omitted package coverage are rejected', async t => {
  for (const type of ['citation', 'role', 'coverage']) {
    const options = await fixture(t);
    await review(options);
    if (type === 'citation') await update(join(options.run, 'findings.json'), f => { f.investigations[0].findings[0].evidenceIds = ['invented']; });
    if (type === 'role') await update(join(options.run, 'findings.json'), f => { f.investigations[1].role = f.investigations[0].role; });
    if (type === 'coverage') await update(join(options.run, 'evidence.json'), e => { e.packages = []; });
    assert.equal((await evaluateGate(options)).exitCode, 3);
  }
});

test('unsupported config and shrinkwrap fail before approval', async t => {
  const options = await fixture(t);
  await writeFile(join(options.head, '.npmrc'), 'registry=https://private.invalid/\n');
  await assert.rejects(loadReviewContext(options), /Unsupported project .npmrc/);
  await rm(join(options.head, '.npmrc'));
  await writeFile(join(options.head, 'npm-shrinkwrap.json'), '{}');
  await assert.rejects(loadReviewContext(options), /shrinkwrap/i);
});

test('CI and signed mode are explicitly rejected', async t => {
  const options = await fixture(t);
  await review(options);
  assert.equal((await evaluateGate({...options, env:{CI:'true'}})).exitCode, 3);
  assert.equal((await evaluateGate({...options, mode:'signed-local'})).exitCode, 3);
});

test('missing artifact source or an unsupported source cannot pass ALLOW', async t => {
  const options = await fixture(t);
  await update(join(options.run, 'evidence.json'), e => { e.sources[0].contentDigest = 'sha256-fixture-files:' + '0'.repeat(64); });
  await review(options, 'QUARANTINE');
  await rebindDecision(options, d => { d.decision = 'ALLOW'; });
  assert.equal((await evaluateGate(options)).exitCode, 3);
});

test('current policy, scanner code, version and reference data changes invalidate approvals in an isolated scanner copy', async t => {
  for (const [path, mutation] of [
    ['policy/policy.json', text => text + '\n'],
    ['src/checks/rules.mjs', text => text + '\n// test scanner release changed\n'],
    ['policy/popular-packages.json', text => text + '\n'],
    ['package.json', text => text.replace('0.1.0', '0.1.1')]
  ]) {
    const options = await fixture(t);
    const scanner = join(options.dir, 'scanner');
    await mkdir(scanner);
    for (const name of ['src', 'schemas', 'policy', 'package.json']) await cp(join(ROOT, name), join(scanner, name), {recursive:true});
    const env = {...process.env, CI:'', GITHUB_ACTIONS:'', GITLAB_CI:'', TF_BUILD:'', BUILD_BUILDID:'', JENKINS_URL:''};
    const setup = `import {reviewInteractively} from './src/menu.mjs';
      const options = JSON.parse(process.argv[1]);
      const answers = ['ALLOW','Automated test only','automated-test'];
      await reviewInteractively(options,{ask:async()=>answers.shift(),write:()=>{}});`;
    const saved = spawnSync(process.execPath, ['--input-type=module', '-e', setup, JSON.stringify(options)], {cwd:scanner, encoding:'utf8', env});
    assert.equal(saved.status, 0, saved.stderr);
    await writeFile(join(scanner, path), mutation(await readFile(join(scanner, path), 'utf8')));
    const evaluated = spawnSync(process.execPath, ['src/local-cli.mjs', 'gate', '--base', options.base, '--head', options.head, '--run', options.run, '--decision', options.decision], {cwd:scanner, encoding:'utf8', env});
    assert.equal(evaluated.status, 2, evaluated.stdout + evaluated.stderr);
  }
});

test('CLI propagates gate exit codes; a piped review cannot manufacture human approval', async t => {
  const options = await fixture(t);
  const args = ['--base', options.base, '--head', options.head, '--run', options.run, '--decision', options.decision];
  const env = {...process.env, CI:'', GITHUB_ACTIONS:'', GITLAB_CI:'', TF_BUILD:'', BUILD_BUILDID:'', JENKINS_URL:''};
  const run = (command, rest = [], input) => spawnSync(process.execPath, [join(ROOT, 'src/local-cli.mjs'), command, ...args, ...rest], {encoding:'utf8', env, input});
  assert.equal(run('gate').status, 2);
  assert.equal(run('review', ['--interactive'], 'ALLOW\ntest reason\ntest-reviewer\n').status, 3);
  await assert.rejects(access(options.decision));
  await review(options, 'BLOCK');
  const marker = join(options.dir, 'cli-marker.txt');
  const blocked = run('demo', ['--marker', marker]);
  assert.equal(blocked.status, 4, blocked.stderr);
  await assert.rejects(access(marker));
  await rebindDecision(options, d => { d.decision = 'ALLOW'; });
  const allowed = run('demo', ['--marker', marker]);
  assert.equal(allowed.status, 0, allowed.stderr);
  await access(marker);
});
