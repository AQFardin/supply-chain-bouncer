import { createInterface } from 'node:readline';
import { writeFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import { MODE, ReviewError, assertNewFile, loadReviewContext, sha256, terminalText } from './review-state.mjs';
import { validateDecision } from './gate.mjs';

export function showReview(context, write) {
  const say = value => write(terminalText(value) + '\n');
  say(`Supply Chain Bouncer — human review (${MODE})`);
  say('Unsigned local record: assumes a trusted operator; it does not authenticate the reviewer.');
  say(`Evidence mode: ${context.evidence.mode.toUpperCase()} | Collection: ${context.evidence.collectionStatus}`);
  if (context.evidence.mode === 'fixture') say('SYNTHETIC FIXTURE: this is a local simulation, not a real malware discovery.');
  say(`Evidence: ${context.runDir}/evidence.json`);
  say(`Findings: ${context.runDir}/findings.json`);
  say(`Bob recommendation: ${context.report.overallRecommendation} | Investigations complete: ${context.report.investigationComplete}`);
  say(`Dependency subject: ${context.subjectDigest}`);
  say(`Full review digest: ${context.reviewDigest}`);
  say('Current input hashes (ABSENT means the optional file does not exist):');
  for (const [label, digest] of context.entries) say(`  ${label}: ${digest}`);
  for (const obs of context.evidence.observations) say(`[evidence ${obs.id}] ${obs.ruleId}: ${obs.explanation}`);
  for (const inv of context.findings?.investigations || []) {
    say(`[${inv.role}] ${inv.status} / ${inv.recommendation}`);
    for (const finding of inv.findings) {
      say(`  ${finding.id} (${finding.severity}, confidence ${finding.confidence}) — cited evidence: ${finding.evidenceIds.join(', ')}`);
      say(`  Observation: ${finding.observation}`);
      say(`  Interpretation (Bob): ${finding.interpretation}`);
      if (finding.benignExplanation) say(`  Possible benign explanation: ${finding.benignExplanation}`);
      say(`  Suggested action: ${finding.suggestedAction}`);
    }
  }
  for (const unknown of context.report.unknowns) say(`Unknown: ${unknown}`);
  // A timestamp inconsistency is a limitation in historical findings, not proof of malware.
  const latestCollection = Math.max(...context.evidence.sources.map(s => Date.parse(s.retrievalTime)).filter(Number.isFinite));
  if (context.findings?.generatedAt && Date.parse(context.findings.generatedAt) < latestCollection) say('Review note: findings timestamp predates evidence collection; verify the Bob session record.');
  say(`Hard BLOCK violations: ${context.hardBlocks.join('; ') || 'none'}`);
  say(`Required evidence gaps: ${context.incomplete.join('; ') || 'none'}`);
  say('Bob recommendations are advisory. Human ALLOW can accept reviewable warnings, but cannot bypass hard violations or incomplete evidence.');
}

/** Test callers supply answers explicitly; production callers use the terminal menu. */
export async function reviewInteractively(options, { ask, write, now = () => new Date() }) {
  const output = resolve(options.decision || `decisions/decision-${randomUUID()}.json`);
  await assertNewFile(output);
  await assertNewFile(output + '.binding.json');
  const context = await loadReviewContext(options);
  showReview(context, write);
  let choice;
  while (true) {
    const answer = (await ask('Choose ALLOW, QUARANTINE or BLOCK [QUARANTINE]: ')).trim().toUpperCase();
    choice = answer || 'QUARANTINE';
    if (!['ALLOW', 'QUARANTINE', 'BLOCK'].includes(choice)) { write('Enter ALLOW, QUARANTINE or BLOCK.\n'); continue; }
    if (choice === 'ALLOW' && (context.hardBlocks.length || context.incomplete.length)) {
      write('ALLOW is unavailable until hard violations and evidence gaps are resolved.\n'); continue;
    }
    break;
  }
  let reason = '';
  while (reason.trim().length < 3) reason = await ask('Reason (at least 3 non-whitespace characters): ');
  let reviewerLabel = '';
  while (!reviewerLabel.trim()) reviewerLabel = await ask('Reviewer label: ');
  // The file being approved must still be the one shown at the start of the menu.
  const current = await loadReviewContext(options);
  if (current.reviewDigest !== context.reviewDigest) throw new ReviewError('Inputs changed during review. Nothing was saved; start review again.', 2);
  const decision = { schemaVersion: '1.1', mode: MODE, subjectDigest: context.subjectDigest, decision: choice, reason: reason.trim(), reviewerLabel: reviewerLabel.trim(), createdAt: now().toISOString() };
  validateDecision(decision, now());
  const raw = JSON.stringify(decision, null, 2) + '\n';
  const binding = { schemaVersion: '1.0', purpose: 'supply-chain-bouncer-local-review-v1', mode: MODE, subjectDigest: context.subjectDigest, reviewDigest: context.reviewDigest, decisionDigest: sha256(raw), entries: context.entries };
  // Exclusive creates preserve prior decisions. A partial pair never passes the gate.
  await writeFile(output + '.binding.json', JSON.stringify(binding, null, 2) + '\n', { flag: 'wx' });
  await writeFile(output, raw, { flag: 'wx' });
  write(`Recorded ${choice}: ${output}\nBinding: ${output}.binding.json\nRun the gate separately to evaluate this record.\n`);
  return { decision, decisionPath: output, bindingPath: output + '.binding.json' };
}

export async function runTerminalReview(options, input = process.stdin, output = process.stdout) {
  if (!input.isTTY || !output.isTTY) throw new ReviewError('Interactive review requires a terminal. No human choice was recorded.');
  const rl = createInterface({ input, output, terminal: true });
  const lines = rl[Symbol.asyncIterator]();
  try {
    return await reviewInteractively(options, {
      write: text => output.write(text),
      ask: async prompt => { output.write(prompt); const answer = await lines.next(); if (answer.done) throw new ReviewError('Review cancelled. No decision saved.', 2); return answer.value; }
    });
  } finally { rl.close(); }
}
