import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { loadSchema, validateAgainstSchema } from './validation.mjs';
import { MODE, ReviewError, assertNewFile, digestEntries, loadReviewContext, requireLocalMode, sha256 } from './review-state.mjs';

const result = (exitCode, reason, context) => ({ exitCode, status: {0:'ALLOW', 2:'QUARANTINE', 3:'INCOMPLETE', 4:'BLOCK'}[exitCode], reason, context });

export function validateDecision(decision, now = new Date()) {
  validateAgainstSchema(loadSchema('decision'), decision, 'decision');
  if (decision.schemaVersion !== '1.1' || decision.mode !== MODE || ['keyId', 'signatureBase64', 'payloadBase64'].some(key => Object.hasOwn(decision, key))) throw new Error('Unsupported decision format or mode.');
  if (decision.reason.trim().length < 3 || !decision.reviewerLabel.trim()) throw new Error('A reviewer label and meaningful reason are required.');
  const created = Date.parse(decision.createdAt);
  if (!Number.isFinite(created) || new Date(created).toISOString() !== decision.createdAt || created > now.getTime()) throw new Error('Invalid or future decision timestamp.');
  if (decision.expiresAt !== undefined) {
    const expiry = Date.parse(decision.expiresAt);
    if (!Number.isFinite(expiry) || new Date(expiry).toISOString() !== decision.expiresAt || expiry <= created || expiry <= now.getTime()) throw new Error('Decision is expired or has invalid expiry.');
  }
}

/** Unsigned local enforcement: it detects stale files, not a malicious local operator. */
export async function evaluateGate(options) {
  try { requireLocalMode(options.mode, options.env); }
  catch (err) { return result(3, err.message); }
  if (!options.decision) return result(2, 'Missing decision. Run the interactive review first.');
  let decision, binding, decisionBytes;
  try {
    decisionBytes = await readFile(resolve(options.decision));
    decision = JSON.parse(decisionBytes.toString('utf8'));
    validateDecision(decision, options.now);
    binding = JSON.parse(await readFile(resolve(options.decision) + '.binding.json', 'utf8'));
    validateAgainstSchema(loadSchema('review-binding'), binding, 'binding');
    if (binding.decisionDigest !== sha256(decisionBytes) || binding.subjectDigest !== decision.subjectDigest || binding.reviewDigest !== digestEntries(binding.entries)) throw new Error('Decision or binding was changed.');
  } catch (err) {
    return result(2, `Missing, malformed, expired or changed approval: ${err.code === 'ENOENT' ? 'decision and its .binding.json companion are both required' : err.message}`);
  }
  let context;
  try { context = await loadReviewContext(options); }
  catch (err) { return result(err instanceof ReviewError ? err.exitCode : 3, err.message); }
  if (decision.subjectDigest !== context.subjectDigest || binding.reviewDigest !== context.reviewDigest || JSON.stringify(binding.entries) !== JSON.stringify(context.entries)) {
    return result(2, 'Stale approval: dependency inputs, configuration, policy, scanner, evidence, findings or fixture files changed. Review again.', context);
  }
  if (context.hardBlocks.length) return result(4, `Hard policy violation: ${context.hardBlocks.join('; ')}. Remove or repair the dependency, then rescan.`, context);
  if (context.incomplete.length) return result(3, `Required evidence is incomplete: ${context.incomplete.join('; ')}`, context);
  if (decision.decision === 'BLOCK') return result(4, 'Human decision is BLOCK. Remove or replace the dependency, then rescan and review.', context);
  if (decision.decision === 'QUARANTINE') return result(2, 'Human decision is QUARANTINE. Held for further review.', context);
  return result(0, `Human ALLOW matches the complete review (${MODE}; ${context.evidence.mode} evidence).`, context);
}

/** The only downstream action is a new harmless marker, strictly after success. */
export async function gateWithMarker(options, markerPath) {
  if (!markerPath) throw new ReviewError('--marker is required for the harmless demonstration.');
  await assertNewFile(resolve(markerPath));
  const outcome = await evaluateGate(options);
  if (outcome.exitCode === 0) await writeFile(resolve(markerPath), 'Release step permitted by the local demo gate. No package code was executed.\n', { flag: 'wx' });
  return outcome;
}
