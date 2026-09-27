#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { MODE, terminalText } from './review-state.mjs';
import { evaluateGate, gateWithMarker } from './gate.mjs';
import { runTerminalReview } from './menu.mjs';

const usage = `Supply Chain Bouncer — unsigned local review and gate
  node src/local-cli.mjs review --base <dir> --head <dir> --run <dir> --interactive [--decision <new-json>]
  node src/local-cli.mjs gate --base <dir> --head <dir> --run <dir> --decision <json>
  node src/local-cli.mjs demo --base <dir> --head <dir> --run <dir> --decision <json> --marker <new-file>
  Optional on every command: --mode trusted-local-demo

Exit codes: 0 allowed/saved; 2 quarantine/missing/malformed/stale approval;
3 operational/incomplete failure; 4 blocked.
Demo writes a harmless marker only after exit 0. It never installs or runs packages.
Keep the decision and its .binding.json companion together. Existing files are never overwritten.
This mode trusts the local operator and does not authenticate approvals. CI and signing are unsupported.
Bob's original scan/report commands remain in src/cli.mjs.`;

export async function main(args = process.argv.slice(2)) {
  try {
    const { values, positionals } = parseArgs({ args, allowPositionals: true, options: {
      base: { type: 'string' }, head: { type: 'string' }, run: { type: 'string' },
      decision: { type: 'string' }, marker: { type: 'string' },
      mode: { type: 'string', default: MODE }, interactive: { type: 'boolean' },
      help: { type: 'boolean', short: 'h' }
    } });
    if (values.help || !positionals.length || positionals[0] === 'help') { console.log(usage); return 0; }
    if (positionals.length !== 1 || !['review', 'gate', 'demo'].includes(positionals[0])) throw new Error('Unknown command. Use --help.');
    if (!values.base || !values.head || !values.run) throw new Error('--base, --head and --run are required.');
    const command = positionals[0];
    if (command === 'review') {
      if (!values.interactive) throw new Error('Review requires --interactive; only the human chooses the decision.');
      await runTerminalReview(values);
      return 0;
    }
    const outcome = command === 'demo' ? await gateWithMarker(values, values.marker) : await evaluateGate(values);
    console.log(terminalText(`${outcome.status} (exit ${outcome.exitCode}, ${MODE}): ${outcome.reason}`));
    if (command === 'demo') console.log(outcome.exitCode === 0 ? `Harmless marker created: ${resolve(values.marker)}` : 'Downstream step withheld; no marker was created.');
    return outcome.exitCode;
  } catch (err) { console.error(terminalText(`Local review/gate failed: ${err.message}`)); return err.exitCode || 3; }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) process.exitCode = await main();
