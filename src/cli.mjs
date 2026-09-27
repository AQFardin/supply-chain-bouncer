#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { loadProjectInputs, computeSubjectDigest } from './input.mjs';
import { compareLockfiles } from './lockfile-diff.mjs';

const USAGE = `Supply Chain Bouncer CLI (v0.1.0)
Usage:
  bouncer scan --base <base-dir> --head <candidate-dir>
  bouncer help
`;

export async function main(argv = process.argv.slice(2)) {
  const options = {
    base: { type: 'string' },
    head: { type: 'string' },
    help: { type: 'boolean', short: 'h' }
  };

  let parsed;
  try {
    parsed = parseArgs({ args: argv, options, allowPositionals: true });
  } catch (err) {
    console.error(`Error parsing arguments: ${err.message}`);
    console.log(USAGE);
    process.exit(1);
  }

  const [command] = parsed.positionals;

  if (parsed.values.help || command === 'help' || !command) {
    console.log(USAGE);
    return;
  }

  if (command === 'scan') {
    const baseDir = parsed.values.base;
    const headDir = parsed.values.head;

    if (!baseDir || !headDir) {
      console.error('Error: --base and --head directories are required for "scan".');
      process.exit(1);
    }

    try {
      const { subjectDigest } = await computeSubjectDigest(baseDir, headDir);
      const baseInputs = await loadProjectInputs(baseDir, 'base');
      const headInputs = await loadProjectInputs(headDir, 'candidate');

      const diff = compareLockfiles(baseInputs.lockfile, headInputs.lockfile);

      console.log('----------------------------------------------------');
      console.log('Supply Chain Bouncer — Lockfile Comparison Result');
      console.log('----------------------------------------------------');
      console.log(`Subject Digest:       ${subjectDigest}`);
      console.log(`Total Evaluated:      ${diff.summary.totalEvaluated}`);
      console.log(`Total Changed:        ${diff.summary.totalChanged}`);
      console.log(`  Added (direct):     ${diff.summary.addedDirect}`);
      console.log(`  Added (transitive): ${diff.summary.addedTransitive}`);
      console.log(`  Changed (direct):   ${diff.summary.changedDirect}`);
      console.log(`  Changed (trans.):   ${diff.summary.changedTransitive}`);
      console.log(`  Removed:            ${diff.summary.removed}`);
      console.log(`  Unsupported Sources: ${diff.summary.unsupportedCount}`);
      console.log('----------------------------------------------------');

      const changedPackages = diff.packages.filter((p) => p.changeType !== 'unchanged');
      for (const pkg of changedPackages) {
        const flag = pkg.isDirect ? '[DIRECT]' : '[TRANSITIVE]';
        const scriptBadge = pkg.hasInstallScript ? '⚠️ [INSTALL_SCRIPT]' : '';
        const unsupBadge = pkg.unsupported ? `❌ [UNSUPPORTED: ${pkg.unsupportedReason}]` : '';
        console.log(`• ${flag} ${pkg.name} (${pkg.changeType}): ${pkg.previousVersion || 'none'} -> ${pkg.version || 'none'} ${scriptBadge} ${unsupBadge}`);
      }
    } catch (err) {
      console.error(`Scan failed: ${err.message}`);
      process.exit(3);
    }
  } else {
    console.error(`Unknown command: ${command}`);
    console.log(USAGE);
    process.exit(1);
  }
}

// Auto-run if executed directly via node
if (process.argv[1] && process.argv[1].endsWith('cli.mjs')) {
  main();
}
