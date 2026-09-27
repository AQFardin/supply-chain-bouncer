#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { loadProjectInputs, computeSubjectDigest } from './input.mjs';
import { compareLockfiles } from './lockfile-diff.mjs';
import { collectEvidence } from './collector.mjs';
import { generateReport } from './report.mjs';

const USAGE = `Supply Chain Bouncer CLI (v0.1.0)
Usage:
  bouncer scan --base <base-dir> --head <candidate-dir> [--out <run-dir>] [--mode <live|fixture>]
  bouncer report --run <run-dir>
  bouncer help
`;

export async function main(argv = process.argv.slice(2)) {
  const options = {
    base: { type: 'string' },
    head: { type: 'string' },
    out: { type: 'string' },
    run: { type: 'string' },
    mode: { type: 'string', default: 'live' },
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
    const outDir = parsed.values.out;
    const mode = parsed.values.mode || 'live';
    if (!['live', 'fixture'].includes(mode)) {
      console.error('Error: --mode must be live or fixture.');
      process.exitCode = 1;
      return;
    }

    if (!baseDir || !headDir) {
      console.error('Error: --base and --head directories are required for "scan".');
      process.exit(1);
    }

    try {
      const { subjectDigest } = await computeSubjectDigest(baseDir, headDir);
      const baseInputs = await loadProjectInputs(baseDir, 'base');
      const headInputs = await loadProjectInputs(headDir, 'candidate');

      // Load policy & popular packages reference list
      let policy = {};
      let popularPackages = [];
      try {
        const policyRaw = await readFile(resolve('policy/policy.json'), 'utf8');
        policy = JSON.parse(policyRaw);
      } catch {}

      try {
        const popRaw = await readFile(resolve('policy/popular-packages.json'), 'utf8');
        const popObj = JSON.parse(popRaw);
        popularPackages = popObj.packages || [];
      } catch {}

      const diff = compareLockfiles(baseInputs.lockfile, headInputs.lockfile);

      // Collect evidence and run static checks
      console.log('Collecting static evidence without executing target code...');
      const evidence = await collectEvidence(diff, subjectDigest, {
        mode,
        policy,
        popularPackages,
        headDir
      });

      console.log('----------------------------------------------------');
      console.log('Supply Chain Bouncer — Evidence Collection Result');
      console.log('----------------------------------------------------');
      console.log(`Subject Digest:       ${evidence.subjectDigest}`);
      console.log(`Collection Status:    ${evidence.collectionStatus.toUpperCase()}`);
      console.log(`Total Changed:        ${diff.summary.totalChanged}`);
      console.log(`  Added (direct):     ${diff.summary.addedDirect}`);
      console.log(`  Added (transitive): ${diff.summary.addedTransitive}`);
      console.log(`  Changed (direct):   ${diff.summary.changedDirect}`);
      console.log(`  Changed (trans.):   ${diff.summary.changedTransitive}`);
      console.log(`  Removed:            ${diff.summary.removed}`);
      console.log(`  Unsupported:        ${diff.summary.unsupportedCount}`);
      console.log(`Observations:         ${evidence.observations.length}`);
      console.log('----------------------------------------------------');

      for (const obs of evidence.observations) {
        const icon = obs.severity === 'critical' ? '🔴' : obs.severity === 'high' ? '🟠' : '🟡';
        console.log(`${icon} [${obs.severity.toUpperCase()}] ${obs.packageName} (${obs.ruleId}): ${obs.explanation}`);
      }

      if (outDir) {
        const resolvedOut = resolve(outDir);
        await mkdir(resolvedOut, { recursive: true });
        const evidenceFile = join(resolvedOut, 'evidence.json');
        await writeFile(evidenceFile, JSON.stringify(evidence, null, 2), 'utf8');
        console.log(`\nEvidence bundle saved to: ${evidenceFile}`);
      }
    } catch (err) {
      console.error(`Scan failed: ${err.message}`);
      process.exit(3);
    }
  } else if (command === 'report') {
    const runDir = parsed.values.run;
    if (!runDir) {
      console.error('Error: --run directory is required for "report".');
      process.exit(1);
    }

    try {
      const result = await generateReport(runDir);
      console.log('----------------------------------------------------');
      console.log('Supply Chain Bouncer — Report Generated');
      console.log('----------------------------------------------------');
      console.log(`Overall Recommendation: ${result.reportData.overallRecommendation}`);
      console.log(`Review Status:          ${result.reportData.reviewStatus}`);
      console.log(`JSON Report:            ${result.reportJsonPath}`);
      console.log(`HTML Report:            ${result.reportHtmlPath}`);
      console.log('----------------------------------------------------');
      console.log('Human review and gate enforcement are planned for the next phase. This report does not authorize installation or merge.');
    } catch (err) {
      console.error(`Report generation failed: ${err.message}`);
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
