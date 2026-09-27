# Supply Chain Bouncer

A dependency review assistant for the IBM Bob 2.0 hackathon. The planned workflow compares npm dependency changes, collects static evidence, and uses three Bob investigators to help a developer choose ALLOW, QUARANTINE, or BLOCK. A local CLI gate will evaluate the decision against the reviewed inputs.

## Current status

The scanner, Bob skill and role instructions, and JSON/HTML report renderer are implemented through roadmap step 10. A real parallel Bob investigation rehearsal is the next step. The human review menu and local gate remain planned; GitHub enforcement and signed decisions are optional later extensions.

## Development setup

Developed and tested with **Node.js v24.12.0** and **npm 11.6.2**. Open this repository in Bob IDE and sign into your hackathon-provisioned account for Bob work.

```text
git clone https://github.com/AQFardin/supply-chain-bouncer.git
cd supply-chain-bouncer
node --version
npm --version
```

The project uses JavaScript ES modules and Node built-ins without package dependencies. `npm test` runs the offline regression suite. To include the optional live-registry smoke test, set `BOUNCER_LIVE_TESTS=1` for the test process.

```text
node src/cli.mjs scan --base fixtures/suspicious/base --head fixtures/suspicious/head --mode fixture --out reports/demo/suspicious-fixture
node src/cli.mjs report --run reports/demo/suspicious-fixture
```

The report remains QUARANTINE until all three investigations complete. This is a review recommendation, not gate enforcement. Existing human decisions are shown separately and must match the evidence subject digest. Malformed or stale findings/decisions are rejected. No package scripts are executed.

## Project structure

| Folder | Planned contents |
|---|---|
| `src/` | CLI, dependency comparison, evidence collection, reports, and gate |
| `tests/` | Automated checks for the implemented behavior |
| `schemas/` | Evidence, investigation, and decision formats |
| `policy/` | Review rules and reference data |
| `examples/sample-app/` | Small application used for the demonstration |
| `fixtures/` | Harmless, clearly labelled test and demonstration inputs (benign, suspicious, legitimate-install-script, prompt-injection, malformed) |
| `decisions/` | Recorded human review decisions and envelope files |
| `reports/demo/` | Sanitized demonstration reports (JSON and HTML) |
| `.bob/agents/` | Investigator role instructions |
| `.bob/skills/supply-chain-bouncer/` | Reusable Bob investigation workflow |
| `docs/` | Architecture, evaluation, and submission notes |
| `bob_sessions/` | Sanitized Bob task-session summary screenshots for submission |

Empty folders contain `.gitkeep` placeholders so they are retained when the repository is cloned. Remove those placeholders when meaningful files are added.

## Next step

In Bob IDE, run the investigation skill against a demo evidence bundle using actual parallel subagents and capture task-session summaries. Then regenerate the report from the resulting `findings.json`. Implement the human review menu and gate after that rehearsal.

## Evidence and credentials

Commit harmless fixtures and sanitized Bob session screenshots. Keep real credentials, private keys, generated dependencies, and build outputs out of Git. Screenshots remain excluded from Bob's context through `.bobignore`, while fixture files remain accessible for review.

Ignore files control file matching; they do not redact secrets pasted into a prompt or printed by a command. The existing `.env.example` contains optional IBM Cloud configuration inherited from the project template; a Cloud API key is not required for this initial local scaffold. See [the security guidelines](SECURITY.MD) before adding credentials.
