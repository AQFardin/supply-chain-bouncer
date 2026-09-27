# Supply Chain Bouncer

A dependency review assistant for the IBM Bob 2.0 hackathon. The planned workflow compares npm dependency changes, collects static evidence, and uses three Bob investigators to help a developer choose ALLOW, QUARANTINE, or BLOCK. A local CLI gate will evaluate the decision against the reviewed inputs.

## Current status

Repository setup is complete. The scanner, Bob investigation workflow, reports, and local gate are not implemented yet. GitHub enforcement and signed decisions are optional later extensions.

## Development setup

Developed and tested with **Node.js v24.12.0** and **npm 11.6.2**. Open this repository in Bob IDE and sign into your hackathon-provisioned account for Bob work.

```text
git clone https://github.com/AQFardin/supply-chain-bouncer.git
cd supply-chain-bouncer
node --version
npm --version
```

The project uses JavaScript ES modules. No package dependencies are declared yet. The `npm run bouncer` and `npm test` scripts are placeholders until the CLI and test files are implemented.

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

Use Bob Plan mode to define the architecture, data contracts, and implementation checklist. Then build the lockfile comparator and evidence collection before adding the investigators, local review menu, and gate.

## Evidence and credentials

Commit harmless fixtures and sanitized Bob session screenshots. Keep real credentials, private keys, generated dependencies, and build outputs out of Git. Screenshots remain excluded from Bob's context through `.bobignore`, while fixture files remain accessible for review.

Ignore files control file matching; they do not redact secrets pasted into a prompt or printed by a command. The existing `.env.example` contains optional IBM Cloud configuration inherited from the project template; a Cloud API key is not required for this initial local scaffold. See [the security guidelines](SECURITY.MD) before adding credentials.
