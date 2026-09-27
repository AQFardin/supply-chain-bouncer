# Supply Chain Bouncer — Implementation Plan

> Read `docs/architecture.md` for the full system design, data contracts, and Bob
> feature notes before starting any sub-task.

---

## Overview

Build a local Node.js CLI that compares npm lockfile v3 changes, collects static
evidence from the npm registry, uses three parallel Bob investigator subagents to reason
over the evidence, captures a human ALLOW / QUARANTINE / BLOCK decision via a terminal
review menu, and evaluates that decision with a local gate. No target code is executed.
No database. The gate starts in explicitly labelled `trusted-local-demo` mode. Optional
signing and remote CI are deferred.

Custom native Bob Workflows are **not available** (platform-built-in only). The
investigation workflow is implemented as a reusable **skill**
(`.bob/skills/supply-chain-bouncer/SKILL.md`) with supporting role files.
Investigator "personas" are role instruction markdown files in `.bob/agents/`, loaded
by the skill — not free-standing persona files (no such Bob concept exists).

---

## Sub-Task 1 — Data Contracts and Schemas

**Status**: [x] done

### Outcomes delivered

- `schemas/evidence.schema.json` — EvidenceBundle (draft-07, `additionalProperties: false`
  on root and source items; `additionalProperties: true` on observations to allow
  `untrustedExcerpt`).
- `schemas/investigation.schema.json` — InvestigationOutput with roles
  `typosquat-detective`, `provenance-auditor`, `behavior-analyst`.
- `schemas/decision.schema.json` — DecisionEnvelope v1.1 with `subjectDigest`,
  `mode` enum (`trusted-local-demo`, `signed-local`).
- `policy/policy.json` — gate rules for BLOCK/QUARANTINE conditions.
- `policy/popular-packages.json` — reference list for typosquat detection.
- Schema validation tested in `tests/schema.test.mjs` (inline pure validator, no
  third-party dependencies).

---

## Sub-Task 2 — Fixture Lockfiles and Sample App

**Status**: [x] done

### Outcomes delivered

- `examples/sample-app/` with `package.json`, `package-lock.json` (lockfile v3), and
  `candidate/` sub-directory with an updated state.
- `fixtures/benign/` — version bump + new direct dependency (ms 2.1.2→2.1.3, picocolors added).
- `fixtures/suspicious/` — `mock-telemetry-reporter` with `hasInstallScript: true` and
  `package-files/mock-telemetry-reporter/setup.js` (inert env-harvest + exfil simulation).
- `fixtures/legitimate-install-script/` — `mock-native-binding` with `binding.gyp` (node-gyp pattern).
- `fixtures/prompt-injection/` — `adversarial-helper` with adversarial `description` field
  and a matching `package-files/adversarial-helper/package.json`.
- `fixtures/malformed/` — four malformed inputs covering missing lockfileVersion, invalid JSON,
  unsupported v2, and git-reference source.
- Each fixture directory has a `README.md`.

---

## Sub-Task 3 — Unit Tests (all implemented)

**Status**: [x] done

### Outcomes delivered

- `tests/archive.test.mjs` — 6 tests: path safety, traversal rejection, symlink rejection,
  valid parse, large-file tracking, zip-bomb defense.
- `tests/checks.test.mjs` — 8 tests: typosquat detection, lifecycle scripts, code patterns,
  obfuscation, integrity mismatch, prompt-injection detection (unit + integration).
- `tests/collector.test.mjs` — 7 tests: suspicious fixture, live benign, missing integrity,
  URL discrepancy, plus 3 regression tests (real contentDigest, missing files, prompt-injection
  evidence reach).
- `tests/input.test.mjs` — 8 tests: SHA-256 hash, null for absent, deterministic digest,
  digest changes, valid inputs, missing dir, wrong lockfileVersion, shrinkwrap detection.
- `tests/lockfile-diff.test.mjs` — 9 tests: identical lockfiles, benign diff, directness
  classification, transitive additions, removal, multi-version coexistence, integrity
  changes, unsupported sources, suspicious fixture lifecycle scripts.
- `tests/schema.test.mjs` — 5 tests: evidence schema structure, investigation schema
  structure, decision schema structure, real bundle validation, additionalProperties rejection.

The original test counts below describe the scanner milestone. Run `npm test` for current results, including report regression tests. Live network smoke tests are opt-in via `BOUNCER_LIVE_TESTS=1`.

---

## Sub-Task 4 — Lockfile Comparator

**Status**: [x] done

### Implemented in `src/lockfile-diff.mjs`

- `checkUnsupportedSource(resolved, version)` — git, file:, link:, non-standard registry.
- `extractRootDirectDepNames(rootPackageObj)` — reads all dep buckets from root entry.
- `classifyDirectness(locationKey, directDepNames)` — direct vs transitive by path depth.
- `compareLockfiles(baseLockfile, headLockfile)` — full diff with summary counts.
- All change types: `added`, `changed`, `removed`, `unchanged`.
- Preserves: version, previousVersion, integrity, previousIntegrity, scripts,
  hasInstallScript, isDirect, isDev, isOptional, unsupported, unsupportedReason.

---

## Sub-Task 5 — Evidence Collector

**Status**: [x] done (with corrections applied)

### Implemented in `src/collector.mjs`

**Fixture mode:**
- Discovers fixture package files via `discoverFixturePackageFiles` (explicit options,
  relative path candidates, workspace fixture paths).
- **Missing fixture files → incomplete evidence** (not silent): adds to `incompleteReasons`
  and produces an `UNSUPPORTED_OR_INCOMPLETE` observation.
- **`contentDigest` = real SHA-256** of inspected fixture file content, labeled
  `sha256-fixture-files:<hex>`. Clearly distinguished from verified downloaded-artifact
  integrity (which uses `sha512-<base64>`).
- Empty set → `sha256-fixture-files:empty-no-files-found`.
- `actualIntegrity` is set to `null` in fixture mode — the fixture content digest is
  not passed to the integrity-mismatch check to avoid spurious critical observations.

**Live mode:**
- Fetches registry metadata via `src/registry.mjs` (HTTPS, allowlisted hosts, timeout).
- Downloads and inspects `.tgz` artifact via `src/archive.mjs` (in-memory only).
- Compares lockfile `resolved` URL vs registry `tarballUrl` — flags discrepancy.
- Tracks truncated archives and omitted large files as incomplete evidence.
- `actualIntegrity` = SHA-512 of downloaded artifact, passed to integrity-mismatch check.

**Static checks (both modes):**
- Extracts package `description` from fixture `package.json` or live registry metadata.
- Passes `metadataFields: { description: ... }` to `runStaticChecks`.
- `checkMetadataFields` scans for prompt-injection patterns; surfaces labeled untrusted
  excerpts: `[UNTRUSTED DATA from <pkg> <field>]: <text>`.
- `runStaticChecks` chains: typosquat → lifecycle scripts → integrity → unsupported →
  metadata fields → code patterns.

**`collectionStatus` logic:**
- `"quarantine"` if any critical-severity observation.
- `"incomplete"` if any incomplete reason or `UNSUPPORTED_OR_INCOMPLETE` observation
  (but no critical).
- `"complete"` otherwise.

---

## Sub-Task 6 — Report Writer

**Status**: [x] done (roadmap step 10)

Implemented in `src/report.mjs`, exposed by `bouncer report --run <dir>`.
Produces `report.json` and escaped, offline `report.html` under the run directory.
Validates evidence, the combined findings wrapper, each investigator output, and
optional decision records. Rejects stale digests, duplicate roles, invented
citations, malformed optional files, and unverified signed decisions.

The report recomputes recommendations from individual investigators. Missing or
failed roles and incomplete evidence require at least QUARANTINE; integrity
violations remain BLOCK. Human decisions are shown separately. No report is gate
enforcement. The interactive review command is not implemented yet.

Contracts: `schemas/report.schema.json`, `schemas/findings.schema.json`, and
`schemas/investigation.schema.json`. Tests: `tests/report.test.mjs`.

---

## Sub-Task 7 — Terminal Review Menu

**Status**: [ ] pending

### Intent

Implement `src/menu.mjs`. Presents the report to the human reviewer in the terminal
and captures ALLOW / QUARANTINE / BLOCK interactively. Writes the decision envelope
to `decisions/` conforming to `schemas/decision.schema.json`.

### Expected Outcomes

- `src/menu.mjs` exports `promptDecision(reportPath, decidedBy, outputDir)`.
- Displays report text, prompts with numbered menu.
- Writes `decisions/decision-<timestamp>.json` with `"mode": "trusted-local-demo"`.
- Non-interactive bypass via `BOUNCER_VERDICT` env var for test use.

### Todo List

1. Implement display + `node:readline` prompt.
2. Assemble and write decision envelope.
3. Add `BOUNCER_VERDICT` bypass (test-only, not a production interface).

---

## Sub-Task 8 — Local Gate

**Status**: [ ] pending

### Intent

Implement `src/gate.mjs`. Read a decision envelope and policy, apply rules, exit 0
(ALLOW passes gate) or 1 (QUARANTINE or BLOCK fails gate, or any policy violation).

The gate must check:
1. Current input hashes match the decision's `subjectDigest`.
2. Evidence `collectionStatus` is `complete`.
3. All three investigator outputs are present and `status: "complete"`.
4. Policy rules pass.
5. Human approval is recorded with a valid verdict.

### Expected Outcomes

- `src/gate.mjs` exports `evaluate(decisionPath, evidencePath, findingsPath, policyPath)`.
- Exit 0 for ALLOW + all checks pass.
- Exit 1 for QUARANTINE, BLOCK, or any check failure.
- `tests/gate.test.mjs` covers all cases.

### Todo List

1. Implement input hash check against `subjectDigest`.
2. Implement evidence completeness check.
3. Implement investigator output completeness check.
4. Implement policy rule evaluation.
5. Add `tests/gate.test.mjs`.

---

## Sub-Task 9 — Bob Skill and Investigator Role Files

**Status**: [x] done

### Outcomes delivered

- `.bob/skills/supply-chain-bouncer/SKILL.md` — full skill with:
  - Pre-flight: reads evidence bundle, output schema, and all three role files.
  - Step 1: spawns all three subagents in the **same turn** (parallel).
  - Each subagent receives: evidence path, schema path, role instruction path, role
    string, and hard constraints (no execution, metadata as data, incomplete→QUARANTINE).
  - Step 2: collects and validates outputs.
  - Step 3: writes `findings.json` alongside the evidence bundle.
  - Step 4: reports aggregate recommendation to the user.

- `.bob/agents/investigator-typosquat-detective.md` — name similarity, typosquat
  signals, scope confusion, exact-match exclusion.
- `.bob/agents/investigator-provenance-auditor.md` — registry source, integrity
  consistency, publish metadata, fixture vs live contentDigest labeling.
- `.bob/agents/investigator-behavior-analyst.md` — lifecycle scripts, code patterns,
  prompt-injection detection, combined-signal severity escalation.

- `.bob/commands/investigate.md` — `/investigate <evidence-path>` slash command.

**Bob feature confirmation:**
- Skills with supporting files: supported (`.bob/skills/<name>/SKILL.md`).
- Parallel subagents: supported (`spawn_subagent` in same turn).
- Slash commands: supported (`.bob/commands/<name>.md`).
- Custom native Workflow authoring: **not supported** — skill is the correct substitute.
- Persona files: **not a Bob concept** — role files loaded as skill supporting files.

---

## Sub-Task 10 — CLI Entry Point

**Status**: [x] done (scan and report commands)

### Implemented in `src/cli.mjs`

- `bouncer scan --base <dir> --head <dir> [--out <dir>] [--mode live|fixture]`
- Loads inputs, computes subject digest, runs diff, collects evidence.
- Writes `evidence.json` to `--out` directory.
- Prints observations to stdout with severity icons.
- Reads `policy/policy.json` and `policy/popular-packages.json` (silently skips if absent).

**Remaining**: implement the review menu and gate. Report generation is available through `bouncer report --run <dir>`.

---

## Sub-Task 11 — Demo Rehearsal and Report Artifacts

**Status**: [-] in progress

### Outcomes so far

- `reports/demo/live-benign/evidence.json` — live scan of benign bump (ms 2.1.2→2.1.3 + picocolors added), 0 observations, `collectionStatus: complete`. `contentDigest` values are verified SHA-512 of downloaded artifacts.
- `reports/demo/suspicious-fixture/evidence.json` — fixture scan of mock-telemetry-reporter, 6 observations (LIFECYCLE_SCRIPT_ADDED, ENVIRONMENT_ACCESS, NETWORK_OPERATION ×2, PROCESS_EXECUTION ×2). `contentDigest` is `sha256-fixture-files:<real-hex>`.
- `reports/demo/prompt-injection-fixture/evidence.json` — fixture scan of adversarial-helper, 1 observation (PROMPT_INJECTION_INDICATOR) with labeled `untrustedExcerpt`.

### Remaining

1. Rehearse `/investigate` skill against each demo evidence bundle in the IDE.
2. Capture sanitized Bob session screenshots to `bob_sessions/`.
3. Run the existing report renderer after the Bob rehearsal, then implement menu and gate (Sub-Tasks 7–8) and complete the end-to-end run.

---

## Dependency boundary

All runtime code uses Node.js v24 built-in modules only:
`node:crypto`, `node:fs/promises`, `node:path`, `node:readline`, `node:util`,
`node:https`, `node:zlib`, `node:test`, `globalThis.fetch`.
No `npm install` is needed to build or test this project.

---

## Test summary

| Test file | Tests | Status |
|---|---|---|
| `tests/archive.test.mjs` | 6 | ✔ all pass |
| `tests/checks.test.mjs` | 8 | ✔ all pass |
| `tests/collector.test.mjs` | 7 | ✔ all pass |
| `tests/input.test.mjs` | 8 | ✔ all pass |
| `tests/lockfile-diff.test.mjs` | 9 | ✔ all pass |
| `tests/schema.test.mjs` | 5 | ✔ all pass |
| `tests/report.test.mjs` | Report validation, aggregation, rendering, and failure cases | Offline |
