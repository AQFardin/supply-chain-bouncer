# Step 12: human review and local gate

This extension adds an interactive menu and an unsigned local gate. All files that existed before this step, including Bob's CLI, reports, findings, schemas and documentation, are preserved. Use the new `src/local-cli.mjs` entry point for review, gate and the harmless downstream demonstration. The original `src/cli.mjs` still provides scan and report.

The implemented mode is **trusted-local-demo**: it assumes a trusted local operator. It detects stale review inputs, but does not authenticate the reviewer or prevent someone controlling the workspace from forging both the decision and its companion binding. Signed mode and CI use are rejected. No package is installed or executed by these commands.

## Review the existing suspicious fixture

Run these commands from the repository root in an interactive terminal. The human must choose the action, provide a reason, and enter a reviewer label. The existing Bob recommendation is BLOCK; it is separate from the human's choice. The menu defaults to QUARANTINE.

```powershell
node src/local-cli.mjs review --base fixtures/suspicious/base --head fixtures/suspicious/head --run reports/demo/suspicious-fixture --interactive --decision decisions/suspicious-review.json
```

The menu shows input hashes, the evidence mode, observations, each investigator's findings and citations, unknowns, the recommendation, and hard policy violations. ALLOW is unavailable for hard violations or incomplete evidence. Reviewable warnings can be accepted by a human with a reason.

The existing findings have a generation timestamp earlier than evidence collection. The menu highlights that inconsistency. Findings are displayed as Bob's interpretations; citation existence and schema validity do not prove every interpretation. The fixture demonstrates suspicious static patterns and does not establish a real attack or observed credential transmission.

Two new files are saved: `decisions/suspicious-review.json` and `decisions/suspicious-review.json.binding.json`. Keep them together. Both use exclusive creation: an existing decision is never overwritten. Choose a new filename for another review, or omit `--decision` to create a unique filename under `decisions/`. Parent directories must already exist. No human decision was made during implementation; automated test decisions are confined to temporary directories.

## Evaluate the decision

```powershell
node src/local-cli.mjs gate --base fixtures/suspicious/base --head fixtures/suspicious/head --run reports/demo/suspicious-fixture --decision decisions/suspicious-review.json
$gateExit = $LASTEXITCODE
Write-Host "Gate exit: $gateExit"
```

| Code | Result |
| --- | --- |
| 0 | A human ALLOW matches the current complete review and passes policy |
| 2 | QUARANTINE, missing/malformed/expired approval, or stale/mismatched binding |
| 3 | Operational failure, unsupported configuration/source, or incomplete evidence/investigations |
| 4 | Human BLOCK on a complete review, or a hard blocking policy violation |

After validating the decision and binding, the gate checks current inputs, hard violations, completeness, and the human choice in that order. An invalid or incomplete review never passes. A stale BLOCK record is also stale and returns 2; an incomplete review returns 3 even if the recorded choice was BLOCK.

## Demonstrate actual downstream enforcement

```powershell
node src/local-cli.mjs demo --base fixtures/suspicious/base --head fixtures/suspicious/head --run reports/demo/suspicious-fixture --decision decisions/suspicious-review.json --marker decisions/release-permitted.txt
```

This command evaluates the gate and writes the harmless marker **only when the gate returns 0**. A BLOCK, QUARANTINE, stale, or incomplete result withholds the marker. It never runs target code. Use a new marker path each time: existing markers are rejected to avoid confusing a previous success with the current run.

PowerShell does not automatically stop later commands after a nonzero native exit. If integrating a different harmless downstream action, explicitly test `$LASTEXITCODE -eq 0` before running it. The `demo` command implements that condition internally.

## Exact input binding

The decision still conforms to Bob's original `schemas/decision.schema.json` and retains the scanner's four-file `subjectDigest`. The required companion file has its own new `schemas/review-binding.schema.json`. It binds the exact decision bytes and a fuller review snapshot. A legacy decision without this companion cannot pass this gate. It is intentionally stored under `decisions/`, outside the old report directory.

The full review digest is SHA-256 over the UTF-8 `JSON.stringify` representation of an ordered array of `[label, hash]` pairs, in this fixed order:

1. Contract identifier, absolute real base-directory identity, absolute real candidate-directory identity.
2. Base `package.json`, base `package-lock.json`, candidate `package.json`, candidate `package-lock.json` — hashes of exact bytes.
3. Base `.npmrc`, base `npm-shrinkwrap.json`, candidate `.npmrc`, candidate `npm-shrinkwrap.json` — exact hashes or the literal `ABSENT` marker.
4. Trusted `policy/policy.json`, `policy/popular-packages.json`, scanner `package.json`, scanner `package-lock.json` (or `ABSENT`).
5. Scanner release: SHA-256 of ordered `[relative path, exact file hash]` pairs from all files recursively under `src/` and then `schemas/`, with directory entries sorted lexically. Scanner symlinks are rejected.
6. Exact `evidence.json` bytes and exact `findings.json` bytes (or `ABSENT`).
7. Ordered fixture file-set digests for added/changed packages, using the collector's sorted `[relative path, file text]` records. These must also match the recorded fixture source digest. An empty list is hashed for live mode.

The gate rebuilds this snapshot from disk on every invocation. The menu rereads it before saving, so edits made while the reviewer was reading abort the save. A move to different dependency-root directories requires a new review. File whitespace changes also invalidate existing approval.

## Scope and limitations

- One dependency root, npm lockfile version 3, explicit base and candidate directories. Workspaces, linked dependencies and shrinkwrap are unsupported.
- Project `.npmrc` allows comments, blank lines, the supported public HTTPS registry setting, and `ignore-scripts=true`. Other settings are rejected without printing their contents. This gate reads explicit lockfile inputs; it does not invoke npm or resolve through user/global npm configuration.
- Every changed package must have collected artifact/fixture and metadata sources and package-specific citations from every investigator. Missing roles, invalid references, omitted coverage, unsupported sources, and incomplete collection prevent ALLOW.
- Live evidence must record an artifact digest matching the valid lockfile SHA-512 integrity. The gate uses the collector's saved source record; it does not fetch artifacts again or independently verify npm provenance. Cached mode is currently unsupported.
- Fixture mode remains explicitly synthetic. Placeholder fixture SRI values do not claim verified npm artifact integrity. The actual local fixture contents must match the collected digest.
- Bob recommendations remain advisory; a hard artifact integrity violation cannot be overridden by ordinary ALLOW. This extension does not silently turn an AI recommendation into a human decision.
- This is a point-in-time local check. It does not enforce unrelated installation commands, protect remote branches, or authenticate local files. All consumed source/report data and the operator are within the declared trusted-local assumption.
- The original README and HTML reports still describe the earlier milestone because they were preserved as requested. Use this guide and the new CLI for step 12; no original reports are regenerated.

## Verification

```powershell
node --test tests/gate.test.mjs
npm test
```

Tests use temporary copies and explicitly artificial test choices. They exercise the default menu choice, ALLOW/QUARANTINE/BLOCK, hard integrity violations, incomplete/failed/missing investigators, invalid references, malformed decisions, stale dependency/evidence/configuration/fixture inputs, policy/scanner/reference changes, expiry, safe output creation, CI rejection, real CLI exit codes, and downstream marker withholding. Target package files are only read as text.
