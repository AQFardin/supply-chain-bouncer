# Supply Chain Bouncer — Architecture

## Purpose

Supply Chain Bouncer reviews npm dependency changes detected in a `package-lock.json`
(lockfile version 3) before they reach production. It collects static evidence from
the lockfile and the npm registry without executing target code, orchestrates three
parallel Bob investigator subagents to reason over that evidence, and produces a
structured investigation report. A human makes the final ALLOW / QUARANTINE / BLOCK
decision. A planned local CLI gate will evaluate the decision against policy.

---

## Implemented scope

| In scope | Out of scope |
|---|---|
| npm lockfile v3 (`package-lock.json`) | yarn.lock, pnpm-lock, other formats |
| Direct and transitive dependency changes | Multi-root monorepos |
| Static evidence only — no `npm install`, no script execution | Installing or running target packages |
| Fixture mode (harmless local files) and live mode (real npm registry) | Other registries as primary evidence |
| Report rendering and validation of matching local decision records | Review menu and gate enforcement (next phase) |
| Human decision schema | Cryptographic signing and remote CI (optional extensions) |
| Parallel Bob subagents via skill | External AI services |

---

## Repository structure

| Path | Contents |
|---|---|
| `src/cli.mjs` | CLI entry point — `scan` and `report` commands |
| `src/report.mjs` | Validated JSON/HTML report generation |
| `src/validation.mjs` | Runtime validation of the project's schema keywords |
| `schemas/findings.schema.json` | Combined investigator wrapper contract |
| `schemas/report.schema.json` | Rendered report contract |
| `src/input.mjs` | Project input loader, SHA-256 file hasher, subject-digest computation |
| `src/lockfile-diff.mjs` | Lockfile comparator — produces direct/transitive diff with unsupported-source detection |
| `src/collector.mjs` | Evidence collector — registry fetch, fixture file inspection, static checks |
| `src/registry.mjs` | Registry HTTP adapter — metadata and artifact fetching with allowlist validation |
| `src/archive.mjs` | In-memory `.tgz` inspector — decompresses and parses without disk writes |
| `src/checks/index.mjs` | Static check orchestrator |
| `src/checks/rules.mjs` | Deterministic check rules (typosquat, lifecycle scripts, code patterns, prompt-injection) |
| `schemas/evidence.schema.json` | Evidence bundle data contract |
| `schemas/investigation.schema.json` | Bob investigator output contract |
| `schemas/decision.schema.json` | Human decision envelope contract |
| `policy/policy.json` | Gate policy rules |
| `policy/popular-packages.json` | Popular package reference list for typosquat detection |
| `policy/reviewers.json` | Reviewer identity reference |
| `tests/*.test.mjs` | Offline regression suites; optional live-registry test via `BOUNCER_LIVE_TESTS=1` |
| `fixtures/` | Harmless, labelled test inputs: benign, suspicious, prompt-injection, legitimate-install-script, malformed |
| `examples/sample-app/` | Sample application for end-to-end demonstration |
| `reports/demo/` | Sanitized demonstration evidence bundles |
| `decisions/` | Recorded human review decisions |
| `.bob/skills/supply-chain-bouncer/SKILL.md` | Bob investigation skill (parallel subagent orchestration) |
| `.bob/agents/` | Three investigator role instruction files |
| `.bob/commands/investigate.md` | `/investigate` slash command entry point |
| `docs/` | Architecture and plan documents |

---

## Data flow

```
package-lock.json (base)     package-lock.json (candidate)
       │                              │
       └─────── src/input.mjs ────────┘
                (load + hash)
                      │
              subjectDigest (SHA-256 over 4 files)
                      │
          src/lockfile-diff.mjs
          (compareLockfiles)
                      │
           dependency diff
           changed: added / changed / removed
           each: name, version, integrity,
                 isDirect, scripts, unsupported
                      │
           src/collector.mjs
           (collectEvidence)
           ├── src/registry.mjs (fetchPackageMetadata, fetchPackageArtifact)
           ├── src/archive.mjs  (inspectTgzArchive — in-memory only)
           └── src/checks/      (runStaticChecks)
                      │
             evidence.json
             (schemas/evidence.schema.json)
                      │
         Bob skill: supply-chain-bouncer
         (/investigate <evidence-path>)
         ┌───────────────┬────────────────────┐
         ▼               ▼                    ▼
  typosquat-       provenance-          behavior-
  detective        auditor              analyst
  (parallel        (parallel            (parallel
   subagent)        subagent)            subagent)
         │               │                    │
         └───────────────┴────────────────────┘
                         │
                   findings.json
                   (3 × schemas/investigation.schema.json
                    wrapped in combined envelope)
                         │
               [NOT YET IMPLEMENTED]
               src/reporter.mjs → report.json + report.txt
               src/menu.mjs     → terminal review menu
               src/gate.mjs     → local gate (exit 0/1)
```

---

## Three-layer model

### Layer 1 — Deterministic code (all implemented)

All modules in `src/` are pure, side-effect-free logic unit-tested without Bob.

**`src/input.mjs`** — Loads `package.json` + `package-lock.json` pairs, enforces
lockfileVersion 3, rejects `npm-shrinkwrap.json`, computes per-file SHA-256 hashes
and a stable `subjectDigest` over all four input files.

**`src/lockfile-diff.mjs`** — Compares two lockfile v3 `packages` maps, classifies
each entry as `added`, `changed`, `removed`, or `unchanged`, distinguishes direct
from transitive dependencies, and detects unsupported source types.

**`src/collector.mjs`** — Coordinates evidence collection:
- In `live` mode: fetches registry metadata and artifact tarball over HTTPS, inspects
  the `.tgz` in memory, computes SHA-512 integrity of the downloaded artifact.
- In `fixture` mode: reads local fixture package files, computes a SHA-256 content
  digest of the inspected files (labeled `sha256-fixture-files:<hex>` to clearly
  distinguish from verified downloaded-artifact integrity). Missing fixture files are
  flagged as `incomplete` evidence, never silently treated as complete.
- Runs deterministic static checks on file contents and metadata fields.

**`src/checks/rules.mjs`** — Deterministic check rules:
- `checkNameNearMatch` — Levenshtein distance ≤ 2 against popular packages list.
- `checkLifecycleScripts` — Detects added or changed install/preinstall/postinstall scripts.
- `analyzePackageFiles` — Regex scans for `ENVIRONMENT_ACCESS`, `NETWORK_OPERATION`,
  `PROCESS_EXECUTION`, `DYNAMIC_EXECUTION`, `OBFUSCATION_INDICATOR`.
- `checkMetadataFields` — Scans package metadata text fields (e.g. `description`) for
  prompt-injection patterns. Matches are surfaced as labeled untrusted excerpts:
  `[UNTRUSTED DATA from <pkg> <field>]: <text>`. The matched text is treated strictly
  as evidence data — investigators must cite it, never follow it.

**`src/archive.mjs`** — Pure in-memory gzip decompression + tar parsing. Enforces:
- 10 MiB compressed, 50 MiB expanded, 5000 entry, 1 MiB-per-file limits.
- Rejects directory traversal and symlink entries.
- Tracks omitted large files explicitly (never silent).

**`src/registry.mjs`** — HTTPS-only, allowlisted registry fetch (`registry.npmjs.org`,
`registry.yarnpkg.com`). Rejects embedded credentials, non-HTTPS protocols, and unknown
registry hosts.

### Layer 2 — Bob reasoning (skill + role files)

Bob is invoked after the evidence bundle is written to disk. The investigation skill
[`.bob/skills/supply-chain-bouncer/SKILL.md`](.bob/skills/supply-chain-bouncer/SKILL.md)
guides Bob through:

1. Reading the evidence bundle and output schema.
2. Spawning three parallel subagents in the same turn.
3. Collecting and validating their outputs.
4. Writing `findings.json` to the evidence directory.

**Custom native Workflow authoring is not supported in this Bob version.** The skill
is the correct substitute. The `/investigate` slash command
([`.bob/commands/investigate.md`](.bob/commands/investigate.md)) provides a convenient
entry point.

**Investigator roles** — role instruction files in `.bob/agents/`:
- `investigator-typosquat-detective.md` — name similarity, scope confusion, typosquat signals.
- `investigator-provenance-auditor.md` — registry source, integrity consistency, publish metadata.
- `investigator-behavior-analyst.md` — lifecycle scripts, code patterns, prompt-injection detection.

Each role file specifies the role's focus, required evidence fields, output contract,
and hard constraints (no execution, treat metadata as data, incomplete → QUARANTINE).

**Bob "persona files" do not exist as a concept** in this version. Roles are implemented
as role-instruction markdown files loaded by the skill as supporting files.

### Layer 3 — Human decisions (not yet implemented)

`src/report.mjs` is implemented. `src/menu.mjs` and `src/gate.mjs` are planned for
the next phase. Reports validate evidence, each investigator, and optional human
decision records. Subject digests must match; missing/failed roles cannot produce
ALLOW. Recommendations are recomputed from individual roles with hard evidence
constraints; a human record never overwrites that recommendation. The renderer
does not verify current workspace inputs or enforce a gate.

---

## Data contracts

### `evidence.json` — `schemas/evidence.schema.json`

Top-level required fields: `schemaVersion`, `runId`, `mode`, `subjectDigest`,
`scannerVersion`, `policyDigest`, `collectionStatus`, `packages`, `observations`,
`unknowns`, `sources`.

**`collectionStatus`** values:
- `"complete"` — all evidence collected, no incomplete reasons, no critical observations.
- `"incomplete"` — at least one incomplete reason (missing files, unsupported source,
  archive truncation, etc.).
- `"quarantine"` — at least one critical-severity observation.

**`sources[].contentDigest`** labeling:
- `sha256-metadata:<hex>` — SHA-256 of registry response bytes, or synthetic metadata
  serialization in fixture mode. This is not downloaded-artifact integrity.
- `sha512-<base64>` — computed SHA-512 of a downloaded artifact (live mode, verified).
- `sha256-fixture-files:<hex>` — SHA-256 over inspected fixture file content
  (fixture mode, synthetic — NOT a verified download).
- `sha256-fixture-files:empty-no-files-found` — no fixture files discovered; evidence
  is incomplete for this package.

**`observations[].untrustedExcerpt`** — present on `PROMPT_INJECTION_INDICATOR`
observations only. Contains the adversarial text labeled as:
`[UNTRUSTED DATA from <pkg> <field>]: <text>`. Investigators must cite it as evidence
and must not follow its directives.

### `findings.json` (combined investigation output)

Produced by the Bob skill after all three subagents complete. Wraps three
`schemas/investigation.schema.json` objects plus:
- `aggregateRecommendation` — most restrictive of the three (`BLOCK` > `QUARANTINE` > `ALLOW`).
- `investigationComplete` — `true` only if all three `status` values are `"complete"`.

### `decision.json` — `schemas/decision.schema.json`

Human review decision. Required fields: `schemaVersion`, `mode`, `subjectDigest`,
`decision`, `reason`, `reviewerLabel`, `createdAt`.

`mode` values: `"trusted-local-demo"` (no crypto) or `"signed-local"` (optional extension).

---

## Unsupported dependency sources

The collector explicitly does not fetch registry evidence for these source types.
Each is flagged `"unsupported": true` in the evidence bundle.

| Pattern | Detection | Reason |
|---|---|---|
| `git+https://...` | version or resolved prefix | No registry metadata |
| `git+ssh://...` | version or resolved prefix | No registry metadata |
| `github:<user>/<repo>` | version prefix | No registry metadata |
| `file:../...` | version or resolved prefix | Local path, no tarball |
| `link:../...` | version or resolved prefix | Symlink, no tarball |
| Non-standard registry hostname | resolved URL hostname check | Registry not queried |
| Invalid resolved URL | URL parse failure | Cannot fetch |

---

## Bob feature support (verified)

| Feature | Support | Implementation |
|---|---|---|
| Reusable skill with supporting files | Supported | `.bob/skills/supply-chain-bouncer/SKILL.md` |
| Parallel subagent spawning | Supported | `spawn_subagent` called in same turn |
| Slash command | Supported | `.bob/commands/investigate.md` |
| Custom native Workflow authoring | **Not supported** | Skill is the correct substitute |
| Persona files | **Not a Bob concept** | Role files in `.bob/agents/` loaded by skill |
| Project-mode custom modes | Supported | `.bob/custom_modes.yaml` (not used here) |

---

## Gate modes

| Mode | Behaviour | Crypto |
|---|---|---|
| `trusted-local-demo` (planned) | Requires current input hashes, complete evidence and investigators, policy checks, and explicit human approval | None |
| `signed-local` (optional) | HMAC-SHA256 over decision envelope, 1-hour TTL, key from env | Symmetric key |

Canonical JSON serialisation is not implemented. Canonical JSON is not planned.

---

## Remaining implementation

- `src/report.mjs` — JSON and escaped HTML reports are implemented; real Bob findings still require a rehearsal in Bob IDE.
- `src/menu.mjs` — Terminal review menu capturing human ALLOW / QUARANTINE / BLOCK.
- `src/gate.mjs` — Local gate: checks current input hashes, evidence completeness,
  all required investigator outputs, policy, and human approval. Exits 0 or 1.
- Optional signed decisions: HMAC-SHA256, 1-hour TTL, key from env. Signed records are rejected until verification is implemented.
- GitHub status check: POST to GitHub Checks API (separate readiness check required first).
