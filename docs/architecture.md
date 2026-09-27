# Supply Chain Bouncer — Architecture

## Purpose

Supply Chain Bouncer reviews npm dependency changes detected in a `package-lock.json`
(lockfile version 3) before they reach production. It collects static evidence from
the lockfile and the npm registry, orchestrates three Bob investigator roles to reason
over that evidence, captures a human ALLOW / QUARANTINE / BLOCK decision, and evaluates
the decision against a local CLI gate. No target code is executed at any point.

---

## Scope (first implementation)

| In scope | Out of scope |
|---|---|
| One dependency root (`examples/sample-app/`) | Multi-root monorepos |
| npm lockfile v3 (`package-lock.json`) | yarn.lock, pnpm-lock, other registries |
| Static evidence only (no `npm install`, no script execution) | Installing or running target packages |
| Local `trusted-local-demo` gate mode | Remote CI enforcement |
| Human decision recorded as JSON | Cryptographic signing (optional extension) |
| Three Bob investigator roles via skill | External AI services |

---

## Data Flow

```
package-lock.json (before)          package-lock.json (after)
         │                                    │
         └──────────── comparator ────────────┘
                            │
                    dependency diff
                    (added / changed / removed)
                            │
                   evidence collector
                  (registry metadata, hashes,
                   publish date, maintainers)
                            │
                    evidence bundle
                    (evidence.json)
                            │
              ┌─────────────┼─────────────┐
              ▼             ▼             ▼
       Investigator 1  Investigator 2  Investigator 3
       (supply-chain   (provenance &   (prompt-injection
        risk)          integrity)       & policy)
              │             │             │
              └─────────────┴─────────────┘
                            │
                   investigation report
                   (report.json + report.html)
                            │
                   terminal review menu
                  (human reads report, chooses
                   ALLOW / QUARANTINE / BLOCK)
                            │
                   decision envelope
                   (decision.json — labelled
                    trusted-local-demo)
                            │
                    local CLI gate
                   (evaluates decision against
                    policy rules, exits 0 or 1)
```

---

## Component Map

| Component | Location | Layer |
|---|---|---|
| Lockfile comparator | `src/comparator.mjs` | Deterministic code |
| Evidence collector | `src/collector.mjs` | Deterministic code (HTTP only) |
| Evidence schema | `schemas/evidence.schema.json` | Data contract |
| Investigation report schema | `schemas/report.schema.json` | Data contract |
| Decision envelope schema | `schemas/decision.schema.json` | Data contract |
| Policy rules | `policy/rules.json` | Configuration |
| CLI entry point | `src/cli.mjs` | Orchestration |
| Terminal review menu | `src/menu.mjs` | Human interface |
| Local gate | `src/gate.mjs` | Deterministic code |
| Bob investigation skill | `.bob/skills/supply-chain-bouncer/SKILL.md` | Bob reasoning |
| Investigator role files | `.bob/agents/` (3 × `.md`) | Bob reasoning |
| Sample application | `examples/sample-app/` | Demonstration |
| Fixture lockfiles | `fixtures/` | Test inputs |
| Decision records | `decisions/` | Outputs |
| Demo reports | `reports/demo/` | Outputs |

---

## Three-Layer Model

### Layer 1 — Deterministic code

All code in `src/` is pure, side-effect-free logic that can be unit-tested without Bob.
- **Comparator**: reads two lockfile JSON files, produces a structured diff.
- **Collector**: fetches `https://registry.npmjs.org/<pkg>/<version>` metadata over HTTPS
  (read-only, no install). Explicitly rejects scoped packages from non-npm registries,
  git references, `file:` paths, and `link:` paths — these are flagged as
  **unsupported dependency sources** and passed to investigators with a warning marker.
- **Gate**: reads a decision envelope and a policy file, returns exit code 0 (ALLOW) or
  1 (BLOCK/QUARANTINE). In `trusted-local-demo` mode the gate accepts a local signature
  field of `"mode": "trusted-local-demo"` with no cryptographic verification.

### Layer 2 — Bob reasoning

Bob is invoked manually by the developer inside the IDE after the evidence bundle is
written to disk. The investigation skill guides Bob through three sequential investigator
roles, each producing a typed finding object that is appended to the report.

**Investigator roles (defined in `.bob/agents/`):**
- `investigator-supply-chain.md` — examines version bump patterns, maintainer changes,
  publish timing, and known-bad version indicators.
- `investigator-provenance.md` — checks hash consistency, registry source, known
  signatures (future), and dist-tag alignment.
- `investigator-policy.md` — applies policy rules from `policy/rules.json`, checks for
  prompt-injection patterns in package metadata fields, and assigns a final risk score.

The skill reads the evidence bundle and each role file, then instructs Bob to produce
structured JSON findings. Bob does not execute code or install packages.

### Layer 3 — Human decisions

The terminal review menu (`src/menu.mjs`) presents the investigation report and
prompts the human developer for ALLOW, QUARANTINE, or BLOCK. The resulting
decision envelope includes the reviewer identity, timestamp, mode label, and
the chosen verdict. It is written to `decisions/` and passed to the gate.

---

## Data Contracts

### `evidence.json`
```
{
  "schema": "evidence/v1",
  "generatedAt": "<ISO-8601>",
  "rootPackage": "<name>@<version>",
  "changes": [
    {
      "name": "<pkg>",
      "changeType": "added|changed|removed",
      "fromVersion": "<semver|null>",
      "toVersion": "<semver|null>",
      "registryMeta": {
        "publishedAt": "<ISO-8601>|null",
        "maintainers": ["<email>"],
        "dist": { "tarball": "<url>", "shasum": "<hex>", "integrity": "<sri>" },
        "scripts": { "install": "<cmd|null>", "preinstall": "<cmd|null>", "postinstall": "<cmd|null>" }
      },
      "unsupported": false,
      "unsupportedReason": null
    }
  ]
}
```

### `report.json`
```
{
  "schema": "report/v1",
  "evidenceRef": "<path>",
  "generatedAt": "<ISO-8601>",
  "findings": [
    {
      "investigator": "supply-chain|provenance|policy",
      "riskLevel": "low|medium|high|critical",
      "summary": "<text>",
      "details": ["<text>"],
      "recommendation": "ALLOW|QUARANTINE|BLOCK"
    }
  ],
  "aggregateRisk": "low|medium|high|critical",
  "recommendedVerdict": "ALLOW|QUARANTINE|BLOCK"
}
```

### `decision.json`
```
{
  "schema": "decision/v1",
  "reportRef": "<path>",
  "decidedAt": "<ISO-8601>",
  "decidedBy": "<string>",
  "mode": "trusted-local-demo",
  "verdict": "ALLOW|QUARANTINE|BLOCK",
  "rationale": "<text>"
}
```

---

## Unsupported Dependency Sources

The collector explicitly does not fetch evidence for the following source types.
Each is flagged with `"unsupported": true` in the evidence bundle and the
investigators are instructed to treat them as requiring manual review.

| Source pattern | Example | Reason |
|---|---|---|
| `git+https://` reference | `"version": "git+https://..."` | No registry metadata |
| `git+ssh://` reference | `"version": "git+ssh://..."` | No registry metadata |
| `github:` shorthand | `"version": "github:user/repo"` | No registry metadata |
| `file:` path | `"version": "file:../local"` | Local path, no tarball |
| `link:` path | `"version": "link:../local"` | Symlink, no tarball |
| Non-npm scoped registry | `"resolved": "https://other-registry.com/..."` | Registry not queried |

---

## Bob Feature Usage

| Requirement | Bob API used | Notes |
|---|---|---|
| Reusable investigation workflow | Skill (`.bob/skills/supply-chain-bouncer/SKILL.md`) | Confirmed supported |
| Investigator roles | Role instruction files in `.bob/agents/`, loaded by skill | Read as supporting files |
| Terminal review menu | Deterministic Node.js code (`src/menu.mjs`) | Not a Bob feature |
| Custom native Workflow | **Not available** — `start_workflow` launches only platform-built-in workflows | Skill is the correct substitute |
| Persona files | **Not a Bob concept** — roles are custom modes or skill-embedded instructions | `.bob/custom_modes.yaml` for named investigator modes (optional) |

---

## Gate Modes

| Mode | Behaviour | Crypto required |
|---|---|---|
| `trusted-local-demo` | Accepts any decision envelope that has `"mode":"trusted-local-demo"` | No |
| `signed` (optional) | Verifies a HMAC-SHA256 signature over the decision envelope; valid for 1 hour | Yes — symmetric key in env var only |

Canonical JSON serialisation is **not** implemented. The signature covers the JSON
string as written to disk (stable field order enforced at write time by the gate module).

---

## Optional Extensions (not in first implementation)

- **Signed decisions**: HMAC-SHA256 over decision envelope, 1-hour TTL, key from env.
- **GitHub status check**: POST to GitHub Checks API from gate; requires separate
  readiness check before implementation.
- **HTML report**: `reports/demo/report.html` generated from `report.json`.
