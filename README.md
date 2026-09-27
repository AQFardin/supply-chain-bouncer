# Supply Chain Bouncer

> **An AI-orchestrated dependency review assistant and deterministic local security gate built with IBM Bob 2.0.**

Supply Chain Bouncer helps developers safely review npm dependency changes in pull requests. Instead of relying solely on CVE databases (which fail against zero-day malicious packages), the Bouncer performs static, zero-execution evidence collection, orchestrates **three specialized IBM Bob subagents in parallel**, records an interactive human security decision, and enforces a cryptographic local gate that halts malicious dependencies before they can reach production.

---

## 🌟 Key Features

1. **Zero Untrusted Code Execution**: Analyzes npm lockfiles (v3), package metadata, and tarball contents entirely in-memory using AST parsers and regex patterns. Target package install scripts are never run.
2. **Decompression Defense (Zip Bomb & Traversal)**: Bounded archive inspection defends against zip bombs (strict uncompressed limits), directory traversals, symlinks, and oversized files.
3. **Three Specialized IBM Bob Investigators**:
   - 🕵️ **Typosquat Detective**: Detects Levenshtein distance impersonations against canonical popular packages.
   - 🔍 **Provenance Auditor**: Verifies lockfile integrity, checks registry publish metadata, maintainer history, and flags synthetic fixture artifacts.
   - 🔬 **Behavior Analyst**: Pinpoints suspicious postinstall scripts, environment secret harvesting (`AWS_SECRET_ACCESS_KEY`, `NPM_TOKEN`), outbound network requests, and child process execution (`execSync`).
4. **Human-in-the-Loop Decision**: AI recommendations are strictly advisory. The developer reviews findings in an interactive terminal menu and chooses **ALLOW**, **QUARANTINE**, or **BLOCK**.
5. **Tamper-Evident Input Binding**: Decisions are cryptographically bound via SHA-256 to exact base/head manifests, lockfiles, policy rules, scanner release code, and evidence bundles. If an attacker modifies even 1 whitespace character after approval, the gate fails closed (Exit code `2`).
6. **Automated Bob Remediation Loop**: Bob in Agent mode can automatically repair a blocked candidate pull request, regenerate clean diffs, and allow a verified release (Exit code `0`).
7. **Zero External Runtime Dependencies**: Built entirely with Node.js v24 LTS built-in modules (`node:crypto`, `node:fs/promises`, `node:path`, `node:readline`, `node:test`, `node:zlib`).

---

## 🏗️ Architecture & Trust Boundaries

```text
Base Manifest & Lockfile        Candidate Manifest & Lockfile
            \                              /
             Deterministic Lockfile Comparator (v3)
                            |
           Static Evidence Collection (Zero Execution)
                            |
              IBM Bob Agent Mode (/investigate)
             /              |               \
    Typosquat Detective  Provenance Auditor  Behavior Analyst
             \              |               /
               Evidence-Linked findings.json
                            |
             Interactive Terminal Review Menu
             (Developer chooses ALLOW / QUARANTINE / BLOCK)
                            |
            Local Gate & Exact Cryptographic Input Binding
             (Exit 0 = Pass, Exit 2 = Stale, Exit 4 = Blocked)
                            |
           Autonomous Bob Repair & Verified Release Marker
```

---

## 🚀 Quickstart & Demo Commands

### Prerequisites
* **Node.js**: `v24.12.0` (or higher LTS)
* **npm**: `v10.9.0` (or higher)
* **IBM Bob IDE**: Signed into your hackathon-provisioned account.

Clone the repository:
```bash
git clone https://github.com/AQFardin/supply-chain-bouncer.git
cd supply-chain-bouncer
```

Run the complete test suite (80 tests across 7 suites):
```bash
npm test
```

---

## 🎬 End-to-End Walkthrough

### 1. Scan a Dependency Change
Scan the candidate lockfile and collect static evidence without executing any target code:
```bash
node src/cli.mjs scan --base fixtures/suspicious/base --head fixtures/suspicious/head --mode fixture --out reports/demo/suspicious-fixture
```

### 2. Generate Evidence Reports
Render both structured JSON and rich, self-contained HTML reports:
```bash
node src/cli.mjs report --run reports/demo/suspicious-fixture
```
*Reports generated at `reports/demo/suspicious-fixture/report.html` and `report.json`.*

### 3. Run the IBM Bob Investigation
Open the repository in **Bob IDE** and run the slash command in chat:
```text
/investigate reports/demo/suspicious-fixture/evidence.json
```
Bob launches the three subagents in parallel and emits `reports/demo/suspicious-fixture/findings.json` recommending **BLOCK**.

### 4. Interactive Human Review & Local Gate Enforcement
In Bob's integrated terminal, review the evidence and record your decision:
```bash
node src/local-cli.mjs review --base fixtures/suspicious/base --head fixtures/suspicious/head --run reports/demo/suspicious-fixture --interactive --decision decisions/suspicious-review.json
```
*Select `BLOCK`, enter your reason, and provide your reviewer label.*

Now evaluate the gate:
```bash
node src/local-cli.mjs demo --base fixtures/suspicious/base --head fixtures/suspicious/head --run reports/demo/suspicious-fixture --decision decisions/suspicious-review.json --marker decisions/release-permitted.txt
```
**Result**: Gate exits with code `4` (BLOCKED). Downstream release marker is withheld.

### 5. Automated Repair & Passing Gate
Ask Bob in Agent mode to repair the pull request:
> *"The package 'mock-telemetry-reporter' was blocked. Please repair the candidate by removing it cleanly from package.json and package-lock.json."*

Once repaired, evaluate the gate on the clean candidate:
```bash
node src/local-cli.mjs demo --base fixtures/suspicious/base --head fixtures/suspicious/base --run reports/demo/repaired-fixture --decision decisions/repaired-review.json --marker decisions/release-permitted.txt
```
**Result**: Gate exits with code `0` (ALLOWED) and creates `decisions/release-permitted.txt`!

Verify the release authorization:
```bash
node -e "console.log(require('fs').readFileSync('decisions/release-permitted.txt', 'utf8'))"
```
Output:
> *"Release step permitted by the local demo gate. No package code was executed."*

---

## 📊 Measured Evaluation Results

From [`docs/evaluation.md`](docs/evaluation.md):

| Test Case | Scenario | Expected | Actual | Measured Time |
| :--- | :--- | :--- | :--- | :--- |
| **CASE-01** | Suspicious Fixture Scan | Flag 6 malicious observations | Status: `quarantine`, 6 observations | **16.2 ms** |
| **CASE-02** | Bob 3-Subagent Investigation | Parallel subagent reasoning | `findings.json` with aggregate `BLOCK` | **~75 s** (Bob) |
| **CASE-03** | Gate BLOCK Evaluation | Block release marker | **Exit code 4**; marker withheld | **48.2 ms** |
| **CASE-04** | Stale Input / Tamper Defense | Catch modified lockfile bytes | **Exit code 2** (`QUARANTINE: Stale`); marker withheld | **41.6 ms** |
| **CASE-05** | Bob Automated Candidate Repair | Autonomous diff in Agent mode | Clean manifest & lockfile | **~15 s** (Bob) |
| **CASE-06** | Repaired Candidate Gate ALLOW | Authorize release marker | **Exit code 0**; marker created | **51.8 ms** |
| **CASE-07** | Prompt Injection Fixture | Isolate adversarial metadata | `PROMPT_INJECTION_INDICATOR` flagged | **14.8 ms** |
| **CASE-08** | Full Acceptance Suite | 80 unit & integration tests | **79 passed, 1 skipped, 0 failed** | **2.93 s** |

---

## 🤖 IBM Bob Feature Utilization

| Bob Feature | Where & How It Is Used | Evidence in Repo |
| :--- | :--- | :--- |
| **Plan Mode** | Architectural blueprint, threat boundaries, and implementation checklist | [`docs/architecture.md`](docs/architecture.md), [`supply-chain-bouncer-plan.md`](supply-chain-bouncer-plan.md) |
| **Agent Mode** | Deterministic scanner implementation, report generation, and autonomous candidate repair | [`src/`](src/), `bob_sessions/` |
| **Subagents** | Spawning 3 concurrent subagents (Typosquat, Provenance, Behavior) with distinct system prompts | [`.bob/agents/`](.bob/agents/) |
| **Custom Skills** | Reusable investigation workflow invoked via `/investigate` slash command | [`.bob/skills/supply-chain-bouncer/SKILL.md`](.bob/skills/supply-chain-bouncer/SKILL.md), [`.bob/commands/`](.bob/commands/) |
| **Task Evidence** | Token consumption and session metrics for hackathon validation | [`bob_sessions/`](bob_sessions/) |

---

## 📁 Repository Structure

```text
supply-chain-bouncer/
├── .bob/
│   ├── agents/          # Investigator subagent instruction files
│   ├── commands/        # Custom /investigate slash command
│   └── skills/          # Reusable supply-chain-bouncer skill
├── bob_sessions/        # Task-session summary screenshots for Bob evaluation
├── decisions/           # Recorded human decisions & cryptographic bindings
├── docs/                # Architecture, step guides, and measured evaluation
├── examples/            # Sample Node.js application
├── fixtures/            # Benign, suspicious, legitimate, and prompt-injection fixtures
├── policy/              # Gate policy rules and reference popular-package list
├── reports/demo/        # Generated JSON & HTML reports for demonstration runs
├── schemas/             # Strict JSON Schemas (Draft-07, additionalProperties: false)
├── src/                 # Scanner, comparator, report renderer, menu, and gate
└── tests/               # 80 automated unit, schema, and gate integration tests
```

---

## ⚖️ Security Boundaries & Disclosures

* **Mode Declaration**: Operates in explicitly declared `trusted-local-demo` mode (assuming trusted developer workspace and CLI operator). Remote CI enforcement and Ed25519 cryptographic reviewer key signatures are documented optional extensions.
* **Non-Execution Invariant**: Target code is inspected as static text/AST only; scripts are never run.
* **Advisory Role of AI**: Subagents interpret evidence and highlight unknowns; AI cannot override hard integrity violations or approve dependencies without human authorization.
