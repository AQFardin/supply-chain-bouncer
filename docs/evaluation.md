# Supply Chain Bouncer — Measured Evaluation & Acceptance Report

**Date**: 27 September 2026  
**Scanner Version**: `0.1.0`  
**Node Version**: `v24.12.0`  
**Test Suite**: 80 tests across 7 suites (`npm test` — 79 passed, 1 skipped live network test, 0 failed)  
**Security Mode**: `trusted-local-demo` (bounded cryptographic input binding)

---

## 1. Acceptance Scenarios & Measured Results

| Case ID | Scenario / Test Fixture | Expected Outcome | Actual Outcome | Measured Elapsed Time | Evidence / Artifact Link |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **CASE-01** | **Suspicious Fixture Scan** (`mock-telemetry-reporter`) | Detects lifecycle script, env access, network calls, child process exec; status `quarantine` | 6 observations flagged; `collectionStatus: quarantine` | **16.2 ms** | [`evidence.json`](file:///e:/ibm%20hackathon%20project/supply-chain-bouncer/reports/demo/suspicious-fixture/evidence.json) |
| **CASE-02** | **Bob 3-Subagent Investigation** (`/investigate`) | 3 parallel subagents identify risks, preserve unknowns, and recommend BLOCK | Typosquat Detective, Provenance Auditor, Behavior Analyst emit findings; aggregate `BLOCK` | **~75 s** (Bob IDE parallel run) | [`findings.json`](file:///e:/ibm%20hackathon%20project/supply-chain-bouncer/reports/demo/suspicious-fixture/findings.json) |
| **CASE-03** | **Interactive Review & Gate BLOCK** | Review menu presents evidence; human decides BLOCK; gate returns exit code `4` | Exit Code `4`; downstream release marker withheld | **48.2 ms** | [`suspicious-review.json`](file:///e:/ibm%20hackathon%20project/supply-chain-bouncer/decisions/suspicious-review.json) |
| **CASE-04** | **Stale Input & Tamper Detection** | Mismatched candidate input files invalidate approval; gate returns exit code `2` | Exit Code `2` (`QUARANTINE: Evidence is stale`); marker withheld | **41.6 ms** | [`suspicious-review.json.binding.json`](file:///e:/ibm%20hackathon%20project/supply-chain-bouncer/decisions/suspicious-review.json.binding.json) |
| **CASE-05** | **Bob Automated Candidate Repair** | Bob removes blocked package from candidate `package.json` & lockfile | Clean candidate diff generated and applied in Agent mode | **~15 s** (Bob task) | [`repaired-fixture/`](file:///e:/ibm%20hackathon%20project/supply-chain-bouncer/reports/demo/repaired-fixture/) |
| **CASE-06** | **Repaired Review & Gate ALLOW** | Clean candidate reviewed as ALLOW; gate returns exit code `0` and writes marker | Exit Code `0`; `decisions/release-permitted.txt` created | **51.8 ms** | [`repaired-review.json`](file:///e:/ibm%20hackathon%20project/supply-chain-bouncer/decisions/repaired-review.json) |
| **CASE-07** | **Prompt Injection Resistance** | Hostile description treated as untrusted data; does not hijack agent directives | Flagged as `PROMPT_INJECTION_INDICATOR`; untrusted excerpt isolated | **14.8 ms** | [`prompt-injection/evidence.json`](file:///e:/ibm%20hackathon%20project/supply-chain-bouncer/reports/demo/prompt-injection-fixture/evidence.json) |
| **CASE-08** | **Live Registry Benign Bump** (`ms` 2.1.2 → 2.1.3 + `picocolors`) | Real npm tarballs downloaded & inspected in-memory; SHA-512 verified | 0 observations; provenance metadata preserved; status `complete` | **215.1 ms** | [`live-benign/report.html`](file:///e:/ibm%20hackathon%20project/supply-chain-bouncer/reports/demo/live-benign/report.html) |
| **CASE-09** | **Full Unit & Integration Suite** | Strict validation of schemas, parser limits, zip-bombs, gate policies, AST checks | 80 tests executed; 79 passed, 1 skipped (network test), 0 failed | **2.93 s** | `npm test` |

---

## 2. Security Invariants & Threat Boundaries Tested

1. **No Target Code Execution**: Package code, install scripts, and downloaded archives are never executed. Static inspection parses AST and raw buffers without running `node`, `npm install`, or subprocesses.
2. **Decompression Defense (Zip Bomb / Tar Traversal)**: 
   - Strict `maxOutputLength` passed to `zlib.gunzipSync` prevents unbounded memory decompression.
   - Files larger than 1 MiB are tracked in `omittedCoverage` rather than silently ignored.
   - Symlinks and paths containing `../` or absolute drives are rejected.
3. **Cryptographic Input Binding**:
   - Every human decision is bound to a fixed-order UTF-8 SHA-256 array of input digests: base manifest/lockfile, candidate manifest/lockfile, `.npmrc`, policy rules, scanner release files, `evidence.json`, and `findings.json`.
   - Modifying a single character or whitespace in any of these files immediately invalidates the decision and causes the gate to fail closed (Exit code `2`).
4. **Strict Schema Conformance**:
   - `evidence.schema.json`, `investigation.schema.json`, `decision.schema.json`, `findings.schema.json`, and `review-binding.schema.json` enforce `additionalProperties: false`.
5. **No Blind Trust in AI**:
   - Bob recommendations are strictly advisory.
   - Hard policy violations (such as `ARTIFACT_INTEGRITY_MISMATCH`) and missing evidence cannot be bypassed by an ordinary human `ALLOW`.

---

## 3. Tool & Runtime Specifications

* **Node.js**: `v24.12.0` (built-in modules only: `node:crypto`, `node:fs/promises`, `node:path`, `node:readline`, `node:test`, `node:assert/strict`, `node:zlib`)
* **npm**: `v10.9.0`
* **Bob IDE**: IBM Bob 2.0 (Plan mode, Agent mode, Subagent panel, Skill system)
* **External Runtime Dependencies**: `0` (Zero external dependencies in `dependencies` or runtime)
