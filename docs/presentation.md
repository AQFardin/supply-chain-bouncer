# Supply Chain Bouncer — Slide Presentation Deck

> **Format**: 6-Slide Executive Pitch Deck (conforming to IBM Bob 2.0 Hackathon Guide Section 16).  
> **Topic**: AI-Orchestrated Dependency Review & Cryptographic Local Gate with IBM Bob.

---

## Slide 1: Problem & Motivation

### Title: Defending the Modern Supply Chain with IBM Bob 2.0
**Subtitle**: Zero-Execution Dependency Investigation & Cryptographically Bound Security Gates

### Key Content:
* **The Blind Spot**: Conventional software composition analysis (SCA) tools rely on CVE databases (NVD/OSV). Newly published malicious packages or poisoned versions have **zero registered CVEs** on day one.
* **The Attack Vector**: Harmless-looking packages sneak into `package-lock.json` with malicious lifecycle scripts (`preinstall`/`postinstall`) that silently harvest developer credentials (`AWS_SECRET_ACCESS_KEY`, `NPM_TOKEN`) and execute subprocesses on `npm install`.
* **Our Solution**: **Supply Chain Bouncer** turns dependency updates into an evidence-driven review workflow. Powered by IBM Bob 2.0, it coordinates three specialized investigators in parallel, captures human security decisions, and enforces a deterministic gate that prevents unverified code execution.

> **Speaker Note**: *"Today, when a developer opens a pull request, they're flying blind. Vulnerability scanners only know about yesterday's attacks. Supply Chain Bouncer brings IBM Bob directly into the review loop to catch day-zero implants before they ever run on a machine."*

---

## Slide 2: End-to-End Workflow

### Title: The Review, Gate, and Repair Lifecycle
**Subtitle**: From Suspicious PR to Autonomous Remediation in 5 Steps

### Key Content:
1. **Deterministic Static Scan**: Bounded in-memory comparison of npm lockfile v3 snapshots without running package scripts. Emits structured `evidence.json`.
2. **Bob Coordinates 3 Subagents**: Invoked via `/investigate`, Bob spawns three parallel subagents to evaluate typosquatting, provenance, and code behavior. Emits `findings.json` recommending **BLOCK**.
3. **Interactive Human Review**: Developer inspects findings in a terminal menu; AI advises, but the **human selects ALLOW, QUARANTINE, or BLOCK**.
4. **Local Gate Enforcement**: The gate verifies input bindings. If BLOCK or stale, it exits with non-zero status and **withholds release authorization**.
5. **Autonomous Bob Repair**: Bob in Agent mode strips the blocked package from `package.json` and lockfile v3, producing a clean candidate that passes the gate with **Exit Code 0**.

> **Speaker Note**: *"Notice the separation of concerns: deterministic code collects facts, Bob reasons and investigates, the human makes the final decision, the gate enforces, and Bob repairs the code."*

---

## Slide 3: Architecture & Security Invariants

### Title: Zero-Execution Architecture & Threat Boundaries
**Subtitle**: Defense in Depth with Zero External Dependencies

### Key Content:
* **Zero Target Code Execution**: Package scripts and archives are parsed strictly as data/AST. No `node` execution, no `npm install`, no shell invocation of target code.
* **Decompression Defense (Zip Bomb / Traversal)**: Streaming tar parser with strict uncompressed byte thresholds (`maxOutputLength`), path traversal protection (`../`), and symlink rejection.
* **Cryptographic Input Binding**: Every decision is bound to a fixed-order SHA-256 array of input digests (manifests, lockfiles, policy rules, scanner release, and evidence). Tampering with even 1 whitespace character immediately invalidates approval (Exit code 2).
* **Zero External Dependencies**: Built 100% with Node.js v24 LTS built-in modules (`node:crypto`, `node:fs/promises`, `node:zlib`, `node:test`) to eliminate supply chain vulnerabilities in the scanner itself.

> **Speaker Note**: *"How can you trust a security scanner that has 500 npm dependencies? You can't. Supply Chain Bouncer uses zero external dependencies—eliminating scanner poisoning at the root."*

---

## Slide 4: Deep IBM Bob 2.0 Integration

### Title: Leveraging the Full Power of IBM Bob
**Subtitle**: Multi-Agent Orchestration Beyond Autocomplete

| Bob Capability | Implementation in Supply Chain Bouncer | Artifact Evidence |
| :--- | :--- | :--- |
| **Plan Mode** | Architectural blueprinting, threat boundaries, and phased implementation roadmaps | [`docs/architecture.md`](architecture.md) |
| **Custom Skills** | Repeatable, versioned investigation workflow in `.bob/skills/supply-chain-bouncer/SKILL.md` | Skill definition |
| **Slash Commands** | One-touch developer invocation (`/investigate <evidence-path>`) | [`.bob/commands/investigate.md`](../.bob/commands/investigate.md) |
| **Parallel Subagents** | 3 concurrent specialized agents: Typosquat Detective, Provenance Auditor, Behavior Analyst | [`.bob/agents/`](../.bob/agents/) |
| **Agent Mode Repair** | Autonomous diff generation and clean manifest/lockfile remediation | [`bob_sessions/`](../bob_sessions/) |

> **Speaker Note**: *"We didn't just use Bob to write code; Bob is an active runtime component of the product. It coordinates three subagents simultaneously and acts as an autonomous engineer to repair blocked PRs."*

---

## Slide 5: Measured Demonstration Results

### Title: Empirical Evaluation & Benchmarks
**Subtitle**: Fast, Transparent, and Thoroughly Verified

| Benchmark Case | Description | Measured Result | Latency |
| :--- | :--- | :--- | :--- |
| **Suspicious Fixture** | `mock-telemetry-reporter` install-time credential exfil | Status: `quarantine`; 6 observations | **16.2 ms** |
| **Bob Investigation** | 3 subagents concurrent evidence reasoning | `findings.json` aggregate `BLOCK` | **~75 s** (Bob) |
| **Gate BLOCK** | Human BLOCK decision enforcement | **Exit Code 4**; marker withheld | **48.2 ms** |
| **Tamper Defense** | Modified candidate lockfile whitespace | **Exit Code 2** (`QUARANTINE: Stale`) | **41.6 ms** |
| **Bob Repair** | Autonomous removal of blocked dependency | Clean removal diff applied | **~15 s** (Bob) |
| **Gate ALLOW** | Clean candidate approved by reviewer | **Exit Code 0**; marker created | **51.8 ms** |
| **Acceptance Suite** | Full regression and schema validation suite | **80 tests passed** (0 failures) | **2.93 s** |

> **Speaker Note**: *"Every number on this slide is real and measured. All CLI operations execute in under 70 milliseconds, and the entire test suite passes in under 3 seconds."*

---

## Slide 6: Limitations & Next Steps

### Title: Security Disclosures & Future Roadmap
**Subtitle**: Transparent Engineering for Production Readiness

### Disclosures & Current Boundaries:
* **Operating Mode**: Current release operates in declared `trusted-local-demo` mode (assuming trusted developer workspace and CLI operator).
* **Static Limitations**: Static inspection identifies code patterns (e.g., `process.env` access and `execSync`), but cannot prove runtime data flow or decrypt heavily obfuscated dynamic payloads without sandboxed execution.

### Production Roadmap:
1. **Cryptographically Signed Decisions**: Ed25519 reviewer keypairs signed via Node.js crypto (Section 10B extension).
2. **Remote GitHub Actions Gate**: Automatic PR evaluation with commit status checks (`supply-chain-bouncer/gate`) and branch protection rules.
3. **Live SLSA/Sigstore Attestation**: Native verification adapter querying npm's public provenance transparency logs.

> **Speaker Note**: *"We are honest about our boundaries: this is a local developer review assistant, not an endpoint sandbox. With signed reviewer envelopes and GitHub Actions integration on our roadmap, Supply Chain Bouncer is positioned to become standard enterprise PR infrastructure."*
