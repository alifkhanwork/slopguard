# `@siliconvalleyglobal/slopguard` 🛡️

> **Real-Time AI Package Hallucination & Slopsquatting Defense for AI Coding Agents**

A Project by [**SILICON VALLEY GLOBAL PH INC**](https://svg.ph/)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![npm version](https://img.shields.io/npm/v/@siliconvalleyglobal/slopguard-red.svg)](https://www.npmjs.com/package/@siliconvalleyglobal/slopguard)
[![Node version](https://img.shields.io/node/v/@siliconvalleyglobal/slopguard.svg)](https://nodejs.org/)
[![Tests Passing](https://img.shields.io/badge/tests-passing-brightgreen.svg)](https://github.com/alifkhanwork/slopguard)

**`@siliconvalleyglobal/slopguard`** provides an install-time defense layer against **slopsquatting** — a novel supply-chain attack vector where attackers register the exact hallucinated package names that AI coding agents (Claude Code, Cursor, Cline, Codex, Windsurf) tend to invent.

---

## ⚙️ How It Works (Execution Model)

`@siliconvalleyglobal/slopguard` operates with a **dual execution architecture**:

1. **Standalone Native TypeScript Engine (Default)**:
   - Runs out-of-the-box in Node.js environments with **zero external system dependencies**.
   - Queries live npm registry metadata APIs for package creation age, release frequency, and unestablished novelty warnings.
   - Evaluates LLM name conflation heuristics (detecting when an agent blends two popular packages together).

2. **Python Core CLI Bridge (Optional Deep Mode)**:
   - If the Python `slopguard` core package is installed on the host system (`pip install slopguard`), this package automatically delegates to the Python CLI (`slopguard check <name> --json`) to run PyPI cross-registry matching and OSV threat intelligence feed synchronization (`api.osv.dev`).

---

## ⚠️ The Problem: What is Slopsquatting?

AI coding assistants frequently invent package names that sound plausible but do not exist — typically by blending two real packages together (e.g. hallucinating `react-codeshift` by merging `jscodeshift` and `react-codemod`).

1. **Predictable & Repeatable**: These AI hallucinations are highly deterministic across model runs. Attackers log common LLM prompt outputs and pre-register hallucinated package names on public registries like npm and PyPI.
2. **Traditional Typosquat Scanners Fail**: Existing scanners check single-character edit distances against existing names (e.g. `reqeusts` vs `requests`). Hallucinated names are valid compound English phrases with no single-name typo collision.
3. **Silent Code Execution**: When a developer or AI agent executes `npm install <hallucinated-pkg>`, an install command that would have returned a 404 error last week now silently succeeds — executing malicious post-install hooks inside your environment or CI pipeline.

---

## 📊 Detection Signals

| Signal | What it Catches | Confidence Level | Implemented in v0.1.0 |
| :--- | :--- | :--- | :--- |
| **Name Conflation** | Hallucinated blends of two real popular package names | Medium | ✅ Native TS + Python |
| **Package Novelty (<14 days)** | Freshly registered package name with minimal history | High | ✅ Native TS + Python |
| **Low Release History** | Packages published with fewer than 3 total releases | Medium | ✅ Native TS + Python |
| **Cross-Registry Mismatch** | Name confusion between PyPI and npm ecosystems | High | 🐍 Python Core Bridge |
| **Threat Feed Sync (OSV)** | Matches known malicious package campaigns in OSV DB | Highest | 🐍 Python Core Bridge |

---

## 📦 Installation

```bash
npm install @siliconvalleyglobal/slopguard
```

---

## 🚀 Quickstart

### 1. `agent-permit` Integration

Integrate SlopGuard directly into `agent-permit` pre-approval hooks:

```typescript
import { checkPackage } from "@siliconvalleyglobal/slopguard/integrations/agent-permit";

// Verify a package before allowing an agent to execute npm install
const result = await checkPackage("react-codeshift", "npm");

console.log(`Risk Score: ${result.riskScore} / 100.0`);

if (result.riskScore >= 30.0) {
  console.error(`[SlopGuard] Suspicious package detected: ${result.packageName}`);
  for (const signal of result.signals) {
    console.log(`  • ${signal.name}: ${signal.description}`);
  }
}
```

### 2. CLI Usage

```bash
# Scan a package name before installation
npx slopguard check react-codeshift --ecosystem npm
```

---

## ⚙️ Configuration (`.slopguard.json`)

Configure SlopGuard globally in `~/.slopguard/config.json` or per project in `.slopguard.json`:

```json
{
  "interceptor_mode": "block",
  "warn_threshold": 30.0,
  "block_threshold": 75.0,
  "enabled_registries": ["npm", "pypi"],
  "allowlist": [
    "my-internal-private-package"
  ],
  "intel_sync_enabled": true
}
```

---

## 🗺️ Roadmap

- [x] Native TypeScript detection engine with live npm registry API metadata inspection
- [x] Seamless bridge to Python `slopguard` core package when available
- [x] First-party `agent-permit` inline check integration
- [ ] Native TypeScript PyPI metadata registry fetcher
- [ ] Lockfile scanner for `package-lock.json` and `yarn.lock`

---

## 📄 License

[MIT](./LICENSE) © SILICON VALLEY GLOBAL PH INC
