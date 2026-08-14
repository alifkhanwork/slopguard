# `@siliconvalleyglobal/slopguard` 🛡️

> **TypeScript bindings & `agent-permit` integration for SlopGuard slopsquatting defense.**

A project by [**SILICON VALLEY GLOBAL PH INC**](https://svg.ph/).

`@siliconvalleyglobal/slopguard` provides JavaScript/TypeScript bindings, CLI utilities, and `agent-permit` security integration for **SlopGuard** — protecting AI coding agents (Claude Code, Cursor, Cline, Codex, Windsurf) against **slopsquatting** supply-chain attacks.

---

## 📦 Installation

```bash
npm install @siliconvalleyglobal/slopguard
```

---

## 🚀 Usage

### 1. `agent-permit` Integration

Plugs directly into `agent-permit` as an inline package verification step:

```typescript
import { checkPackage } from "@siliconvalleyglobal/slopguard/integrations/agent-permit";

// Verify a package before allowing an agent to execute npm install
const result = await checkPackage("react-codeshift", "npm");

if (result.riskScore >= 75) {
  console.error(`[SlopGuard] Blocked suspicious package: ${result.packageName}`);
  // Reject installation action
}
```

### 2. CLI Package Checker

```bash
# Scan a package name for slopsquatting heuristics
npx slopguard check react-codeshift --ecosystem npm
```

---

## 📄 License

[MIT](./LICENSE) © SILICON VALLEY GLOBAL PH INC
