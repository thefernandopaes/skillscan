# SkillScan

Security scanner for AI agent skills/plugins. Detects prompt injection, data exfiltration, excessive permissions, and supply chain attacks in OpenClaw, LangChain, and other agent frameworks.

## Project Overview

SkillScan is an open-source CLI tool that analyzes AI agent skills/plugins for security vulnerabilities. Think "ESLint for agent security" or "npm audit for AI skills." It targets the documented crisis of 1,184+ malicious skills found in agent marketplaces.

**Target users:** Developers building/installing AI agent skills, marketplace maintainers, security teams.

**Key value:** Run `skillscan ./my-skill` → get a security report with risk score in seconds.

## Tech Stack

- **Language:** TypeScript (strict mode)
- **Runtime:** Node.js >= 22
- **Package manager:** pnpm
- **Build:** tsup (bundle to single CLI binary)
- **Test:** Vitest
- **Lint:** Biome (format + lint)
- **AST parsing:** ts-morph (TypeScript/JavaScript analysis)
- **CLI framework:** Commander.js
- **Output:** chalk + ora (colors + spinners)
- **Config:** cosmiconfig (skillscan.config.ts/json/yaml)

## Project Structure

```
skillscan/
├── src/
│   ├── cli.ts              # CLI entry point (Commander.js)
│   ├── scanner.ts           # Main scanner orchestrator
│   ├── config.ts            # Config loading (cosmiconfig)
│   ├── report.ts            # Report generation (terminal + JSON + HTML)
│   ├── detectors/           # Each detector = one security check
│   │   ├── index.ts         # Detector registry
│   │   ├── network-exfil.ts # Outbound HTTP to unknown domains
│   │   ├── fs-access.ts     # Dangerous filesystem reads/writes
│   │   ├── shell-exec.ts    # Shell command execution
│   │   ├── prompt-injection.ts # Embedded prompt injection patterns
│   │   ├── credential-leak.ts  # API keys, tokens, secrets in code
│   │   ├── obfuscation.ts   # Obfuscated/encoded code detection
│   │   ├── dependency.ts    # Malicious/typosquatted npm dependencies
│   │   └── permission-scope.ts # Overly broad permission requests
│   ├── parsers/             # File format parsers
│   │   ├── skill-md.ts      # SKILL.md frontmatter + instructions
│   │   ├── package-json.ts  # package.json analysis
│   │   └── source-code.ts   # TS/JS AST analysis via ts-morph
│   ├── types.ts             # Shared TypeScript types/interfaces
│   └── utils.ts             # Shared utilities
├── tests/
│   ├── fixtures/            # Sample skills for testing (safe + malicious)
│   │   ├── safe-skill/
│   │   └── malicious-skill/
│   └── detectors/           # One test file per detector
├── docs/
│   ├── PRD.md               # Product Requirements Document
│   └── TASKS.md             # Phased task list
├── package.json
├── tsconfig.json
├── tsup.config.ts
├── vitest.config.ts
├── biome.json
└── README.md
```

## Commands

```bash
pnpm install          # Install dependencies
pnpm build            # Build with tsup
pnpm dev              # Run in dev mode (tsx)
pnpm test             # Run all tests with Vitest
pnpm test:watch       # Watch mode
pnpm lint             # Biome check
pnpm lint:fix         # Biome fix
pnpm typecheck        # tsc --noEmit
```

## Coding Rules

- Use ES modules (import/export), never CommonJS
- Strict TypeScript: no `any`, no `@ts-ignore`
- Every detector must implement the `Detector` interface from `src/types.ts`
- Every detector must have tests with both safe and malicious fixtures
- Use descriptive variable names. No abbreviations except well-known ones (fs, ast, etc.)
- Error messages must be actionable: tell the user WHAT is wrong and HOW to fix it
- All public functions must have JSDoc comments
- Prefer pure functions. Minimize side effects.
- Use `Result<T, E>` pattern for operations that can fail (no throwing)

## Architecture Decisions

- **Detectors are independent modules.** Each detector receives a `ScanContext` and returns `Finding[]`. They don't depend on each other. This makes it easy for contributors to add new detectors.
- **AST-based analysis, not regex.** Use ts-morph to parse code into AST. Regex is fragile and misses obfuscated patterns.
- **Severity levels:** CRITICAL (immediate danger), HIGH (likely malicious), MEDIUM (suspicious), LOW (best practice), INFO (informational).
- **Risk score:** 0-10 float. Calculated from weighted findings. >=7 = DO NOT INSTALL, 4-7 = CAUTION, <4 = LIKELY SAFE.
- **Zero dependencies at runtime if possible.** Minimize attack surface of the security tool itself.

## Important Context

- Read `@docs/PRD.md` for full product requirements and user stories
- Read `@docs/TASKS.md` for the phased implementation plan
- This project targets the OpenClaw ecosystem primarily but must be framework-agnostic
- Security tool = must be extra careful about our own code quality
- The CLI must work as a standalone `npx skillscan ./path` without global install
- Output formats: terminal (default), JSON (--json), HTML report (--html)