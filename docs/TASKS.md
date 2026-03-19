# SkillScan — Implementation Tasks

Phased task list. Execute in order. Each phase should be fully working before starting the next.

## Phase 1: Project Skeleton (Day 1)

- [ ] Initialize project with `pnpm init`
- [ ] Configure TypeScript (`tsconfig.json` — strict: true, ES2022 target, NodeNext module)
- [ ] Configure tsup (`tsup.config.ts` — single entry, CLI banner with shebang)
- [ ] Configure Vitest (`vitest.config.ts`)
- [ ] Configure Biome (`biome.json` — format + lint)
- [ ] Create `src/types.ts` with core interfaces:
  ```typescript
  interface ScanContext {
    skillPath: string;
    files: SourceFile[];
    skillMd: SkillMdData | null;
    packageJson: PackageJsonData | null;
    config: ScanConfig;
  }

  interface Finding {
    detectorId: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    title: string;
    description: string;
    file: string;
    line: number;
    code: string;  // the offending code snippet
    fix: string;   // suggested remediation
  }

  interface ScanResult {
    skillName: string;
    skillPath: string;
    riskScore: number;         // 0-10
    riskLevel: 'safe' | 'caution' | 'warning' | 'danger';
    findings: Finding[];
    detectorResults: DetectorResult[];
    duration: number;          // ms
    scannedFiles: number;
    timestamp: string;
  }

  interface Detector {
    id: string;
    name: string;
    description: string;
    run(ctx: ScanContext): Promise<Finding[]>;
  }

  interface DetectorResult {
    detectorId: string;
    detectorName: string;
    passed: boolean;
    findings: Finding[];
    duration: number;
  }
  ```
- [ ] Create `src/cli.ts` with Commander.js — parse args, call scanner, format output
- [ ] Create `src/scanner.ts` — orchestrates: load files → run detectors → calculate score → return result
- [ ] Create `src/report.ts` — terminal formatter with chalk + ora
- [ ] Create `src/config.ts` — cosmiconfig loader for skillscan.config.*
- [ ] Create `src/detectors/index.ts` — detector registry (array of Detector)
- [ ] Add `bin` field to package.json pointing to dist/cli.js
- [ ] Verify: `pnpm build && node dist/cli.js --help` works
- [ ] Verify: `pnpm test` runs (even with no tests yet)
- [ ] Verify: `pnpm lint` passes

## Phase 2: Parsers (Day 2)

- [ ] Create `src/parsers/source-code.ts`:
  - Load .ts/.js/.mjs/.cjs files with ts-morph
  - Extract AST: function calls, imports, string literals, assignments
  - Provide helper: findCallExpressions(name), findImports(module), findStringLiterals()
- [ ] Create `src/parsers/skill-md.ts`:
  - Parse SKILL.md YAML frontmatter (use gray-matter)
  - Extract: name, description, permissions, triggers, dependencies
  - Extract instruction text (post-frontmatter markdown)
- [ ] Create `src/parsers/package-json.ts`:
  - Parse package.json
  - Extract: dependencies, devDependencies, scripts (especially postinstall), openclaw config
- [ ] Create test fixtures:
  - `tests/fixtures/safe-skill/` — a clean, harmless skill
  - `tests/fixtures/malicious-skill/` — a skill with multiple security issues
  - `tests/fixtures/suspicious-skill/` — edge cases, some suspicious patterns
- [ ] Write parser tests using fixtures

## Phase 3: Core Detectors — Critical (Days 3-5)

Build the 4 most impactful detectors first.

### D01: Network Exfiltration
- [ ] Detect fetch(), axios, http.request(), https.request(), XMLHttpRequest
- [ ] Detect got, node-fetch, undici imports
- [ ] Extract target URLs from call arguments
- [ ] Check URLs against default allowlist (api.openai.com, api.anthropic.com, etc.)
- [ ] Flag when request body contains variables named: context, memory, conversation, history, messages, prompt, system
- [ ] Severity: CRITICAL if data exfil pattern, HIGH if unknown outbound
- [ ] Write tests with fixtures (safe API call vs. exfiltration)

### D02: Filesystem Access
- [ ] Detect fs.readFile*, fs.writeFile*, fs.readdir, fs.access, fs.open
- [ ] Maintain sensitive path list: ~/.ssh, ~/.aws, ~/.config/gcloud, ~/.gnupg, /etc/shadow, /etc/passwd, browser profiles (~/.config/google-chrome, ~/Library/Application Support/Google/Chrome)
- [ ] Detect path.join(os.homedir(), '.ssh') and similar constructions
- [ ] Flag glob patterns: /**, /*, ../../
- [ ] Severity: CRITICAL for credential paths, HIGH for broad access
- [ ] Write tests

### D03: Shell Execution
- [ ] Detect: child_process.exec, execSync, spawn, spawnSync, fork
- [ ] Detect: shell: true option in spawn/exec
- [ ] Maintain dangerous command blocklist: rm -rf, curl|bash, wget|sh, chmod 777, mkfs, dd
- [ ] Detect command strings built from variables (command injection)
- [ ] Severity: CRITICAL for dangerous commands, HIGH for any shell exec
- [ ] Write tests

### D04: Prompt Injection
- [ ] Scan SKILL.md instruction text for injection patterns:
  - "ignore previous", "ignore all previous", "disregard", "override"
  - "you are now", "new instructions", "system:", "assistant:"
  - Hidden text: HTML comments, zero-width unicode chars (\u200B, \uFEFF, etc.)
  - Base64 encoded blocks in instructions
- [ ] Scan string literals in code for same patterns
- [ ] Detect dynamic prompt construction: template literals with external variables
- [ ] Severity: CRITICAL for clear injection, MEDIUM for suspicious
- [ ] Write tests

## Phase 4: Remaining Detectors (Days 6-8)

### D05: Credential Exposure
- [ ] Regex patterns for known API key formats (AWS AKIA, GitHub ghp_, Slack xoxb-, etc.)
- [ ] Detect hardcoded strings that look like secrets (high entropy + key-like patterns)
- [ ] Detect process.env access for sensitive variable names
- [ ] Write tests

### D06: Code Obfuscation
- [ ] Detect eval(), new Function(), setTimeout/setInterval with string arg
- [ ] Detect Buffer.from() with base64 → toString() → eval chain
- [ ] Detect String.fromCharCode() building strings
- [ ] Detect heavily minified code (very long lines, single-char variables in non-build files)
- [ ] Write tests

### D07: Dependency Risk
- [ ] Parse package.json dependencies
- [ ] Check against curated blocklist of known malicious packages
- [ ] Simple typosquatting check: Levenshtein distance to top-1000 npm packages
- [ ] Flag postinstall/preinstall scripts in dependencies
- [ ] Write tests

### D08: Permission Scope
- [ ] Parse SKILL.md frontmatter permissions (if declared)
- [ ] Compare declared permissions against actual code usage from other detectors
- [ ] Flag skills using fs/net/shell without declaring those permissions
- [ ] Flag skills declaring permissions they don't use (over-privileged)
- [ ] Write tests

## Phase 5: Output & Polish (Days 9-10)

- [ ] Terminal output: colored, structured, with risk score box (see PRD §5.4)
- [ ] JSON output: `--format json` → structured ScanResult as JSON
- [ ] HTML output: `--format html` → self-contained HTML report file
- [ ] Quiet mode: `--quiet` → just exit code + risk score number
- [ ] Verbose mode: `--verbose` → show code context around each finding
- [ ] Config file support: skillscan.config.ts with allowlists, ignored detectors, custom thresholds
- [ ] Exit codes: 0 = safe (score < 4), 1 = warnings (score 4-7), 2 = danger (score > 7)
- [ ] Progress indicator with ora spinner per detector
- [ ] Comprehensive error handling: missing files, invalid paths, permission errors

## Phase 6: Distribution & Docs (Days 11-12)

- [ ] README.md with:
  - Hero banner / logo
  - One-line install: `npx skillscan ./my-skill`
  - Feature list with examples
  - Detector documentation table
  - Configuration guide
  - Contributing guide
  - Risk score explanation
- [ ] GitHub Action workflow (`.github/workflows/skillscan.yml`) for CI scanning
- [ ] Publish to npm as `skillscan`
- [ ] Add `npx` support (ensure bin field works correctly)
- [ ] LICENSE file (Apache 2.0)
- [ ] CONTRIBUTING.md
- [ ] GitHub issue templates (bug report, feature request, new detector)

## Phase 7: Real-World Validation (Days 13-14)

- [ ] Download 10 popular OpenClaw skills from ClawHub and scan them
- [ ] Download 5 known-suspicious skills and verify detection
- [ ] Document false positive rate and adjust thresholds
- [ ] Create a `reports/` directory with example scan results
- [ ] Write a blog post / tweet thread showing real findings
- [ ] Submit to relevant security communities (Hacker News, Reddit r/netsec)

## Implementation Notes

- Start each detector with the simplest possible implementation, then iterate
- Always write the test BEFORE the detector (TDD approach helps define expected behavior)
- Each detector should be completable in 2-4 hours
- Run `pnpm typecheck && pnpm test && pnpm lint` after each detector is done
- Commit after each completed task with descriptive message