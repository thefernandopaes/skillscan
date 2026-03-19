# SkillScan

**Security scanner for AI agent skills/plugins.** Detects prompt injection, data exfiltration, excessive permissions, and supply chain attacks in OpenClaw, LangChain, and other agent frameworks.

> "Know before you install."

```
npx skillscan ./my-skill
```

## Why?

- **1,184 confirmed malicious skills** found in OpenClaw's ClawHub marketplace
- **7%+ of skills expose sensitive credentials** (Snyk research)
- **No existing tool** performs static analysis specifically for AI agent skill security

SkillScan fills this gap with 8 purpose-built security detectors that understand AI-specific threats.

## Quick Start

```bash
# Scan a skill directory
npx skillscan ./my-skill

# JSON output for CI/CD
npx skillscan ./my-skill --format json

# HTML report
npx skillscan ./my-skill --format html --output report.html

# Quiet mode (just the risk score)
npx skillscan ./my-skill --quiet
```

## What It Detects

| Detector | ID | What It Finds |
|---|---|---|
| Network Exfiltration | `network-exfil` | Outbound HTTP to unknown domains, context data being sent externally |
| Filesystem Access | `fs-access` | Reads from ~/.ssh, ~/.aws, /etc/passwd, path traversal, broad globs |
| Shell Execution | `shell-exec` | child_process usage, `rm -rf`, `curl\|bash`, command injection |
| Prompt Injection | `prompt-injection` | "Ignore previous instructions", hidden text in HTML comments, zero-width chars |
| Credential Exposure | `credential-leak` | Hardcoded AWS keys, GitHub tokens, Slack tokens, API keys |
| Code Obfuscation | `obfuscation` | eval(), new Function(), base64 decoding, String.fromCharCode |
| Dependency Risk | `dependency` | Known malicious packages, typosquatting, postinstall scripts |
| Permission Scope | `permission-scope` | Undeclared capabilities, excessive permission requests |

## Risk Score

```
0.0 - 2.0  →  SAFE      (likely safe to install)
2.1 - 4.0  →  CAUTION   (review findings before installing)
4.1 - 7.0  →  WARNING   (significant risks detected)
7.1 - 10.0 →  DANGER    (do NOT install)
```

## CLI Options

```
skillscan <path> [options]

Arguments:
  path                    Path to skill directory or SKILL.md file

Options:
  -f, --format <format>   Output format: terminal (default), json, html
  -o, --output <file>     Write report to file instead of stdout
  -s, --severity <level>  Minimum severity: critical, high, medium, low, info
  --no-color              Disable colored output
  --config <path>         Path to config file
  --ignore <detectors>    Comma-separated detector IDs to skip
  -q, --quiet             Only output risk score (for CI/CD)
  -v, --verbose           Show code context for each finding
  -V, --version           Show version
  -h, --help              Show help
```

## Configuration

Create a `skillscan.config.json` (or `.ts`, `.yaml`) in your project:

```json
{
  "severity": "medium",
  "ignore": ["permission-scope"],
  "allowlistedDomains": [
    "api.openai.com",
    "api.anthropic.com",
    "api.mycompany.com"
  ]
}
```

## CI/CD Integration

### GitHub Actions

```yaml
- name: Scan skill for security issues
  run: npx skillscan ./my-skill --quiet
```

Exit codes: `0` = safe, `1` = warnings, `2` = critical findings.

See [`.github/workflows/skillscan.yml`](.github/workflows/skillscan.yml) for a full example.

## Development

```bash
pnpm install          # Install dependencies
pnpm build            # Build with tsup
pnpm dev              # Run in dev mode
pnpm test             # Run tests
pnpm test:watch       # Watch mode
pnpm lint             # Biome check
pnpm lint:fix         # Auto-fix
pnpm typecheck        # Type check
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on adding new detectors and submitting changes.

## License

[Apache 2.0](LICENSE)
