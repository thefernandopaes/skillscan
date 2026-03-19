# Contributing to SkillScan

Thanks for your interest in improving AI agent security! Here's how to contribute.

## Getting Started

```bash
git clone https://github.com/thefernandopaes/skillscan.git
cd skillscan
pnpm install
pnpm test
```

## Adding a New Detector

1. Create `src/detectors/your-detector.ts` implementing the `Detector` interface from `src/types.ts`
2. Register it in `src/detectors/index.ts`
3. Add test fixtures in `tests/fixtures/` (both safe and malicious examples)
4. Write tests in `tests/detectors/your-detector.test.ts`
5. Run `pnpm typecheck && pnpm test && pnpm lint` before submitting

### Detector Template

```typescript
import type { Detector, Finding, ScanContext } from "../types.js";

export const myDetector: Detector = {
  id: "my-detector",
  name: "My Detector",
  description: "What this detector checks for",

  async run(ctx: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    // Your detection logic here
    return findings;
  },
};
```

## Code Standards

- TypeScript strict mode, no `any`, no `@ts-ignore`
- ES modules only
- Biome for formatting and linting
- Every detector needs tests with safe and malicious fixtures
- Use AST analysis (ts-morph), not regex, for code analysis

## Pull Requests

- Fork the repo and create a feature branch
- Keep PRs focused on a single change
- Include tests for new functionality
- Run `pnpm typecheck && pnpm test && pnpm lint` before submitting
- Describe what your change does and why

## Reporting Issues

Use GitHub Issues with the appropriate template:
- **Bug Report**: Something isn't working as expected
- **Feature Request**: Suggest a new detector or improvement
- **New Detector**: Propose a new security check

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.
