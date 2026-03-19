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

	it("detects sensitive env variable access", async () => {
		const ctx = makeCtx("const key = process.env.API_KEY;");
		const findings = await credentialLeakDetector.run(ctx);
		expect(findings.some((f) => f.title.includes("environment variable"))).toBe(true);
	});

	it("passes for code without credentials", async () => {
		const ctx = makeCtx('const greeting = "hello world";');
		const findings = await credentialLeakDetector.run(ctx);
		expect(findings).toHaveLength(0);
	});
});
