import { Project } from "ts-morph";
import { describe, expect, it } from "vitest";
import { DEFAULT_CONFIG } from "../../src/config.js";
import { fsAccessDetector } from "../../src/detectors/fs-access.js";
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

describe("fs-access detector", () => {
	it("detects SSH key access", async () => {
		const ctx = makeCtx('import fs from "fs";\nfs.readFileSync("/home/user/.ssh/id_rsa");');
		const findings = await fsAccessDetector.run(ctx);
		expect(findings.some((f) => f.severity === "critical")).toBe(true);
	});

	it("detects AWS credential access", async () => {
		const ctx = makeCtx('import fs from "fs";\nfs.readFileSync("/home/user/.aws/credentials");');
		const findings = await fsAccessDetector.run(ctx);
		expect(findings.some((f) => f.severity === "critical")).toBe(true);
	});

	it("detects /etc/passwd access", async () => {
		const ctx = makeCtx('import fs from "fs";\nfs.readFileSync("/etc/passwd");');
		const findings = await fsAccessDetector.run(ctx);
		expect(findings.some((f) => f.severity === "critical")).toBe(true);
	});

	it("detects path traversal", async () => {
		const ctx = makeCtx('import fs from "fs";\nfs.readFileSync("../../../../etc/passwd");');
		const findings = await fsAccessDetector.run(ctx);
		expect(findings.some((f) => f.title === "Path traversal detected")).toBe(true);
	});

	it("detects broad glob patterns", async () => {
		const ctx = makeCtx('import fs from "fs";\nfs.readdirSync("/**");');
		const findings = await fsAccessDetector.run(ctx);
		expect(findings.some((f) => f.title === "Overly broad filesystem access")).toBe(true);
	});

	it("passes for safe file operations", async () => {
		const ctx = makeCtx('import fs from "fs";\nfs.readFileSync("./config.json", "utf-8");');
		const findings = await fsAccessDetector.run(ctx);
		expect(findings).toHaveLength(0);
	});
});
