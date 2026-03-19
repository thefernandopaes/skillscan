import { Project } from "ts-morph";
import { describe, expect, it } from "vitest";
import { DEFAULT_CONFIG } from "../../src/config.js";
import { permissionScopeDetector } from "../../src/detectors/permission-scope.js";
import type { ScanContext } from "../../src/types.js";

function makeCtx(code: string, permissions: string[]): ScanContext {
	const project = new Project({ useInMemoryFileSystem: true });
	project.createSourceFile("test.ts", code);
	return {
		skillPath: "/test-skill",
		files: project.getSourceFiles(),
		skillMd: {
			name: "test",
			description: "test",
			permissions,
			triggers: [],
			dependencies: [],
			instructions: "",
			raw: "",
		},
		packageJson: null,
		config: DEFAULT_CONFIG,
	};
}

describe("permission-scope detector", () => {
	it("detects undeclared filesystem usage", async () => {
		const ctx = makeCtx('import fs from "fs";\nfs.readFileSync("./data.json");', []);
		const findings = await permissionScopeDetector.run(ctx);
		expect(findings.some((f) => f.title === "Undeclared permission usage")).toBe(true);
	});

	it("detects undeclared shell usage", async () => {
		const ctx = makeCtx('import { execSync } from "child_process";\nexecSync("ls");', [
			"filesystem",
		]);
		const findings = await permissionScopeDetector.run(ctx);
		expect(findings.some((f) => f.description.includes("shell"))).toBe(true);
	});

	it("detects excessive permissions", async () => {
		const ctx = makeCtx("const x = 1;", ["network", "filesystem", "shell"]);
		const findings = await permissionScopeDetector.run(ctx);
		expect(findings.filter((f) => f.title === "Excessive permission declared")).toHaveLength(3);
	});

	it("passes when permissions match usage", async () => {
		const ctx = makeCtx('import fs from "fs";\nfs.readFileSync("./config.json");', ["filesystem"]);
		const findings = await permissionScopeDetector.run(ctx);
		expect(findings).toHaveLength(0);
	});

	it("handles missing SKILL.md gracefully", async () => {
		const project = new Project({ useInMemoryFileSystem: true });
		project.createSourceFile("test.ts", "const x = 1;");
		const ctx: ScanContext = {
			skillPath: "/test",
			files: project.getSourceFiles(),
			skillMd: null,
			packageJson: null,
			config: DEFAULT_CONFIG,
		};
		const findings = await permissionScopeDetector.run(ctx);
		expect(findings).toHaveLength(0);
	});
});
