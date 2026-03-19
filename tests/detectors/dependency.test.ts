import { Project } from "ts-morph";
import { describe, expect, it } from "vitest";
import { DEFAULT_CONFIG } from "../../src/config.js";
import { dependencyDetector } from "../../src/detectors/dependency.js";
import type { PackageJsonData, ScanContext } from "../../src/types.js";

function makeCtx(pkg: Partial<PackageJsonData>): ScanContext {
	const project = new Project({ useInMemoryFileSystem: true });
	return {
		skillPath: "/test-skill",
		files: project.getSourceFiles(),
		skillMd: null,
		packageJson: {
			name: "test",
			version: "1.0.0",
			dependencies: {},
			devDependencies: {},
			scripts: {},
			raw: {},
			...pkg,
		},
		config: DEFAULT_CONFIG,
	};
}

describe("dependency detector", () => {
	it("detects known malicious packages", async () => {
		const ctx = makeCtx({ dependencies: { "event-stream": "^3.3.4" } });
		const findings = await dependencyDetector.run(ctx);
		expect(findings.some((f) => f.severity === "critical")).toBe(true);
	});

	it("detects typosquatted packages", async () => {
		const ctx = makeCtx({ dependencies: { lodasch: "^4.0.0" } });
		const findings = await dependencyDetector.run(ctx);
		expect(findings.some((f) => f.title.includes("typosquatted"))).toBe(true);
	});

	it("detects postinstall scripts", async () => {
		const ctx = makeCtx({ scripts: { postinstall: "node setup.js" } });
		const findings = await dependencyDetector.run(ctx);
		expect(findings.some((f) => f.title.includes("Lifecycle"))).toBe(true);
	});

	it("passes for safe dependencies", async () => {
		const ctx = makeCtx({ dependencies: { lodash: "^4.17.21", express: "^4.18.0" } });
		const findings = await dependencyDetector.run(ctx);
		expect(findings).toHaveLength(0);
	});

	it("returns empty for missing package.json", async () => {
		const project = new Project({ useInMemoryFileSystem: true });
		const ctx: ScanContext = {
			skillPath: "/test",
			files: project.getSourceFiles(),
			skillMd: null,
			packageJson: null,
			config: DEFAULT_CONFIG,
		};
		const findings = await dependencyDetector.run(ctx);
		expect(findings).toHaveLength(0);
	});
});
