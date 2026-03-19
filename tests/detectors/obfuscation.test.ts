import { Project } from "ts-morph";
import { describe, expect, it } from "vitest";
import { DEFAULT_CONFIG } from "../../src/config.js";
import { obfuscationDetector } from "../../src/detectors/obfuscation.js";
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

describe("obfuscation detector", () => {
	it("detects eval()", async () => {
		const ctx = makeCtx('eval("console.log(1)");');
		const findings = await obfuscationDetector.run(ctx);
		expect(findings.some((f) => f.title.includes("eval()"))).toBe(true);
	});

	it("detects new Function()", async () => {
		const ctx = makeCtx('const fn = new Function("return 1");');
		const findings = await obfuscationDetector.run(ctx);
		expect(findings.some((f) => f.title.includes("new Function()"))).toBe(true);
	});

	it("detects setTimeout with string argument", async () => {
		const ctx = makeCtx("setTimeout(\"console.log('hi')\", 1000);");
		const findings = await obfuscationDetector.run(ctx);
		expect(findings.some((f) => f.title.includes("Timer"))).toBe(true);
	});

	it("detects Buffer.from with base64", async () => {
		const ctx = makeCtx('Buffer.from("aGVsbG8=", "base64");');
		const findings = await obfuscationDetector.run(ctx);
		expect(findings.some((f) => f.title.includes("Base64"))).toBe(true);
	});

	it("detects String.fromCharCode", async () => {
		const ctx = makeCtx("String.fromCharCode(72, 101, 108, 108, 111);");
		const findings = await obfuscationDetector.run(ctx);
		expect(findings.some((f) => f.title.includes("fromCharCode"))).toBe(true);
	});

	it("passes for normal code", async () => {
		const ctx = makeCtx("const sum = (a: number, b: number) => a + b;");
		const findings = await obfuscationDetector.run(ctx);
		expect(findings).toHaveLength(0);
	});
});
