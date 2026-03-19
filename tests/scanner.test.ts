import { mkdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { DEFAULT_CONFIG } from "../src/config.js";
import { calculateRiskScore, getRiskLevel, scan } from "../src/scanner.js";
import type { Finding } from "../src/types.js";

describe("calculateRiskScore", () => {
	it("returns 0 for no findings", () => {
		expect(calculateRiskScore([])).toBe(0);
	});

	it("calculates score from severity weights", () => {
		const findings: Finding[] = [
			{
				detectorId: "test",
				severity: "critical",
				title: "Test",
				description: "Test finding",
				file: "test.ts",
				line: 1,
				code: "test()",
				fix: "Fix it",
			},
		];
		expect(calculateRiskScore(findings)).toBe(10);
	});

	it("caps score at 10", () => {
		const findings: Finding[] = Array.from({ length: 5 }, () => ({
			detectorId: "test",
			severity: "critical" as const,
			title: "Test",
			description: "Test finding",
			file: "test.ts",
			line: 1,
			code: "test()",
			fix: "Fix it",
		}));
		expect(calculateRiskScore(findings)).toBe(10);
	});
});

describe("getRiskLevel", () => {
	it("returns safe for low scores", () => {
		expect(getRiskLevel(0)).toBe("safe");
		expect(getRiskLevel(2.0)).toBe("safe");
	});

	it("returns caution for moderate scores", () => {
		expect(getRiskLevel(2.1)).toBe("caution");
		expect(getRiskLevel(4.0)).toBe("caution");
	});

	it("returns warning for high scores", () => {
		expect(getRiskLevel(4.1)).toBe("warning");
		expect(getRiskLevel(7.0)).toBe("warning");
	});

	it("returns danger for critical scores", () => {
		expect(getRiskLevel(7.1)).toBe("danger");
		expect(getRiskLevel(10)).toBe("danger");
	});
});

describe("scan excludeDirs", () => {
	const tmpDir = path.join(import.meta.dirname, ".tmp-exclude-test");

	beforeEach(async () => {
		await mkdir(path.join(tmpDir, "src"), { recursive: true });
		await mkdir(path.join(tmpDir, "dist"), { recursive: true });
		await mkdir(path.join(tmpDir, "custom"), { recursive: true });
		await writeFile(path.join(tmpDir, "src", "index.ts"), "const x = 1;");
		await writeFile(path.join(tmpDir, "dist", "bundle.js"), "const y = 2;");
		await writeFile(path.join(tmpDir, "custom", "file.ts"), "const z = 3;");
	});

	afterEach(async () => {
		await rm(tmpDir, { recursive: true, force: true });
	});

	it("excludes dist/ by default", async () => {
		const result = await scan(tmpDir, DEFAULT_CONFIG);
		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.value.scannedFiles).toBe(2); // src/index.ts + custom/file.ts, but not dist/
	});

	it("includes dist/ when excludeDirs is empty", async () => {
		const result = await scan(tmpDir, { ...DEFAULT_CONFIG, excludeDirs: [] });
		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.value.scannedFiles).toBe(3); // src + dist + custom
	});

	it("excludes custom directories", async () => {
		const result = await scan(tmpDir, {
			...DEFAULT_CONFIG,
			excludeDirs: [...DEFAULT_CONFIG.excludeDirs, "custom"],
		});
		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.value.scannedFiles).toBe(1); // only src/index.ts
	});

	it("excludes prefix-dash variants like dist-bff", async () => {
		await mkdir(path.join(tmpDir, "dist-bff"), { recursive: true });
		await writeFile(path.join(tmpDir, "dist-bff", "output.js"), "const w = 4;");
		const result = await scan(tmpDir, DEFAULT_CONFIG);
		expect(result.ok).toBe(true);
		if (!result.ok) return;
		// src/index.ts + custom/file.ts — dist/ and dist-bff/ both excluded
		expect(result.value.scannedFiles).toBe(2);
	});

	it("does not exclude dirs that merely start with excluded name", async () => {
		await mkdir(path.join(tmpDir, "distribution"), { recursive: true });
		await writeFile(path.join(tmpDir, "distribution", "main.ts"), "const v = 5;");
		const result = await scan(tmpDir, DEFAULT_CONFIG);
		expect(result.ok).toBe(true);
		if (!result.ok) return;
		// src/index.ts + custom/file.ts + distribution/main.ts — dist/ excluded but not distribution/
		expect(result.value.scannedFiles).toBe(3);
	});
});
