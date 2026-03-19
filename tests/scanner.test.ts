import { describe, expect, it } from "vitest";
import { calculateRiskScore, getRiskLevel } from "../src/scanner.js";
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
