import chalk from "chalk";
import type { ScanResult, Severity } from "./types.js";

const SEVERITY_ICONS: Record<Severity, string> = {
	critical: chalk.red("CRITICAL"),
	high: chalk.redBright("HIGH    "),
	medium: chalk.yellow("MEDIUM  "),
	low: chalk.blue("LOW     "),
	info: chalk.gray("INFO    "),
};

const RISK_DISPLAY: Record<string, string> = {
	safe: chalk.green("SAFE — Likely safe to install"),
	caution: chalk.yellow("CAUTION — Review findings before installing"),
	warning: chalk.hex("#FFA500")("WARNING — Significant risks detected"),
	danger: chalk.red("DANGER — Do NOT install"),
};

/** Format a scan result as a colored terminal report */
export function formatTerminal(result: ScanResult): string {
	const lines: string[] = [];
	const version = "0.1.0";

	lines.push("");
	lines.push(chalk.bold(`  SkillScan v${version} — Analyzing "${result.skillName}"`));
	lines.push("");

	// Risk score box
	const scoreStr = result.riskScore.toFixed(1);
	const riskDisplay = RISK_DISPLAY[result.riskLevel];
	lines.push(chalk.bold(`  Risk Score: ${scoreStr} / 10  ${riskDisplay}`));
	lines.push("");

	// Findings grouped by detector
	for (const detectorResult of result.detectorResults) {
		if (detectorResult.passed) {
			lines.push(chalk.green(`  PASS  ${detectorResult.detectorName} — No issues detected`));
		} else {
			for (const finding of detectorResult.findings) {
				lines.push(
					`  ${SEVERITY_ICONS[finding.severity]}  ${finding.title} (${finding.detectorId})`,
				);
				lines.push(chalk.gray(`     ${finding.file}:${finding.line} — ${finding.description}`));
				lines.push(chalk.gray(`     > ${finding.code}`));
				lines.push(chalk.cyan(`     Fix: ${finding.fix}`));
				lines.push("");
			}
		}
	}

	// Summary
	const counts = countBySeverity(result);
	const summaryParts: string[] = [];
	if (counts.critical > 0) summaryParts.push(`${counts.critical} critical`);
	if (counts.high > 0) summaryParts.push(`${counts.high} high`);
	if (counts.medium > 0) summaryParts.push(`${counts.medium} medium`);
	if (counts.low > 0) summaryParts.push(`${counts.low} low`);

	const durationStr = (result.duration / 1000).toFixed(1);
	lines.push("");
	lines.push(
		`  Summary: ${summaryParts.length > 0 ? summaryParts.join(", ") : "No issues"} | ${result.detectorResults.length} detectors ran in ${durationStr}s`,
	);
	lines.push("");

	return lines.join("\n");
}

/** Format a scan result as JSON */
export function formatJson(result: ScanResult): string {
	return JSON.stringify(result, null, 2);
}

/** Format a scan result as a quiet one-liner (for CI/CD) */
export function formatQuiet(result: ScanResult): string {
	return `${result.riskScore.toFixed(1)}`;
}

function countBySeverity(result: ScanResult): Record<Severity, number> {
	const counts: Record<Severity, number> = {
		critical: 0,
		high: 0,
		medium: 0,
		low: 0,
		info: 0,
	};
	for (const finding of result.findings) {
		counts[finding.severity]++;
	}
	return counts;
}
