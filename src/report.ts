import chalk from "chalk";
import type { Finding, ScanResult, Severity } from "./types.js";

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
export function formatTerminal(result: ScanResult, verbose = false): string {
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
				if (verbose) {
					lines.push(chalk.gray(`     > ${finding.code}`));
				}
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

/** Format a scan result as a self-contained HTML report */
export function formatHtml(result: ScanResult): string {
	const severityColor: Record<Severity, string> = {
		critical: "#dc2626",
		high: "#ef4444",
		medium: "#f59e0b",
		low: "#3b82f6",
		info: "#6b7280",
	};

	const riskColor: Record<string, string> = {
		safe: "#16a34a",
		caution: "#f59e0b",
		warning: "#f97316",
		danger: "#dc2626",
	};

	const findingsHtml = result.detectorResults
		.map((dr) => {
			if (dr.passed) {
				return `<div class="detector pass"><span class="badge safe">PASS</span> ${escapeHtml(dr.detectorName)} — No issues detected</div>`;
			}
			return dr.findings
				.map(
					(f) => `
				<div class="finding" style="border-left: 4px solid ${severityColor[f.severity]}">
					<div class="finding-header">
						<span class="badge" style="background:${severityColor[f.severity]}">${f.severity.toUpperCase()}</span>
						<strong>${escapeHtml(f.title)}</strong>
						<span class="detector-id">(${escapeHtml(f.detectorId)})</span>
					</div>
					<div class="finding-location">${escapeHtml(f.file)}:${f.line}</div>
					<div class="finding-desc">${escapeHtml(f.description)}</div>
					<pre class="finding-code">${escapeHtml(f.code)}</pre>
					<div class="finding-fix">Fix: ${escapeHtml(f.fix)}</div>
				</div>`,
				)
				.join("\n");
		})
		.join("\n");

	const counts = countBySeverity(result);
	const durationStr = (result.duration / 1000).toFixed(1);

	return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SkillScan Report — ${escapeHtml(result.skillName)}</title>
<style>
	* { margin: 0; padding: 0; box-sizing: border-box; }
	body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; padding: 2rem; max-width: 900px; margin: 0 auto; }
	h1 { font-size: 1.5rem; margin-bottom: 1rem; }
	.score-box { background: #1e293b; border-radius: 12px; padding: 1.5rem; margin-bottom: 2rem; text-align: center; }
	.score { font-size: 3rem; font-weight: bold; color: ${riskColor[result.riskLevel]}; }
	.risk-level { font-size: 1.2rem; margin-top: 0.5rem; color: ${riskColor[result.riskLevel]}; }
	.meta { color: #94a3b8; font-size: 0.9rem; margin-top: 0.5rem; }
	.finding { background: #1e293b; border-radius: 8px; padding: 1rem; margin-bottom: 1rem; }
	.finding-header { display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.5rem; }
	.badge { color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; }
	.badge.safe { background: #16a34a; }
	.detector-id { color: #64748b; font-size: 0.85rem; }
	.finding-location { color: #94a3b8; font-size: 0.85rem; margin-bottom: 0.25rem; }
	.finding-desc { margin-bottom: 0.5rem; }
	.finding-code { background: #0f172a; padding: 0.75rem; border-radius: 4px; overflow-x: auto; font-size: 0.85rem; margin-bottom: 0.5rem; }
	.finding-fix { color: #22d3ee; font-size: 0.9rem; }
	.detector.pass { color: #16a34a; padding: 0.5rem 0; }
	.summary { background: #1e293b; border-radius: 8px; padding: 1rem; margin-top: 2rem; color: #94a3b8; }
	footer { margin-top: 2rem; text-align: center; color: #475569; font-size: 0.8rem; }
</style>
</head>
<body>
<h1>SkillScan Report — ${escapeHtml(result.skillName)}</h1>
<div class="score-box">
	<div class="score">${result.riskScore.toFixed(1)} / 10</div>
	<div class="risk-level">${result.riskLevel.toUpperCase()}</div>
	<div class="meta">${result.scannedFiles} files scanned in ${durationStr}s | ${result.timestamp}</div>
</div>
${findingsHtml}
<div class="summary">
	${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low |
	${result.detectorResults.length} detectors ran in ${durationStr}s
</div>
<footer>Generated by SkillScan v0.1.0</footer>
</body>
</html>`;
}

function escapeHtml(text: string): string {
	return text
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;")
		.replace(/"/g, "&quot;");
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
