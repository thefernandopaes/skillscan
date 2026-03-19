import path from "node:path";
import { Command } from "commander";
import { loadConfig } from "./config.js";
import { formatJson, formatQuiet, formatTerminal } from "./report.js";
import { scan } from "./scanner.js";
import type { Severity } from "./types.js";

const program = new Command();

program
	.name("skillscan")
	.description(
		"Security scanner for AI agent skills/plugins. Detects prompt injection, data exfiltration, excessive permissions, and supply chain attacks.",
	)
	.version("0.1.0")
	.argument("<path>", "Path to skill directory or SKILL.md file")
	.option("-f, --format <format>", "Output format: terminal, json, html", "terminal")
	.option("-o, --output <file>", "Write report to file instead of stdout")
	.option(
		"-s, --severity <level>",
		"Minimum severity to report: critical, high, medium, low, info",
		"low",
	)
	.option("--no-color", "Disable colored output")
	.option("--config <path>", "Path to config file")
	.option("--ignore <detectors>", "Comma-separated detector IDs to skip")
	.option("-q, --quiet", "Only output risk score (for CI/CD)")
	.option("-v, --verbose", "Show detailed analysis for each finding")
	.action(async (skillPath: string, options: Record<string, unknown>) => {
		const resolvedPath = path.resolve(skillPath);

		const configResult = await loadConfig({
			format: options.format as "terminal" | "json" | "html",
			output: (options.output as string) ?? null,
			severity: options.severity as Severity,
			ignore: options.ignore ? (options.ignore as string).split(",").map((s) => s.trim()) : [],
			quiet: Boolean(options.quiet),
			verbose: Boolean(options.verbose),
		});

		if (!configResult.ok) {
			console.error(`Error loading config: ${configResult.error.message}`);
			process.exit(1);
		}

		const config = configResult.value;
		const result = await scan(resolvedPath, config);

		if (!result.ok) {
			console.error(`Scan failed: ${result.error.message}`);
			process.exit(1);
		}

		const scanResult = result.value;

		// Format output
		let output: string;
		if (config.quiet) {
			output = formatQuiet(scanResult);
		} else if (config.format === "json") {
			output = formatJson(scanResult);
		} else {
			output = formatTerminal(scanResult);
		}

		console.log(output);

		// Exit codes: 0 = safe, 1 = warnings, 2 = danger
		if (scanResult.riskScore > 7) {
			process.exit(2);
		} else if (scanResult.riskScore > 4) {
			process.exit(1);
		}
	});

program.parse();
