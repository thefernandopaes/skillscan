import { findCallExpressionsMatching, findImports } from "../parsers/source-code.js";
import type { Detector, Finding, ScanContext } from "../types.js";
import { toRelativePath } from "../utils.js";

const NETWORK_FUNCTIONS = ["fetch", "request", "get", "post", "put", "patch", "delete", "axios"];

const HTTP_MODULE_IMPORTS = [
	"node-fetch",
	"axios",
	"got",
	"undici",
	"http",
	"https",
	"node:http",
	"node:https",
	"superagent",
];

const CONTEXT_VARIABLE_NAMES = [
	"context",
	"memory",
	"conversation",
	"history",
	"messages",
	"prompt",
	"system",
	"systemPrompt",
	"chatHistory",
	"userMessage",
];

/** Detect outbound network requests that may exfiltrate data */
export const networkExfilDetector: Detector = {
	id: "network-exfil",
	name: "Network Exfiltration",
	description: "Detects outbound HTTP requests to unknown domains that may exfiltrate data",

	async run(ctx: ScanContext): Promise<Finding[]> {
		const findings: Finding[] = [];
		const allowlist = new Set(ctx.config.allowlistedDomains);

		// Check for suspicious HTTP module imports
		for (const moduleName of HTTP_MODULE_IMPORTS) {
			const imports = findImports(ctx.files, moduleName);
			for (const imp of imports) {
				const filePath = toRelativePath(imp.sourceFile.getFilePath(), ctx.skillPath);
				findings.push({
					detectorId: "network-exfil",
					severity: "high",
					title: "HTTP module imported",
					description: `Imports "${imp.moduleSpecifier}" which enables outbound network requests`,
					file: filePath,
					line: imp.line,
					code: imp.sourceFile.getFullText().split("\n")[imp.line - 1]?.trim() ?? "",
					fix: `Verify that the use of "${imp.moduleSpecifier}" is necessary and all requests go to trusted endpoints`,
				});
			}
		}

		// Find network call expressions
		const calls = findCallExpressionsMatching(ctx.files, NETWORK_FUNCTIONS);

		for (const call of calls) {
			const filePath = toRelativePath(call.sourceFile.getFilePath(), ctx.skillPath);
			const firstArg = call.arguments[0] ?? "";
			const allArgs = call.arguments.join(", ");

			// Check if URL is in allowlist
			const urlMatch = firstArg.match(/["'`](https?:\/\/[^"'`]+)["'`]/);
			if (urlMatch) {
				try {
					const url = new URL(urlMatch[1]);
					if (allowlist.has(url.hostname)) continue;
				} catch {
					// Invalid URL, flag it
				}
			}

			// Check if request body contains context/sensitive variables
			const hasContextData = CONTEXT_VARIABLE_NAMES.some((varName) =>
				allArgs.toLowerCase().includes(varName.toLowerCase()),
			);

			if (hasContextData) {
				findings.push({
					detectorId: "network-exfil",
					severity: "critical",
					title: "Data exfiltration detected",
					description: "Sends conversation context or sensitive data to an external endpoint",
					file: filePath,
					line: call.line,
					code: call.fullText.slice(0, 120),
					fix: "Remove outbound request that sends context data, or use an allowlisted API endpoint",
				});
			} else {
				findings.push({
					detectorId: "network-exfil",
					severity: "high",
					title: "Outbound request to unknown domain",
					description: `Makes an HTTP request to a non-allowlisted endpoint`,
					file: filePath,
					line: call.line,
					code: call.fullText.slice(0, 120),
					fix: "Verify the target URL is trusted, or add the domain to the allowlist in your config",
				});
			}
		}

		return findings;
	},
};
