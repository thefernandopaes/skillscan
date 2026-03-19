import type { SourceFile } from "ts-morph";
import { findCallExpressionsMatching, findImports } from "../parsers/source-code.js";
import type { Detector, Finding, ScanContext, Severity } from "../types.js";
import { toRelativePath } from "../utils.js";

/** Always flag when called standalone (no receiver) */
const STANDALONE_HTTP_FUNCTIONS = ["fetch"];

/** Only flag when receiver is an imported HTTP client */
const HTTP_METHOD_NAMES = ["get", "post", "put", "patch", "delete", "request"];

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

const STDLIB_HTTP_MODULES = new Set(["http", "https", "node:http", "node:https"]);

const SERVER_ONLY_SYMBOLS = new Set([
	"createServer",
	"Server",
	"IncomingMessage",
	"ServerResponse",
	"STATUS_CODES",
	"METHODS",
]);

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

/**
 * Collect identifiers that represent HTTP client imports from source files.
 * Returns a set of variable names that refer to HTTP client libraries.
 */
function collectHttpClientIdentifiers(files: SourceFile[]): Set<string> {
	const identifiers = new Set<string>();

	for (const moduleName of HTTP_MODULE_IMPORTS) {
		const imports = findImports(files, moduleName);
		for (const imp of imports) {
			if (imp.defaultImport) {
				identifiers.add(imp.defaultImport);
			}
			for (const named of imp.namedImports) {
				identifiers.add(named);
			}
		}
	}

	return identifiers;
}

/**
 * Determine severity for an HTTP module import.
 * Server-only stdlib imports (e.g. createServer from http) get INFO severity.
 */
function getImportSeverity(
	moduleSpecifier: string,
	namedImports: string[],
	defaultImport: string | null,
): { severity: Severity; title: string } {
	if (
		STDLIB_HTTP_MODULES.has(moduleSpecifier) &&
		!defaultImport &&
		namedImports.length > 0 &&
		namedImports.every((name) => SERVER_ONLY_SYMBOLS.has(name))
	) {
		return { severity: "info", title: "Standard HTTP server module imported" };
	}
	return { severity: "high", title: "HTTP module imported" };
}

/** Detect outbound network requests that may exfiltrate data */
export const networkExfilDetector: Detector = {
	id: "network-exfil",
	name: "Network Exfiltration",
	description: "Detects outbound HTTP requests to unknown domains that may exfiltrate data",

	async run(ctx: ScanContext): Promise<Finding[]> {
		const findings: Finding[] = [];
		const allowlist = new Set(ctx.config.allowlistedDomains);

		// Check for HTTP module imports
		for (const moduleName of HTTP_MODULE_IMPORTS) {
			const imports = findImports(ctx.files, moduleName);
			for (const imp of imports) {
				const filePath = toRelativePath(imp.sourceFile.getFilePath(), ctx.skillPath);
				const { severity, title } = getImportSeverity(
					imp.moduleSpecifier,
					imp.namedImports,
					imp.defaultImport,
				);
				findings.push({
					detectorId: "network-exfil",
					severity,
					title,
					description: `Imports "${imp.moduleSpecifier}" which enables outbound network requests`,
					file: filePath,
					line: imp.line,
					code: imp.sourceFile.getFullText().split("\n")[imp.line - 1]?.trim() ?? "",
					fix: `Verify that the use of "${imp.moduleSpecifier}" is necessary and all requests go to trusted endpoints`,
				});
			}
		}

		// Collect known HTTP client identifiers from imports
		const httpClients = collectHttpClientIdentifiers(ctx.files);

		// Find network call expressions
		const allNames = [...STANDALONE_HTTP_FUNCTIONS, ...HTTP_METHOD_NAMES];
		const calls = findCallExpressionsMatching(ctx.files, allNames);

		for (const call of calls) {
			const filePath = toRelativePath(call.sourceFile.getFilePath(), ctx.skillPath);
			const firstArg = call.arguments[0] ?? "";

			// Determine if this is a real HTTP call using import-aware receiver matching
			const dotIndex = call.name.lastIndexOf(".");
			if (dotIndex === -1) {
				// Standalone call: only flag if it's fetch or an imported HTTP client name
				const fnName = call.name;
				if (!STANDALONE_HTTP_FUNCTIONS.includes(fnName) && !httpClients.has(fnName)) {
					continue;
				}
			} else {
				// Method call: only flag if receiver is an imported HTTP client
				const receiver = call.name.slice(0, dotIndex);
				if (!httpClients.has(receiver)) {
					continue;
				}
			}

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

			// Check if request body contains context/sensitive variables (skip URL arg)
			const bodyArgs = call.arguments.slice(1).join(", ");
			const hasContextData = CONTEXT_VARIABLE_NAMES.some((varName) => {
				const pattern = new RegExp(`\\b${varName}\\b`, "i");
				return pattern.test(bodyArgs);
			});

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
					description: "Makes an HTTP request to a non-allowlisted endpoint",
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
