import { SyntaxKind } from "ts-morph";
import { findCallExpressions, findCallExpressionsMatching } from "../parsers/source-code.js";
import type { Detector, Finding, ScanContext } from "../types.js";
import { toRelativePath } from "../utils.js";

/** Detect obfuscated or dynamically executed code */
export const obfuscationDetector: Detector = {
	id: "obfuscation",
	name: "Code Obfuscation",
	description: "Detects eval(), Function(), encoded strings, and obfuscated code patterns",

	async run(ctx: ScanContext): Promise<Finding[]> {
		const findings: Finding[] = [];

		// Detect eval()
		const evalCalls = findCallExpressions(ctx.files, "eval");
		for (const call of evalCalls) {
			const filePath = toRelativePath(call.sourceFile.getFilePath(), ctx.skillPath);
			findings.push({
				detectorId: "obfuscation",
				severity: "high",
				title: "eval() usage detected",
				description: "Uses eval() which can execute arbitrary code and hides intent",
				file: filePath,
				line: call.line,
				code: call.fullText.slice(0, 120),
				fix: "Replace eval() with explicit code. If parsing JSON, use JSON.parse()",
			});
		}

		// Detect new Function()
		for (const file of ctx.files) {
			const filePath = toRelativePath(file.getFilePath(), ctx.skillPath);
			const newExpressions = file.getDescendantsOfKind(SyntaxKind.NewExpression);
			for (const expr of newExpressions) {
				if (expr.getExpression().getText() === "Function") {
					findings.push({
						detectorId: "obfuscation",
						severity: "high",
						title: "new Function() usage detected",
						description: "Uses new Function() constructor which is equivalent to eval()",
						file: filePath,
						line: expr.getStartLineNumber(),
						code: expr.getText().slice(0, 120),
						fix: "Replace new Function() with a regular function declaration",
					});
				}
			}
		}

		// Detect setTimeout/setInterval with string argument
		const timerCalls = findCallExpressionsMatching(ctx.files, ["setTimeout", "setInterval"]);
		for (const call of timerCalls) {
			const firstArg = call.arguments[0] ?? "";
			if (firstArg.startsWith('"') || firstArg.startsWith("'") || firstArg.startsWith("`")) {
				const filePath = toRelativePath(call.sourceFile.getFilePath(), ctx.skillPath);
				findings.push({
					detectorId: "obfuscation",
					severity: "medium",
					title: "Timer with string argument",
					description: `${call.name} called with a string argument, which is evaluated like eval()`,
					file: filePath,
					line: call.line,
					code: call.fullText.slice(0, 120),
					fix: "Pass a function reference instead of a string to setTimeout/setInterval",
				});
			}
		}

		// Detect Buffer.from with base64
		const bufferCalls = findCallExpressions(ctx.files, "from");
		for (const call of bufferCalls) {
			if (call.name.includes("Buffer") && call.arguments.some((a) => a.includes("base64"))) {
				const filePath = toRelativePath(call.sourceFile.getFilePath(), ctx.skillPath);
				findings.push({
					detectorId: "obfuscation",
					severity: "medium",
					title: "Base64 decoding detected",
					description: "Decodes base64 content which may hide malicious code",
					file: filePath,
					line: call.line,
					code: call.fullText.slice(0, 120),
					fix: "Decode and review the base64 content. Replace with explicit code",
				});
			}
		}

		// Detect String.fromCharCode
		const charCodeCalls = findCallExpressions(ctx.files, "fromCharCode");
		for (const call of charCodeCalls) {
			const filePath = toRelativePath(call.sourceFile.getFilePath(), ctx.skillPath);
			findings.push({
				detectorId: "obfuscation",
				severity: "medium",
				title: "String.fromCharCode() obfuscation",
				description: "Builds strings from character codes, a common obfuscation technique",
				file: filePath,
				line: call.line,
				code: call.fullText.slice(0, 120),
				fix: "Replace String.fromCharCode() with a plain string literal",
			});
		}

		// Detect heavily minified code (lines > 500 chars in non-build files)
		for (const file of ctx.files) {
			const filePath = toRelativePath(file.getFilePath(), ctx.skillPath);
			if (filePath.includes("dist/") || filePath.includes("build/") || filePath.includes("min.")) {
				continue;
			}
			const lines = file.getFullText().split("\n");
			const longLines = lines.filter((l) => l.trim().length > 500);
			if (longLines.length > 0) {
				findings.push({
					detectorId: "obfuscation",
					severity: "medium",
					title: "Minified or obfuscated code",
					description: `Contains ${longLines.length} line(s) exceeding 500 characters, suggesting minified/obfuscated code`,
					file: filePath,
					line: lines.findIndex((l) => l.trim().length > 500) + 1,
					code: `${longLines.length} long lines detected`,
					fix: "Skills should contain readable source code. Replace minified code with the unminified source",
				});
			}
		}

		return findings;
	},
};
