import { findCallExpressionsMatching, findImports } from "../parsers/source-code.js";
import type { Detector, Finding, ScanContext } from "../types.js";
import { toRelativePath } from "../utils.js";

/** Always flag these — no standard API shares these names */
const UNAMBIGUOUS_SHELL_FUNCTIONS = ["execSync", "spawnSync", "execFile", "execFileSync"];

/** Only flag these if the file imports child_process */
const AMBIGUOUS_SHELL_FUNCTIONS = ["exec", "spawn", "fork"];

const DANGEROUS_COMMAND_STRINGS = [
	"rm -rf",
	"rm -fr",
	"rmdir /s",
	"chmod 777",
	"mkfs",
	"dd if=",
	"> /dev/sda",
	":(){ :|:& };:",
	"format c:",
];

const DANGEROUS_PIPE_PATTERNS = [/curl\b.*\|\s*(?:ba)?sh/i, /wget\b.*\|\s*(?:ba)?sh/i];

/** Detect shell command execution and dangerous command patterns */
export const shellExecDetector: Detector = {
	id: "shell-exec",
	name: "Shell Execution",
	description: "Detects child_process usage and dangerous shell command patterns",

	async run(ctx: ScanContext): Promise<Finding[]> {
		const findings: Finding[] = [];

		// Build set of file paths that import child_process
		const childProcessImports = findImports(ctx.files);
		const filesWithChildProcess = new Set(
			childProcessImports
				.filter(
					(imp) =>
						imp.moduleSpecifier === "child_process" || imp.moduleSpecifier === "node:child_process",
				)
				.map((imp) => imp.sourceFile.getFilePath()),
		);

		// Find unambiguous calls (always flagged) + ambiguous calls (only if file imports child_process)
		const unambiguousCalls = findCallExpressionsMatching(ctx.files, UNAMBIGUOUS_SHELL_FUNCTIONS);
		const ambiguousCalls = findCallExpressionsMatching(ctx.files, AMBIGUOUS_SHELL_FUNCTIONS).filter(
			(call) => filesWithChildProcess.has(call.sourceFile.getFilePath()),
		);
		const calls = [...unambiguousCalls, ...ambiguousCalls];

		for (const call of calls) {
			const filePath = toRelativePath(call.sourceFile.getFilePath(), ctx.skillPath);
			const argsText = call.arguments.join(" ");
			const argsLower = argsText.toLowerCase();

			// Check for dangerous command patterns
			let isDangerous = false;
			for (const pattern of DANGEROUS_COMMAND_STRINGS) {
				if (argsLower.includes(pattern.toLowerCase())) {
					findings.push({
						detectorId: "shell-exec",
						severity: "critical",
						title: "Dangerous shell command",
						description: `Executes dangerous command pattern: "${pattern}"`,
						file: filePath,
						line: call.line,
						code: call.fullText.slice(0, 120),
						fix: "Remove this dangerous command. Skills should never execute destructive shell commands",
					});
					isDangerous = true;
				}
			}

			// Check for dangerous pipe patterns (curl|bash, wget|sh, etc.)
			for (const pipePattern of DANGEROUS_PIPE_PATTERNS) {
				if (pipePattern.test(argsText)) {
					findings.push({
						detectorId: "shell-exec",
						severity: "critical",
						title: "Dangerous shell command",
						description: "Pipes downloaded content to a shell interpreter",
						file: filePath,
						line: call.line,
						code: call.fullText.slice(0, 120),
						fix: "Never pipe downloaded content to bash/sh. Download first, review, then execute",
					});
					isDangerous = true;
				}
			}

			// Check for shell: true in spawn options
			if (
				(call.name.includes("spawn") || call.name.includes("exec")) &&
				argsText.includes("shell: true")
			) {
				findings.push({
					detectorId: "shell-exec",
					severity: "high",
					title: "Shell execution with shell: true",
					description: "Spawns a process with shell: true, enabling shell injection",
					file: filePath,
					line: call.line,
					code: call.fullText.slice(0, 120),
					fix: "Avoid shell: true. Use spawn with an arguments array instead of exec with a command string",
				});
			}

			// Check for command injection (template literals or variable concatenation in first arg)
			const firstArg = call.arguments[0] ?? "";
			const hasTemplateOrConcat =
				firstArg.includes("${") || firstArg.includes("+") || firstArg.includes("` ");
			if (hasTemplateOrConcat) {
				findings.push({
					detectorId: "shell-exec",
					severity: "critical",
					title: "Command injection risk",
					description:
						"Shell command is constructed from dynamic input, enabling command injection",
					file: filePath,
					line: call.line,
					code: call.fullText.slice(0, 120),
					fix: "Never build shell commands from variables. Use spawn with an arguments array and validate inputs",
				});
			}

			// General shell execution finding (if not already caught as dangerous)
			if (!isDangerous) {
				findings.push({
					detectorId: "shell-exec",
					severity: "high",
					title: "Shell command execution",
					description: `Executes a shell command via ${call.name}`,
					file: filePath,
					line: call.line,
					code: call.fullText.slice(0, 120),
					fix: "Avoid shell execution in skills. If necessary, use spawn with an arguments array and validate all inputs",
				});
			}
		}

		return findings;
	},
};
