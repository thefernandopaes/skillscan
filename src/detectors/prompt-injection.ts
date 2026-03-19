import { SyntaxKind } from "ts-morph";
import { findStringLiterals } from "../parsers/source-code.js";
import type { Detector, Finding, ScanContext } from "../types.js";
import { toRelativePath } from "../utils.js";

const INJECTION_PATTERNS: Array<{ pattern: RegExp; description: string }> = [
	{
		pattern: /ignore\s+(all\s+)?previous\s+instructions/i,
		description: "Attempts to override previous instructions",
	},
	{
		pattern: /ignore\s+(all\s+)?prior\s+instructions/i,
		description: "Attempts to override prior instructions",
	},
	{
		pattern: /disregard\s+(all\s+)?(previous|prior|above)/i,
		description: "Attempts to disregard previous instructions",
	},
	{ pattern: /you\s+are\s+now\b/i, description: "Attempts to redefine the agent's identity" },
	{ pattern: /new\s+instructions:/i, description: "Injects new instructions" },
	{ pattern: /^system:\s*override/im, description: "Attempts system-level override" },
	{ pattern: /system:\s*you\s+are/i, description: "Attempts to inject a system prompt" },
	{ pattern: /assistant:\s*I\s+will/i, description: "Attempts to inject assistant behavior" },
	{
		pattern: /forget\s+(all\s+)?(your|previous)\s+(instructions|rules)/i,
		description: "Attempts to clear agent instructions",
	},
	{ pattern: /override\s+(all\s+)?safety/i, description: "Attempts to override safety checks" },
	{ pattern: /admin\s+mode/i, description: "Attempts to enter admin mode" },
	{ pattern: /jailbreak/i, description: "Contains jailbreak attempt" },
	{
		pattern: /do\s+not\s+follow\s+(your|the)\s+(instructions|rules)/i,
		description: "Attempts to bypass instructions",
	},
];

const ZERO_WIDTH_CHARS = [
	"\u200B", // zero-width space
	"\u200C", // zero-width non-joiner
	"\u200D", // zero-width joiner
	"\uFEFF", // zero-width no-break space
	"\u2060", // word joiner
	"\u180E", // mongolian vowel separator
];

const BASE64_PATTERN = /(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/;
const HTML_COMMENT_PATTERN = /<!--[\s\S]*?-->/g;

/** Detect prompt injection patterns in SKILL.md and source code */
export const promptInjectionDetector: Detector = {
	id: "prompt-injection",
	name: "Prompt Injection",
	description: "Detects embedded prompt injection patterns in instructions and code",

	async run(ctx: ScanContext): Promise<Finding[]> {
		const findings: Finding[] = [];

		// Scan SKILL.md
		if (ctx.skillMd) {
			scanText(ctx.skillMd.instructions, "SKILL.md", findings);
			scanText(ctx.skillMd.raw, "SKILL.md (raw)", findings);
		}

		// Scan string literals in source code
		const allStrings = findStringLiterals(ctx.files);
		for (const str of allStrings) {
			const filePath = toRelativePath(str.sourceFile.getFilePath(), ctx.skillPath);
			for (const { pattern, description } of INJECTION_PATTERNS) {
				if (pattern.test(str.text)) {
					findings.push({
						detectorId: "prompt-injection",
						severity: "critical",
						title: "Prompt injection in code",
						description: `${description}: "${str.text.slice(0, 80)}"`,
						file: filePath,
						line: str.line,
						code: str.text.slice(0, 120),
						fix: "Remove prompt injection patterns from string literals",
					});
				}
			}
		}

		// Check for dynamic prompt construction (template literals with expressions)
		for (const file of ctx.files) {
			const filePath = toRelativePath(file.getFilePath(), ctx.skillPath);
			const templates = file.getDescendantsOfKind(SyntaxKind.TemplateExpression);
			for (const template of templates) {
				const text = template.getText().toLowerCase();
				const hasPromptKeywords =
					text.includes("prompt") ||
					text.includes("instruction") ||
					text.includes("system") ||
					text.includes("you are");

				if (hasPromptKeywords && template.getTemplateSpans().length > 0) {
					findings.push({
						detectorId: "prompt-injection",
						severity: "medium",
						title: "Dynamic prompt construction",
						description: "Constructs prompts from dynamic input, which may enable injection",
						file: filePath,
						line: template.getStartLineNumber(),
						code: template.getText().slice(0, 120),
						fix: "Sanitize or validate external inputs before including them in prompts",
					});
				}
			}
		}

		return deduplicateFindings(findings);
	},
};

function scanText(text: string, source: string, findings: Finding[]): void {
	const lines = text.split("\n");

	for (let i = 0; i < lines.length; i++) {
		const line = lines[i];
		const lineNum = i + 1;

		// Check injection patterns
		for (const { pattern, description } of INJECTION_PATTERNS) {
			if (pattern.test(line)) {
				findings.push({
					detectorId: "prompt-injection",
					severity: "critical",
					title: "Prompt injection in instructions",
					description,
					file: source,
					line: lineNum,
					code: line.trim().slice(0, 120),
					fix: "Remove prompt injection patterns from skill instructions",
				});
			}
		}
	}

	// Check for hidden text in HTML comments
	const commentMatches = text.match(HTML_COMMENT_PATTERN);
	if (commentMatches) {
		for (const comment of commentMatches) {
			// Check if the comment contains injection-like content
			for (const { pattern, description } of INJECTION_PATTERNS) {
				if (pattern.test(comment)) {
					const lineNum = text.slice(0, text.indexOf(comment)).split("\n").length;
					findings.push({
						detectorId: "prompt-injection",
						severity: "critical",
						title: "Hidden prompt injection in HTML comment",
						description: `${description} (hidden in HTML comment)`,
						file: source,
						line: lineNum,
						code: comment.slice(0, 120),
						fix: "Remove hidden instructions from HTML comments",
					});
				}
			}
		}
	}

	// Check for zero-width characters
	for (const char of ZERO_WIDTH_CHARS) {
		if (text.includes(char)) {
			findings.push({
				detectorId: "prompt-injection",
				severity: "high",
				title: "Zero-width characters detected",
				description: "Contains zero-width Unicode characters that may hide instructions",
				file: source,
				line: 1,
				code: `Contains zero-width character U+${char.codePointAt(0)?.toString(16).toUpperCase().padStart(4, "0")}`,
				fix: "Remove zero-width characters from skill instructions",
			});
			break; // One finding for all zero-width chars
		}
	}

	// Check for base64 encoded blocks
	const base64Matches = text.match(BASE64_PATTERN);
	if (base64Matches) {
		for (const match of base64Matches) {
			if (match.length > 32) {
				const lineNum = text.slice(0, text.indexOf(match)).split("\n").length;
				findings.push({
					detectorId: "prompt-injection",
					severity: "medium",
					title: "Base64 encoded content in instructions",
					description: "Contains base64 encoded content that may hide instructions",
					file: source,
					line: lineNum,
					code: `${match.slice(0, 60)}...`,
					fix: "Decode and review base64 content, or remove it from instructions",
				});
			}
		}
	}
}

function deduplicateFindings(findings: Finding[]): Finding[] {
	const seen = new Set<string>();
	return findings.filter((f) => {
		const key = `${f.file}:${f.line}:${f.title}`;
		if (seen.has(key)) return false;
		seen.add(key);
		return true;
	});
}
