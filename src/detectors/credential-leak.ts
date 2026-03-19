import { findStringLiterals } from "../parsers/source-code.js";
import type { Detector, Finding, ScanContext } from "../types.js";
import { toRelativePath } from "../utils.js";

const CREDENTIAL_PATTERNS: Array<{ name: string; pattern: RegExp }> = [
	{ name: "AWS Access Key", pattern: /AKIA[0-9A-Z]{16}/ },
	{
		name: "AWS Secret Key",
		pattern: /(?:aws)?_?secret_?(?:access)?_?key.{0,20}[A-Za-z0-9/+=]{40}/,
	},
	{ name: "GitHub Token", pattern: /ghp_[A-Za-z0-9]{36}/ },
	{ name: "GitHub OAuth", pattern: /gho_[A-Za-z0-9]{36}/ },
	{ name: "GitHub App Token", pattern: /(?:ghu|ghs)_[A-Za-z0-9]{36}/ },
	{ name: "Slack Bot Token", pattern: /xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}/ },
	{ name: "Slack User Token", pattern: /xoxp-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}/ },
	{
		name: "Slack Webhook",
		pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/,
	},
	{ name: "Stripe Secret Key", pattern: /sk_live_[0-9a-zA-Z]{24,}/ },
	{ name: "Stripe Publishable Key", pattern: /pk_live_[0-9a-zA-Z]{24,}/ },
	{ name: "Google API Key", pattern: /AIza[0-9A-Za-z_-]{35}/ },
	{ name: "Twilio API Key", pattern: /SK[0-9a-fA-F]{32}/ },
	{ name: "SendGrid API Key", pattern: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/ },
	{ name: "npm Token", pattern: /npm_[A-Za-z0-9]{36}/ },
	{ name: "Private Key", pattern: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/ },
	{
		name: "Generic API Key",
		pattern: /(?:api[_-]?key|apikey)\s*[:=]\s*["'][A-Za-z0-9_-]{20,}["']/i,
	},
	{ name: "Generic Secret", pattern: /(?:secret|password|passwd|pwd)\s*[:=]\s*["'][^"']{8,}["']/i },
];

const SENSITIVE_ENV_NAMES = [
	"API_KEY",
	"SECRET_KEY",
	"ACCESS_TOKEN",
	"AUTH_TOKEN",
	"PRIVATE_KEY",
	"DATABASE_URL",
	"DB_PASSWORD",
	"AWS_SECRET",
	"GITHUB_TOKEN",
	"SLACK_TOKEN",
	"STRIPE_KEY",
	"OPENAI_API_KEY",
	"ANTHROPIC_API_KEY",
	"PASSWORD",
	"CREDENTIALS",
];

/** Detect hardcoded credentials and sensitive environment variable access */
export const credentialLeakDetector: Detector = {
	id: "credential-leak",
	name: "Credential Exposure",
	description: "Detects hardcoded API keys, tokens, and secrets in source code",

	async run(ctx: ScanContext): Promise<Finding[]> {
		const findings: Finding[] = [];

		// Scan string literals for credential patterns
		const allStrings = findStringLiterals(ctx.files);
		for (const str of allStrings) {
			const filePath = toRelativePath(str.sourceFile.getFilePath(), ctx.skillPath);

			for (const { name, pattern } of CREDENTIAL_PATTERNS) {
				if (pattern.test(str.text)) {
					findings.push({
						detectorId: "credential-leak",
						severity: "high",
						title: `Hardcoded ${name}`,
						description: `Contains what appears to be a hardcoded ${name}`,
						file: filePath,
						line: str.line,
						code: str.text.slice(0, 40).replace(/./g, (c, i) => (i < 8 ? c : "*")),
						fix: `Move the ${name} to an environment variable and use process.env to access it`,
					});
					break; // One finding per string
				}
			}
		}

		// Check for process.env access to sensitive names
		for (const file of ctx.files) {
			const filePath = toRelativePath(file.getFilePath(), ctx.skillPath);
			const text = file.getFullText();

			for (const envName of SENSITIVE_ENV_NAMES) {
				const envPattern = new RegExp(
					`process\\.env\\.${envName}|process\\.env\\[['"]${envName}['"]\\]`,
					"g",
				);
				const matches = text.matchAll(envPattern);
				for (const match of matches) {
					const lineNum = text.slice(0, match.index).split("\n").length;
					findings.push({
						detectorId: "credential-leak",
						severity: "medium",
						title: "Sensitive environment variable access",
						description: `Accesses sensitive environment variable ${envName}`,
						file: filePath,
						line: lineNum,
						code: match[0],
						fix: "Ensure this environment variable is not logged or transmitted to external services",
					});
				}
			}
		}

		return findings;
	},
};
