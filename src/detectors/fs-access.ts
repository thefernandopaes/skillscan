import { findCallExpressionsMatching, findStringLiterals } from "../parsers/source-code.js";
import type { Detector, Finding, ScanContext } from "../types.js";
import { toRelativePath } from "../utils.js";

const FS_READ_FUNCTIONS = [
	"readFileSync",
	"readFile",
	"readdir",
	"readdirSync",
	"access",
	"accessSync",
	"open",
	"openSync",
	"createReadStream",
];

const FS_WRITE_FUNCTIONS = [
	"writeFileSync",
	"writeFile",
	"appendFileSync",
	"appendFile",
	"createWriteStream",
	"mkdir",
	"mkdirSync",
	"rename",
	"renameSync",
	"unlink",
	"unlinkSync",
	"rmSync",
	"rm",
];

const SENSITIVE_PATHS = [
	".ssh",
	".aws",
	".config/gcloud",
	".gnupg",
	".config/google-chrome",
	"Library/Application Support/Google/Chrome",
	".mozilla/firefox",
	".kube/config",
	".docker/config.json",
	".npmrc",
	".pypirc",
	".netrc",
	".bash_history",
	".zsh_history",
];

const SENSITIVE_SYSTEM_PATHS = ["/etc/passwd", "/etc/shadow", "/etc/hosts"];

const TRAVERSAL_PATTERNS = ["../../", "..\\..\\"];

const BROAD_GLOB_PATTERNS = ["/**", "/*", "\\**"];

/** Detect dangerous filesystem access patterns */
export const fsAccessDetector: Detector = {
	id: "fs-access",
	name: "Filesystem Access",
	description: "Detects reads from sensitive paths and dangerous filesystem operations",

	async run(ctx: ScanContext): Promise<Finding[]> {
		const findings: Finding[] = [];
		const allFsFunctions = [...FS_READ_FUNCTIONS, ...FS_WRITE_FUNCTIONS];
		const calls = findCallExpressionsMatching(ctx.files, allFsFunctions);

		for (const call of calls) {
			const filePath = toRelativePath(call.sourceFile.getFilePath(), ctx.skillPath);
			const argsText = call.arguments.join(" ").toLowerCase();
			const fullCallText = call.fullText.toLowerCase();

			// Check for sensitive path access
			for (const sensitivePath of SENSITIVE_PATHS) {
				if (fullCallText.includes(sensitivePath.toLowerCase())) {
					findings.push({
						detectorId: "fs-access",
						severity: "critical",
						title: "Credential file access",
						description: `Accesses sensitive path "${sensitivePath}" which may contain credentials`,
						file: filePath,
						line: call.line,
						code: call.fullText.slice(0, 120),
						fix: "Skills should never access credential files like SSH keys, AWS credentials, or browser profiles",
					});
				}
			}

			for (const sysPath of SENSITIVE_SYSTEM_PATHS) {
				if (fullCallText.includes(sysPath)) {
					findings.push({
						detectorId: "fs-access",
						severity: "critical",
						title: "System file access",
						description: `Accesses sensitive system file "${sysPath}"`,
						file: filePath,
						line: call.line,
						code: call.fullText.slice(0, 120),
						fix: "Skills should never read system files like /etc/passwd or /etc/shadow",
					});
				}
			}

			// Check for path traversal
			for (const pattern of TRAVERSAL_PATTERNS) {
				if (fullCallText.includes(pattern)) {
					findings.push({
						detectorId: "fs-access",
						severity: "high",
						title: "Path traversal detected",
						description:
							"Uses path traversal (../) which may access files outside the skill directory",
						file: filePath,
						line: call.line,
						code: call.fullText.slice(0, 120),
						fix: "Use absolute paths or paths relative to the skill directory. Avoid ../ patterns",
					});
				}
			}

			// Check for broad glob patterns
			for (const glob of BROAD_GLOB_PATTERNS) {
				if (argsText.includes(glob)) {
					findings.push({
						detectorId: "fs-access",
						severity: "high",
						title: "Overly broad filesystem access",
						description:
							"Uses an overly broad glob/path pattern that accesses the entire filesystem",
						file: filePath,
						line: call.line,
						code: call.fullText.slice(0, 120),
						fix: "Restrict filesystem access to specific directories the skill needs",
					});
				}
			}
		}

		// Also check string literals for homedir() + sensitive path patterns
		const strings = findStringLiterals(ctx.files, (text) => {
			const lower = text.toLowerCase();
			return (
				SENSITIVE_PATHS.some((p) => lower.includes(p.toLowerCase())) ||
				SENSITIVE_SYSTEM_PATHS.some((p) => lower.includes(p))
			);
		});

		for (const str of strings) {
			const filePath = toRelativePath(str.sourceFile.getFilePath(), ctx.skillPath);
			// Avoid duplicates — only flag if not already caught by call analysis
			const alreadyCaught = findings.some((f) => f.file === filePath && f.line === str.line);
			if (!alreadyCaught) {
				findings.push({
					detectorId: "fs-access",
					severity: "high",
					title: "Sensitive path reference",
					description: `References a sensitive file path: "${str.text.slice(0, 60)}"`,
					file: filePath,
					line: str.line,
					code: str.text.slice(0, 120),
					fix: "Verify this path reference is necessary and does not access credential files",
				});
			}
		}

		return findings;
	},
};
