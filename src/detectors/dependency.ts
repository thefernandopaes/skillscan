import type { Detector, Finding, ScanContext } from "../types.js";

const KNOWN_MALICIOUS_PACKAGES = new Set([
	"event-stream",
	"flatmap-stream",
	"ua-parser-js-malware",
	"colors-hierarchical",
	"rc-hierarchical",
	"coa-hierarchical",
]);

const POPULAR_PACKAGES = [
	"lodash",
	"express",
	"react",
	"axios",
	"moment",
	"chalk",
	"commander",
	"debug",
	"dotenv",
	"cors",
	"body-parser",
	"uuid",
	"webpack",
	"babel",
	"eslint",
	"prettier",
	"typescript",
	"jest",
	"mocha",
	"colors",
	"request",
	"underscore",
	"async",
	"bluebird",
	"cheerio",
	"inquirer",
	"ora",
	"glob",
	"minimist",
	"yargs",
	"node-fetch",
	"cross-env",
	"rimraf",
	"mkdirp",
	"semver",
	"fs-extra",
];

/**
 * Calculate the Levenshtein distance between two strings.
 */
function levenshtein(a: string, b: string): number {
	const matrix: number[][] = [];

	for (let i = 0; i <= b.length; i++) {
		matrix[i] = [i];
	}
	for (let j = 0; j <= a.length; j++) {
		matrix[0][j] = j;
	}

	for (let i = 1; i <= b.length; i++) {
		for (let j = 1; j <= a.length; j++) {
			const cost = b[i - 1] === a[j - 1] ? 0 : 1;
			matrix[i][j] = Math.min(
				matrix[i - 1][j] + 1,
				matrix[i][j - 1] + 1,
				matrix[i - 1][j - 1] + cost,
			);
		}
	}

	return matrix[b.length][a.length];
}

/**
 * Check if a package name might be a typosquatting attempt.
 */
function findTyposquatCandidates(packageName: string): string[] {
	return POPULAR_PACKAGES.filter((popular) => {
		if (packageName === popular) return false;
		const distance = levenshtein(packageName, popular);
		return distance > 0 && distance <= 2;
	});
}

/** Detect malicious, typosquatted, or risky npm dependencies */
export const dependencyDetector: Detector = {
	id: "dependency",
	name: "Dependency Risk",
	description: "Analyzes package.json for malicious, typosquatted, or risky dependencies",

	async run(ctx: ScanContext): Promise<Finding[]> {
		const findings: Finding[] = [];

		if (!ctx.packageJson) return findings;

		const allDeps = {
			...ctx.packageJson.dependencies,
			...ctx.packageJson.devDependencies,
		};

		for (const [name, version] of Object.entries(allDeps)) {
			// Check known malicious packages
			if (KNOWN_MALICIOUS_PACKAGES.has(name)) {
				findings.push({
					detectorId: "dependency",
					severity: "critical",
					title: "Known malicious package",
					description: `Depends on "${name}" which is a known malicious package`,
					file: "package.json",
					line: 1,
					code: `"${name}": "${version}"`,
					fix: `Remove "${name}" immediately and audit your project for compromise`,
				});
				continue;
			}

			// Check for typosquatting
			const candidates = findTyposquatCandidates(name);
			if (candidates.length > 0) {
				findings.push({
					detectorId: "dependency",
					severity: "medium",
					title: "Possible typosquatted package",
					description: `"${name}" is suspiciously similar to popular package(s): ${candidates.join(", ")}`,
					file: "package.json",
					line: 1,
					code: `"${name}": "${version}"`,
					fix: `Verify that "${name}" is the correct package name. Did you mean: ${candidates.join(" or ")}?`,
				});
			}
		}

		// Check for lifecycle scripts
		const lifecycleScripts = ["preinstall", "install", "postinstall"];
		for (const scriptName of lifecycleScripts) {
			if (ctx.packageJson.scripts[scriptName]) {
				findings.push({
					detectorId: "dependency",
					severity: "high",
					title: "Lifecycle script detected",
					description: `Has a "${scriptName}" script that runs automatically: "${ctx.packageJson.scripts[scriptName]}"`,
					file: "package.json",
					line: 1,
					code: `"${scriptName}": "${ctx.packageJson.scripts[scriptName]}"`,
					fix: `Review the "${scriptName}" script carefully. Lifecycle scripts can execute arbitrary code during install`,
				});
			}
		}

		return findings;
	},
};
