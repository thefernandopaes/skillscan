import { findCallExpressionsMatching, findImports } from "../parsers/source-code.js";
import type { Detector, Finding, ScanContext } from "../types.js";

const PERMISSION_MAP: Record<string, { imports: string[]; functions: string[] }> = {
	network: {
		imports: ["node-fetch", "axios", "got", "undici", "http", "https", "node:http", "node:https"],
		functions: ["fetch", "request", "get", "post"],
	},
	filesystem: {
		imports: ["fs", "node:fs", "fs/promises", "node:fs/promises"],
		functions: [
			"readFileSync",
			"readFile",
			"writeFileSync",
			"writeFile",
			"readdirSync",
			"readdir",
			"mkdirSync",
			"mkdir",
		],
	},
	shell: {
		imports: ["child_process", "node:child_process"],
		functions: ["exec", "execSync", "spawn", "spawnSync", "fork", "execFile"],
	},
};

/** Detect permission mismatches between declared capabilities and actual code usage */
export const permissionScopeDetector: Detector = {
	id: "permission-scope",
	name: "Permission Scope",
	description: "Compares declared permissions against actual code usage",

	async run(ctx: ScanContext): Promise<Finding[]> {
		const findings: Finding[] = [];

		const declaredPermissions = new Set(ctx.skillMd?.permissions ?? []);

		// Detect actual capabilities used in code
		const usedPermissions = new Set<string>();

		for (const [permission, { imports, functions }] of Object.entries(PERMISSION_MAP)) {
			const hasImport = imports.some((mod) => findImports(ctx.files, mod).length > 0);
			const hasFunction = findCallExpressionsMatching(ctx.files, functions).length > 0;

			if (hasImport || hasFunction) {
				usedPermissions.add(permission);
			}
		}

		// Flag undeclared permissions (using capabilities not declared)
		for (const used of usedPermissions) {
			if (!declaredPermissions.has(used)) {
				findings.push({
					detectorId: "permission-scope",
					severity: "medium",
					title: "Undeclared permission usage",
					description: `Uses "${used}" capabilities without declaring the "${used}" permission in SKILL.md`,
					file: "SKILL.md",
					line: 1,
					code: `Missing permission: ${used}`,
					fix: `Add "${used}" to the permissions list in SKILL.md frontmatter, or remove the code that requires it`,
				});
			}
		}

		// Flag excessive permissions (declared but not used)
		for (const declared of declaredPermissions) {
			if (PERMISSION_MAP[declared] && !usedPermissions.has(declared)) {
				findings.push({
					detectorId: "permission-scope",
					severity: "low",
					title: "Excessive permission declared",
					description: `Declares "${declared}" permission but doesn't appear to use it`,
					file: "SKILL.md",
					line: 1,
					code: `Unused permission: ${declared}`,
					fix: `Remove "${declared}" from the permissions list if it's not needed`,
				});
			}
		}

		return findings;
	},
};
