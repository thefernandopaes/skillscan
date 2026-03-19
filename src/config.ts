import { cosmiconfig } from "cosmiconfig";
import type { Result, ScanConfig } from "./types.js";

/** Default directories to exclude from scanning (build artifacts, framework output, caches) */
export const DEFAULT_EXCLUDE_DIRS = [
	"dist",
	".sst",
	".next",
	".nuxt",
	"build",
	".output",
	".vercel",
	".serverless",
	".amplify",
	".terraform",
	"coverage",
	".cache",
	"__pycache__",
	".turbo",
];

/** Default scan configuration */
export const DEFAULT_CONFIG: ScanConfig = {
	severity: "low",
	ignore: [],
	excludeDirs: [...DEFAULT_EXCLUDE_DIRS],
	allowlistedDomains: [
		"api.openai.com",
		"api.anthropic.com",
		"api.cohere.com",
		"generativelanguage.googleapis.com",
	],
	format: "terminal",
	output: null,
	quiet: false,
	verbose: false,
};

/**
 * Load scan configuration from cosmiconfig sources (skillscan.config.ts/json/yaml)
 * and merge with CLI option overrides.
 */
export async function loadConfig(overrides: Partial<ScanConfig> = {}): Promise<Result<ScanConfig>> {
	try {
		const explorer = cosmiconfig("skillscan");
		const result = await explorer.search();

		const fileConfig = (result?.config as Partial<ScanConfig>) ?? {};

		// Merge excludeDirs additively: user config extends defaults, not replaces
		const mergedExcludeDirs = [
			...DEFAULT_EXCLUDE_DIRS,
			...(fileConfig.excludeDirs ?? []),
			...(overrides.excludeDirs ?? []),
		];

		return {
			ok: true,
			value: {
				...DEFAULT_CONFIG,
				...fileConfig,
				...overrides,
				excludeDirs: [...new Set(mergedExcludeDirs)],
			},
		};
	} catch (error) {
		return {
			ok: false,
			error: error instanceof Error ? error : new Error("Failed to load configuration"),
		};
	}
}
