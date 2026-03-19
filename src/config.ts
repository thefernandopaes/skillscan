import { cosmiconfig } from "cosmiconfig";
import type { Result, ScanConfig } from "./types.js";

/** Default scan configuration */
export const DEFAULT_CONFIG: ScanConfig = {
	severity: "low",
	ignore: [],
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

		return {
			ok: true,
			value: {
				...DEFAULT_CONFIG,
				...fileConfig,
				...overrides,
			},
		};
	} catch (error) {
		return {
			ok: false,
			error: error instanceof Error ? error : new Error("Failed to load configuration"),
		};
	}
}
