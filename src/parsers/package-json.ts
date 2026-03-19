import type { PackageJsonData, Result } from "../types.js";

/**
 * Parse a package.json string into structured data relevant for security analysis.
 */
export function parsePackageJson(content: string): Result<PackageJsonData> {
	try {
		const raw = JSON.parse(content) as Record<string, unknown>;

		return {
			ok: true,
			value: {
				name: asString(raw.name),
				version: asString(raw.version),
				dependencies: asRecord(raw.dependencies),
				devDependencies: asRecord(raw.devDependencies),
				scripts: asRecord(raw.scripts),
				raw,
			},
		};
	} catch (error) {
		return {
			ok: false,
			error: error instanceof Error ? error : new Error("Failed to parse package.json"),
		};
	}
}

/**
 * Check if a package.json has lifecycle scripts that run automatically (postinstall, preinstall, etc.)
 */
export function getLifecycleScripts(data: PackageJsonData): Record<string, string> {
	const lifecycleNames = [
		"preinstall",
		"install",
		"postinstall",
		"preuninstall",
		"postuninstall",
		"prepublish",
		"prepare",
	];

	const found: Record<string, string> = {};
	for (const name of lifecycleNames) {
		if (data.scripts[name]) {
			found[name] = data.scripts[name];
		}
	}
	return found;
}

function asString(value: unknown): string {
	return typeof value === "string" ? value : "";
}

function asRecord(value: unknown): Record<string, string> {
	if (typeof value === "object" && value !== null && !Array.isArray(value)) {
		const result: Record<string, string> = {};
		for (const [k, v] of Object.entries(value)) {
			if (typeof v === "string") {
				result[k] = v;
			}
		}
		return result;
	}
	return {};
}
