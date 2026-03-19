import matter from "gray-matter";
import type { Result, SkillMdData } from "../types.js";

/**
 * Parse a SKILL.md file content into structured data.
 * Extracts YAML frontmatter and instruction text.
 */
export function parseSkillMd(content: string): Result<SkillMdData> {
	try {
		const { data, content: instructions } = matter(content);
		const frontmatter = data as Record<string, unknown>;

		return {
			ok: true,
			value: {
				name: asString(frontmatter.name),
				description: asString(frontmatter.description),
				permissions: asStringArray(frontmatter.permissions),
				triggers: asStringArray(frontmatter.triggers),
				dependencies: asStringArray(frontmatter.dependencies),
				instructions: instructions.trim(),
				raw: content,
			},
		};
	} catch (error) {
		return {
			ok: false,
			error: error instanceof Error ? error : new Error("Failed to parse SKILL.md"),
		};
	}
}

function asString(value: unknown): string {
	return typeof value === "string" ? value : "";
}

function asStringArray(value: unknown): string[] {
	if (Array.isArray(value)) {
		return value.filter((v): v is string => typeof v === "string");
	}
	return [];
}
