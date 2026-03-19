import { Project } from "ts-morph";
import { describe, expect, it } from "vitest";
import { getLifecycleScripts, parsePackageJson } from "../src/parsers/package-json.js";
import { parseSkillMd } from "../src/parsers/skill-md.js";
import {
	findCallExpressions,
	findImports,
	findStringLiterals,
} from "../src/parsers/source-code.js";

describe("parseSkillMd", () => {
	it("parses frontmatter and instructions from SKILL.md", () => {
		const content = `---
name: test-skill
description: A test skill
permissions:
  - network
  - filesystem
triggers:
  - test
dependencies:
  - some-dep
---

# Test Skill

This is the instruction text.`;

		const result = parseSkillMd(content);
		expect(result.ok).toBe(true);
		if (!result.ok) return;

		expect(result.value.name).toBe("test-skill");
		expect(result.value.description).toBe("A test skill");
		expect(result.value.permissions).toEqual(["network", "filesystem"]);
		expect(result.value.triggers).toEqual(["test"]);
		expect(result.value.dependencies).toEqual(["some-dep"]);
		expect(result.value.instructions).toContain("This is the instruction text.");
	});

	it("handles missing frontmatter gracefully", () => {
		const result = parseSkillMd("# Just a heading\n\nSome text.");
		expect(result.ok).toBe(true);
		if (!result.ok) return;

		expect(result.value.name).toBe("");
		expect(result.value.permissions).toEqual([]);
	});
});

describe("parsePackageJson", () => {
	it("parses a valid package.json", () => {
		const content = JSON.stringify({
			name: "test-pkg",
			version: "1.0.0",
			dependencies: { lodash: "^4.0.0" },
			devDependencies: { vitest: "^1.0.0" },
			scripts: { test: "vitest", postinstall: "node setup.js" },
		});

		const result = parsePackageJson(content);
		expect(result.ok).toBe(true);
		if (!result.ok) return;

		expect(result.value.name).toBe("test-pkg");
		expect(result.value.dependencies).toEqual({ lodash: "^4.0.0" });
		expect(result.value.scripts.postinstall).toBe("node setup.js");
	});

	it("returns error for invalid JSON", () => {
		const result = parsePackageJson("not json");
		expect(result.ok).toBe(false);
	});
});

describe("getLifecycleScripts", () => {
	it("detects postinstall scripts", () => {
		const result = parsePackageJson(
			JSON.stringify({
				name: "test",
				version: "1.0.0",
				scripts: { postinstall: "node setup.js", test: "vitest" },
			}),
		);
		if (!result.ok) return;

		const lifecycle = getLifecycleScripts(result.value);
		expect(lifecycle).toEqual({ postinstall: "node setup.js" });
	});
});

describe("source-code parser", () => {
	function createProject(code: string) {
		const project = new Project({ useInMemoryFileSystem: true });
		project.createSourceFile("test.ts", code);
		return project.getSourceFiles();
	}

	it("finds call expressions by name", () => {
		const files = createProject('fetch("https://example.com");');
		const calls = findCallExpressions(files, "fetch");
		expect(calls).toHaveLength(1);
		expect(calls[0].name).toBe("fetch");
	});

	it("finds dotted call expressions", () => {
		const files = createProject('fs.readFileSync("/etc/passwd", "utf-8");');
		const calls = findCallExpressions(files, "readFileSync");
		expect(calls).toHaveLength(1);
		expect(calls[0].name).toBe("fs.readFileSync");
	});

	it("finds imports by module name", () => {
		const files = createProject('import fs from "fs";\nimport path from "path";');
		const imports = findImports(files, "fs");
		expect(imports).toHaveLength(1);
		expect(imports[0].defaultImport).toBe("fs");
	});

	it("finds all imports when no module filter", () => {
		const files = createProject('import fs from "fs";\nimport path from "path";');
		const imports = findImports(files);
		expect(imports).toHaveLength(2);
	});

	it("finds string literals with predicate", () => {
		const files = createProject('const url = "https://evil.com";\nconst name = "safe";');
		const strings = findStringLiterals(files, (t) => t.includes("evil"));
		expect(strings).toHaveLength(1);
		expect(strings[0].text).toBe("https://evil.com");
	});
});
