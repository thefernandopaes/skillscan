import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";
import { Project } from "ts-morph";
import { detectors } from "./detectors/index.js";
import type {
	DetectorResult,
	Finding,
	PackageJsonData,
	Result,
	RiskLevel,
	ScanConfig,
	ScanContext,
	ScanResult,
	Severity,
	SkillMdData,
} from "./types.js";

const SEVERITY_WEIGHTS: Record<Severity, number> = {
	critical: 10,
	high: 6,
	medium: 3,
	low: 1,
	info: 0,
};

const SOURCE_EXTENSIONS = new Set([".ts", ".js", ".mjs", ".cjs"]);

/**
 * Calculate risk score from findings.
 * Returns a value between 0.0 and 10.0.
 */
export function calculateRiskScore(findings: Finding[]): number {
	if (findings.length === 0) return 0;

	const totalWeight = findings.reduce(
		(sum, finding) => sum + SEVERITY_WEIGHTS[finding.severity],
		0,
	);

	// Cap at 10, scale logarithmically to avoid one finding = max score
	return Math.min(10, Math.round(totalWeight * 10) / 10);
}

/** Derive risk level from a numeric risk score */
export function getRiskLevel(score: number): RiskLevel {
	if (score <= 2.0) return "safe";
	if (score <= 4.0) return "caution";
	if (score <= 7.0) return "warning";
	return "danger";
}

/** Recursively collect source file paths from a directory */
async function collectSourceFiles(dirPath: string): Promise<string[]> {
	const files: string[] = [];
	const entries = await readdir(dirPath, { withFileTypes: true });

	for (const entry of entries) {
		const fullPath = path.join(dirPath, entry.name);
		if (entry.isDirectory()) {
			if (entry.name === "node_modules" || entry.name === ".git") continue;
			files.push(...(await collectSourceFiles(fullPath)));
		} else if (SOURCE_EXTENSIONS.has(path.extname(entry.name))) {
			files.push(fullPath);
		}
	}

	return files;
}

/** Try to parse SKILL.md from the skill directory */
async function loadSkillMd(skillPath: string): Promise<SkillMdData | null> {
	const skillMdPath = path.join(skillPath, "SKILL.md");
	try {
		const content = await readFile(skillMdPath, "utf-8");
		// Full parsing will be in src/parsers/skill-md.ts
		return {
			name: "",
			description: "",
			permissions: [],
			triggers: [],
			dependencies: [],
			instructions: content,
			raw: content,
		};
	} catch {
		return null;
	}
}

/** Try to parse package.json from the skill directory */
async function loadPackageJson(skillPath: string): Promise<PackageJsonData | null> {
	const pkgPath = path.join(skillPath, "package.json");
	try {
		const content = await readFile(pkgPath, "utf-8");
		const raw = JSON.parse(content) as Record<string, unknown>;
		return {
			name: (raw.name as string) ?? "",
			version: (raw.version as string) ?? "",
			dependencies: (raw.dependencies as Record<string, string>) ?? {},
			devDependencies: (raw.devDependencies as Record<string, string>) ?? {},
			scripts: (raw.scripts as Record<string, string>) ?? {},
			raw,
		};
	} catch {
		return null;
	}
}

/**
 * Run a full security scan on a skill directory.
 * Orchestrates file loading, detector execution, and score calculation.
 */
export async function scan(skillPath: string, config: ScanConfig): Promise<Result<ScanResult>> {
	const startTime = performance.now();

	try {
		// Verify path exists
		const pathStat = await stat(skillPath);
		if (!pathStat.isDirectory()) {
			return {
				ok: false,
				error: new Error(`Path is not a directory: ${skillPath}`),
			};
		}

		// Load files
		const filePaths = await collectSourceFiles(skillPath);
		const project = new Project({ skipAddingFilesFromTsConfig: true });
		for (const filePath of filePaths) {
			project.addSourceFileAtPath(filePath);
		}
		const sourceFiles = project.getSourceFiles();

		// Load metadata
		const [skillMd, packageJson] = await Promise.all([
			loadSkillMd(skillPath),
			loadPackageJson(skillPath),
		]);

		const skillName = packageJson?.name || skillMd?.name || path.basename(skillPath);

		// Build scan context
		const ctx: ScanContext = {
			skillPath,
			files: sourceFiles,
			skillMd,
			packageJson,
			config,
		};

		// Run detectors
		const activeDetectors = detectors.filter((d) => !config.ignore.includes(d.id));

		const detectorResults: DetectorResult[] = [];
		const allFindings: Finding[] = [];

		for (const detector of activeDetectors) {
			const detectorStart = performance.now();
			const findings = await detector.run(ctx);
			const duration = performance.now() - detectorStart;

			// Filter by minimum severity
			const severityOrder: Severity[] = ["info", "low", "medium", "high", "critical"];
			const minIndex = severityOrder.indexOf(config.severity);
			const filteredFindings = findings.filter(
				(f) => severityOrder.indexOf(f.severity) >= minIndex,
			);

			detectorResults.push({
				detectorId: detector.id,
				detectorName: detector.name,
				passed: filteredFindings.length === 0,
				findings: filteredFindings,
				duration,
			});

			allFindings.push(...filteredFindings);
		}

		const riskScore = calculateRiskScore(allFindings);
		const duration = performance.now() - startTime;

		return {
			ok: true,
			value: {
				skillName,
				skillPath,
				riskScore,
				riskLevel: getRiskLevel(riskScore),
				findings: allFindings,
				detectorResults,
				duration,
				scannedFiles: sourceFiles.length,
				timestamp: new Date().toISOString(),
			},
		};
	} catch (error) {
		return {
			ok: false,
			error: error instanceof Error ? error : new Error("Scan failed unexpectedly"),
		};
	}
}
