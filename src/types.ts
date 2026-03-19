import type { SourceFile } from "ts-morph";

/** Severity levels for security findings, ordered by impact */
export type Severity = "critical" | "high" | "medium" | "low" | "info";

/** Risk level classification derived from the overall risk score */
export type RiskLevel = "safe" | "caution" | "warning" | "danger";

/** Parsed SKILL.md frontmatter and content */
export interface SkillMdData {
	name: string;
	description: string;
	permissions: string[];
	triggers: string[];
	dependencies: string[];
	instructions: string;
	raw: string;
}

/** Parsed package.json data relevant to security analysis */
export interface PackageJsonData {
	name: string;
	version: string;
	dependencies: Record<string, string>;
	devDependencies: Record<string, string>;
	scripts: Record<string, string>;
	raw: Record<string, unknown>;
}

/** Context passed to each detector during a scan */
export interface ScanContext {
	skillPath: string;
	files: SourceFile[];
	skillMd: SkillMdData | null;
	packageJson: PackageJsonData | null;
	config: ScanConfig;
}

/** A single security finding reported by a detector */
export interface Finding {
	detectorId: string;
	severity: Severity;
	title: string;
	description: string;
	file: string;
	line: number;
	code: string;
	fix: string;
}

/** Result from a single detector's analysis */
export interface DetectorResult {
	detectorId: string;
	detectorName: string;
	passed: boolean;
	findings: Finding[];
	duration: number;
}

/** Complete scan result returned by the scanner */
export interface ScanResult {
	skillName: string;
	skillPath: string;
	riskScore: number;
	riskLevel: RiskLevel;
	findings: Finding[];
	detectorResults: DetectorResult[];
	duration: number;
	scannedFiles: number;
	timestamp: string;
}

/** Interface that all detectors must implement */
export interface Detector {
	id: string;
	name: string;
	description: string;
	/** Run the detector against the scan context and return findings */
	run(ctx: ScanContext): Promise<Finding[]>;
}

/** User-configurable scan settings */
export interface ScanConfig {
	severity: Severity;
	ignore: string[];
	allowlistedDomains: string[];
	format: "terminal" | "json" | "html";
	output: string | null;
	quiet: boolean;
	verbose: boolean;
}

/** Result type for operations that can fail */
export type Result<T, E = Error> = { ok: true; value: T } | { ok: false; error: E };
