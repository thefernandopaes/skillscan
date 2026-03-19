import type { Detector } from "../types.js";
import { credentialLeakDetector } from "./credential-leak.js";
import { dependencyDetector } from "./dependency.js";
import { fsAccessDetector } from "./fs-access.js";
import { networkExfilDetector } from "./network-exfil.js";
import { obfuscationDetector } from "./obfuscation.js";
import { permissionScopeDetector } from "./permission-scope.js";
import { promptInjectionDetector } from "./prompt-injection.js";
import { shellExecDetector } from "./shell-exec.js";

/**
 * Registry of all available detectors.
 * Detectors are executed in order during a scan.
 */
export const detectors: Detector[] = [
	networkExfilDetector,
	fsAccessDetector,
	shellExecDetector,
	promptInjectionDetector,
	credentialLeakDetector,
	obfuscationDetector,
	dependencyDetector,
	permissionScopeDetector,
];
