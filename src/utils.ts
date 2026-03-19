import type { Result } from "./types.js";

/**
 * Create a successful Result
 */
export function ok<T>(value: T): Result<T, never> {
	return { ok: true, value };
}

/**
 * Create a failed Result
 */
export function err<E>(error: E): Result<never, E> {
	return { ok: false, error };
}

/**
 * Convert a relative file path to a display-friendly format
 */
export function toRelativePath(filePath: string, basePath: string): string {
	const normalizedFile = filePath.replace(/\\/g, "/");
	const normalizedBase = basePath.replace(/\\/g, "/");
	if (normalizedFile.startsWith(normalizedBase)) {
		return normalizedFile.slice(normalizedBase.length + 1);
	}
	return normalizedFile;
}
