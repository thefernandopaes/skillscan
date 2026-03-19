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
	if (filePath.startsWith(basePath)) {
		return filePath.slice(basePath.length + 1).replace(/\\/g, "/");
	}
	return filePath.replace(/\\/g, "/");
}
