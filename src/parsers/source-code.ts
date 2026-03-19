import { type SourceFile, SyntaxKind } from "ts-morph";

/** Represents a found call expression with metadata */
export interface CallExpressionInfo {
	name: string;
	fullText: string;
	arguments: string[];
	line: number;
	sourceFile: SourceFile;
}

/** Represents a found import declaration with metadata */
export interface ImportInfo {
	moduleSpecifier: string;
	namedImports: string[];
	defaultImport: string | null;
	line: number;
	sourceFile: SourceFile;
}

/** Represents a found string literal with metadata */
export interface StringLiteralInfo {
	text: string;
	line: number;
	sourceFile: SourceFile;
}

/**
 * Find all call expressions matching a given function/method name across source files.
 * Supports dotted names like "fs.readFileSync" and simple names like "fetch".
 */
export function findCallExpressions(files: SourceFile[], name: string): CallExpressionInfo[] {
	const results: CallExpressionInfo[] = [];

	for (const file of files) {
		const calls = file.getDescendantsOfKind(SyntaxKind.CallExpression);
		for (const call of calls) {
			const expression = call.getExpression();
			const callText = expression.getText();

			if (callText === name || callText.endsWith(`.${name}`)) {
				results.push({
					name: callText,
					fullText: call.getText(),
					arguments: call.getArguments().map((a) => a.getText()),
					line: call.getStartLineNumber(),
					sourceFile: file,
				});
			}
		}
	}

	return results;
}

/**
 * Find all call expressions where the function name matches any of the given names.
 */
export function findCallExpressionsMatching(
	files: SourceFile[],
	names: string[],
): CallExpressionInfo[] {
	const results: CallExpressionInfo[] = [];

	for (const file of files) {
		const calls = file.getDescendantsOfKind(SyntaxKind.CallExpression);
		for (const call of calls) {
			const expression = call.getExpression();
			const callText = expression.getText();

			for (const name of names) {
				if (callText === name || callText.endsWith(`.${name}`)) {
					results.push({
						name: callText,
						fullText: call.getText(),
						arguments: call.getArguments().map((a) => a.getText()),
						line: call.getStartLineNumber(),
						sourceFile: file,
					});
					break;
				}
			}
		}
	}

	return results;
}

/**
 * Find all import declarations across source files, optionally filtered by module name.
 */
export function findImports(files: SourceFile[], moduleName?: string): ImportInfo[] {
	const results: ImportInfo[] = [];

	for (const file of files) {
		const imports = file.getImportDeclarations();
		for (const imp of imports) {
			const specifier = imp.getModuleSpecifierValue();

			if (moduleName && specifier !== moduleName) continue;

			const namedImports = imp.getNamedImports().map((n) => n.getName());
			const defaultImport = imp.getDefaultImport()?.getText() ?? null;

			results.push({
				moduleSpecifier: specifier,
				namedImports,
				defaultImport,
				line: imp.getStartLineNumber(),
				sourceFile: file,
			});
		}
	}

	return results;
}

/**
 * Find all string literals across source files, optionally filtered by a predicate.
 */
export function findStringLiterals(
	files: SourceFile[],
	predicate?: (text: string) => boolean,
): StringLiteralInfo[] {
	const results: StringLiteralInfo[] = [];

	for (const file of files) {
		const literals = file.getDescendantsOfKind(SyntaxKind.StringLiteral);
		for (const literal of literals) {
			const text = literal.getLiteralValue();
			if (predicate && !predicate(text)) continue;

			results.push({
				text,
				line: literal.getStartLineNumber(),
				sourceFile: file,
			});
		}

		// Also check template literals (no-substitution only for simple strings)
		const templates = file.getDescendantsOfKind(SyntaxKind.NoSubstitutionTemplateLiteral);
		for (const tmpl of templates) {
			const text = tmpl.getLiteralValue();
			if (predicate && !predicate(text)) continue;

			results.push({
				text,
				line: tmpl.getStartLineNumber(),
				sourceFile: file,
			});
		}
	}

	return results;
}

/**
 * Get all call expressions in the source files (unfiltered).
 */
export function getAllCallExpressions(files: SourceFile[]): CallExpressionInfo[] {
	const results: CallExpressionInfo[] = [];

	for (const file of files) {
		const calls = file.getDescendantsOfKind(SyntaxKind.CallExpression);
		for (const call of calls) {
			results.push({
				name: call.getExpression().getText(),
				fullText: call.getText(),
				arguments: call.getArguments().map((a) => a.getText()),
				line: call.getStartLineNumber(),
				sourceFile: file,
			});
		}
	}

	return results;
}
