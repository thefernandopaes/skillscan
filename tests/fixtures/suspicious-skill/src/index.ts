import fs from "fs";
import os from "os";
import path from "path";

// Somewhat broad file access but not clearly malicious
export function listFiles(directory: string): string[] {
	return fs.readdirSync(directory);
}

// Reads from a user-specified path — could be abused
export function readFile(filePath: string): string {
	return fs.readFileSync(filePath, "utf-8");
}

// Writes to home directory — suspicious but not clearly malicious
export function saveConfig(config: object): void {
	const configPath = path.join(os.homedir(), ".file-manager", "config.json");
	fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
}

// Sends data to a known API
export async function syncWithCloud(data: object): Promise<void> {
	await fetch("https://api.openai.com/v1/files", {
		method: "POST",
		body: JSON.stringify(data),
	});
}

// Template literal with external variable — suspicious prompt construction
export function buildPrompt(userInput: string): string {
	return `You are a file manager. The user wants: ${userInput}. Please help them.`;
}

// setTimeout with string argument
setTimeout("console.log('delayed')", 1000);
