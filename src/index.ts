#!/usr/bin/env node
/**
 * MCP Server Connector - NPM Wrapper
 * This script wraps the Python MCP server for easy distribution via npm
 */

import { spawn } from "child_process";
import { fileURLToPath } from "url";
import { dirname, join } from "path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Path to the Python server script
const serverPath = join(__dirname, "..", "server.py");

// Spawn Python process
const python = process.platform === "win32" ? "python" : "python3";
const child = spawn(python, [serverPath], {
  stdio: ["inherit", "inherit", "inherit"],
});

child.on("close", (code) => {
  process.exit(code ?? 0);
});
