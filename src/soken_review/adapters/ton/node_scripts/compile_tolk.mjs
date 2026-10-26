#!/usr/bin/env node
/**
 * compile_tolk.mjs — compile a Tolk contract to code cell BoC.
 *
 * Usage:
 *   node compile_tolk.mjs <version> <entry.tolk> <output.boc>
 *
 * Each Tolk version is installed in the sandbox image as an npm alias:
 *   tolk-0.12.0 → @ton/tolk-js@0.12.0 at node_modules/tolk-0.12.0/
 *   tolk-1.0.0  → @ton/tolk-js@1.0.0  at node_modules/tolk-1.0.0/
 *
 * The version argument selects the alias via require('tolk-<version>').
 * Fallback for local dev or for a version matching the canonical @ton/tolk-js:
 * tries the canonical package if its version field matches.
 *
 * API compatibility (across all installed versions):
 *   runTolkCompiler({ entrypointFileName, fsReadCallback }) → { status, codeBoc64|codeBoc }
 *   compileTolk({ entrypoint, files }) → { status, codeBoc64|codeBoc }   (older)
 *
 * Exit 0 on success, exit 1 on error.
 *
 * Plan v4 06 4.2 — multi-version support 2026-10-25.
 */
import { readFileSync, writeFileSync, existsSync } from "fs";
import { resolve, dirname } from "path";
import { createRequire } from "module";

const require = createRequire(import.meta.url);

/**
 * Load the @ton/tolk-js module for a given version.
 * Tries tolk-<version> alias first, then the canonical @ton/tolk-js if it matches.
 */
function loadTolkModule(version) {
  // Try alias tolk-<version>
  try {
    return require(`tolk-${version}`);
  } catch (_) {}

  // Fallback: canonical @ton/tolk-js if version matches
  try {
    const canonMeta = require("@ton/tolk-js/package.json");
    if (canonMeta.version === version) {
      return require("@ton/tolk-js");
    }
  } catch (_) {}

  return null;
}

async function main() {
  const [version, entryPath, outPath] = process.argv.slice(2);
  if (!version || !entryPath || !outPath) {
    process.stderr.write("compile_tolk.mjs: usage: <version> <entry.tolk> <out.boc>\n");
    process.exit(1);
  }

  const tolkModule = loadTolkModule(version);
  if (!tolkModule) {
    process.stderr.write(
      `compile_tolk.mjs: unsupported_toolchain: cannot load tolk-js ${version} ` +
      `(alias tolk-${version} not found)\n`
    );
    process.exit(1);
  }

  const absEntry = resolve(entryPath);
  const entryDir = dirname(absEntry);

  // @ton/tolk-js API: runTolkCompiler({ entrypointFileName, fsReadCallback })
  if (typeof tolkModule.runTolkCompiler === "function") {
    try {
      const result = await tolkModule.runTolkCompiler({
        entrypointFileName: absEntry,
        fsReadCallback: (path) => {
          const abs = resolve(entryDir, path);
          if (existsSync(abs)) return readFileSync(abs, "utf8");
          // stdlib is loaded from the package — return null to let tolk-js handle it
          return null;
        },
      });
      if (result.status !== "ok") {
        process.stderr.write(`compile_tolk.mjs: ${result.message || "unknown error"}\n`);
        if (result.stderr) process.stderr.write(result.stderr + "\n");
        process.exit(1);
      }
      const bocField = result.codeBoc64 ?? result.codeBoc;
      if (!bocField) {
        process.stderr.write("compile_tolk.mjs: no codeBoc64 in result\n");
        process.exit(1);
      }
      const bocBuffer = Buffer.from(bocField, "base64");
      writeFileSync(outPath, bocBuffer);
      process.stdout.write(`ok: ${bocBuffer.length} bytes\n`);
      process.exit(0);
    } catch (e) {
      process.stderr.write(`compile_tolk.mjs: ${e.message}\n`);
      process.exit(1);
    }
  }

  // Older API: compileTolk({ entrypoint, files })
  if (typeof tolkModule.compileTolk === "function") {
    const entryContent = readFileSync(absEntry, "utf8");
    try {
      const result = await tolkModule.compileTolk({
        entrypoint: absEntry,
        files: [{ filename: absEntry, content: entryContent }],
      });
      if (result.status === "error") {
        process.stderr.write(`compile_tolk.mjs: ${result.message}\n`);
        process.exit(1);
      }
      const bocField = result.codeBoc64 ?? result.codeBoc;
      if (!bocField) {
        process.stderr.write("compile_tolk.mjs: no codeBoc field\n");
        process.exit(1);
      }
      const bocBuffer = Buffer.from(bocField, "base64");
      writeFileSync(outPath, bocBuffer);
      process.stdout.write(`ok: ${bocBuffer.length} bytes\n`);
      process.exit(0);
    } catch (e) {
      process.stderr.write(`compile_tolk.mjs: ${e.message}\n`);
      if (e.stack) process.stderr.write(e.stack + "\n");
      process.exit(1);
    }
  }

  process.stderr.write(`compile_tolk.mjs: unsupported @ton/tolk-js API in version ${version}\n`);
  process.exit(1);
}

main();
