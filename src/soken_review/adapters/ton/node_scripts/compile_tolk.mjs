#!/usr/bin/env node
/**
 * compile_tolk.mjs — compile a Tolk contract to code cell BoC.
 *
 * Usage:
 *   node compile_tolk.mjs <version> <entry.tolk> <output.boc>
 *
 * Uses @ton/tolk-js 0.12.0 (runTolkCompiler API, F32, plan v4 06 4.2).
 * Exit 0 on success, exit 1 on error.
 */
import { readFileSync, writeFileSync, existsSync } from "fs";
import { resolve, dirname } from "path";
import { createRequire } from "module";

const require = createRequire(import.meta.url);

async function main() {
  const [version, entryPath, outPath] = process.argv.slice(2);
  if (!version || !entryPath || !outPath) {
    process.stderr.write("compile_tolk.mjs: usage: <version> <entry.tolk> <out.boc>\n");
    process.exit(1);
  }

  let tolkModule;
  try {
    tolkModule = require("@ton/tolk-js");
  } catch (e) {
    process.stderr.write(`compile_tolk.mjs: cannot load @ton/tolk-js: ${e.message}\n`);
    process.exit(1);
  }

  const absEntry = resolve(entryPath);
  const entryDir = dirname(absEntry);

  // @ton/tolk-js 0.12.0 API: runTolkCompiler({ entrypointFileName, fsReadCallback })
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
      // 0.12.0 returns codeBoc64 (base64-encoded BoC)
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
      process.exit(1);
    }
  }

  process.stderr.write("compile_tolk.mjs: unsupported @ton/tolk-js API\n");
  process.exit(1);
}

main();
