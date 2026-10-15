#!/usr/bin/env node
/**
 * compile_tact.mjs — compile a Tact project to code cell BoC.
 *
 * Usage:
 *   node compile_tact.mjs <version> <tact.config.json_path> <output_dir>
 *
 * Uses the `tact` CLI from @tact-lang/compiler.
 * Patches the config's project.output fields to point to <output_dir>,
 * writes a temp config next to the original (so relative paths resolve),
 * then runs: tact --config <patched_config>
 * Exit 0 on success, exit 1 on error.
 *
 * Plan v4 06 4.2 — coordinator requirement 2026-10-09: project root with tact.config.json.
 */
import { spawnSync } from "child_process";
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync, unlinkSync } from "fs";
import { resolve, dirname, join } from "path";

function findTactCli() {
  const nodePath = process.env.NODE_PATH || "";
  for (const dir of nodePath.split(":").filter(Boolean)) {
    // In the sandbox image: NODE_PATH=/opt/ton-node/node_modules
    // .bin symlinks are at /opt/ton-node/node_modules/.bin/
    const bin = join(dir, ".bin", "tact");
    if (existsSync(bin)) return bin;
    // Also try parent dir .bin
    const parentBin = join(dir, "..", "node_modules", ".bin", "tact");
    if (existsSync(parentBin)) return parentBin;
  }
  // Local dev: script's node_modules/.bin
  const scriptDir = new URL(".", import.meta.url).pathname;
  const localBin = join(scriptDir, "node_modules", ".bin", "tact");
  if (existsSync(localBin)) return localBin;
  return null;
}

function findBocFiles(dir) {
  const found = [];
  try {
    for (const f of readdirSync(dir, { withFileTypes: true })) {
      if (f.isFile() && (f.name.endsWith(".boc") || f.name.endsWith(".cell"))) {
        found.push(join(dir, f.name));
      } else if (f.isDirectory()) {
        found.push(...findBocFiles(join(dir, f.name)));
      }
    }
  } catch (_) {}
  return found;
}

async function main() {
  const [version, configPath, outDir] = process.argv.slice(2);
  if (!version || !configPath || !outDir) {
    process.stderr.write("compile_tact.mjs: usage: <version> <config.json> <outDir>\n");
    process.exit(1);
  }

  mkdirSync(outDir, { recursive: true });
  const absConfig = resolve(configPath);
  const configDir = dirname(absConfig);
  const absOut = resolve(outDir);

  const tactBin = findTactCli();
  if (!tactBin) {
    process.stderr.write("compile_tact.mjs: cannot locate tact CLI (NODE_PATH=" + (process.env.NODE_PATH || "") + ")\n");
    process.exit(1);
  }
  process.stderr.write(`compile_tact.mjs: tact CLI at ${tactBin}\n`);

  // Read and patch the config: set project output dirs to absOut
  let config;
  try {
    config = JSON.parse(readFileSync(absConfig, "utf8"));
  } catch (e) {
    process.stderr.write(`compile_tact.mjs: cannot parse config: ${e.message}\n`);
    process.exit(1);
  }
  for (const proj of config.projects || []) {
    proj.output = absOut;
  }

  // Write patched config NEXT TO the original so relative project paths still resolve
  const patchedPath = join(configDir, "tact.config._soken_patched.json");
  try {
    writeFileSync(patchedPath, JSON.stringify(config, null, 2));
  } catch (e) {
    process.stderr.write(`compile_tact.mjs: cannot write patched config: ${e.message}\n`);
    process.exit(1);
  }

  const nodeExe = process.execPath;
  const result = spawnSync(nodeExe, [tactBin, "--config", patchedPath, "--quiet"], {
    encoding: "utf8",
    timeout: 300000,  // 5 min: arm64/Rosetta emulation of amd64 image adds latency
    env: { ...process.env },
    cwd: configDir,  // run from config dir so any remaining relative paths resolve
  });

  // Clean up patched config
  try { unlinkSync(patchedPath); } catch (_) {}

  if (result.error) {
    process.stderr.write(`compile_tact.mjs: spawn error: ${result.error.message}\n`);
    process.exit(1);
  }
  if (result.status !== 0) {
    process.stderr.write(`compile_tact.mjs: tact exited ${result.status}\n`);
    if (result.stdout) process.stderr.write("stdout: " + result.stdout.slice(0, 500) + "\n");
    if (result.stderr) process.stderr.write("stderr: " + result.stderr.slice(0, 500) + "\n");
    process.exit(1);
  }

  const bocFiles = findBocFiles(absOut);
  process.stdout.write(`ok: ${bocFiles.length} output files\n`);
  process.exit(0);
}

main();
