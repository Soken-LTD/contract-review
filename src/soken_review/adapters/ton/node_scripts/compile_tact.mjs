#!/usr/bin/env node
/**
 * compile_tact.mjs — compile a Tact project to code cell BoC.
 *
 * Usage:
 *   node compile_tact.mjs <version> <tact.config.json_path> <output_dir>
 *
 * Each Tact version is installed in the sandbox image as an npm alias:
 *   tact-1.6.5  → @tact-lang/compiler@1.6.5  at node_modules/tact-1.6.5/
 *   tact-1.6.13 → @tact-lang/compiler@1.6.13 at node_modules/tact-1.6.13/
 *
 * The version argument selects the alias; the bin/tact.js (or bin/tact) entry
 * point is resolved from that alias's package.json, then called with:
 *   node <bin> --config <patched_config> --quiet
 *
 * Fallback for local dev (DIRECT mode, no NODE_PATH in image): looks for
 *   @tact-lang/compiler in the script's own node_modules (if installed there).
 *
 * Exit 0 on success, exit 1 on error.
 *
 * Plan v4 06 4.2 — multi-version support 2026-10-25.
 */
import { spawnSync } from "child_process";
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync, unlinkSync } from "fs";
import { resolve, dirname, join } from "path";

/**
 * Resolve the bin/tact.js path for a given version alias.
 *
 * In the sandbox image, NODE_PATH=/opt/ton-node/node_modules.
 * Each alias `tact-<version>` is installed at NODE_PATH/tact-<version>/.
 * The package.json bin field names the entry script.
 *
 * For local dev (DIRECT mode, NODE_PATH unset), we also check the script's
 * own sibling node_modules for @tact-lang/compiler.
 */
function resolveTactBin(version) {
  const nodePath = process.env.NODE_PATH || "";
  const dirs = nodePath.split(":").filter(Boolean);

  // Primary: tact-<version> alias in image node_modules
  for (const dir of dirs) {
    const pkgDir = join(dir, `tact-${version}`);
    const binPath = tactBinFromDir(pkgDir);
    if (binPath) return binPath;
  }

  // Secondary: @tact-lang/compiler (default, for matching version in local dev or
  // when the canonical install matches the requested version)
  for (const dir of dirs) {
    const pkgDir = join(dir, "@tact-lang", "compiler");
    const pkgJsonPath = join(pkgDir, "package.json");
    if (existsSync(pkgJsonPath)) {
      try {
        const meta = JSON.parse(readFileSync(pkgJsonPath, "utf8"));
        if (meta.version === version) {
          const binPath = tactBinFromDir(pkgDir);
          if (binPath) return binPath;
        }
      } catch (_) {}
    }
  }

  // Local dev: script's own node_modules (DIRECT=1, no image NODE_PATH)
  const scriptDir = new URL(".", import.meta.url).pathname;
  const localPkg = join(scriptDir, "node_modules", `tact-${version}`);
  const localBin = tactBinFromDir(localPkg);
  if (localBin) return localBin;

  const localCanonical = join(scriptDir, "node_modules", "@tact-lang", "compiler");
  if (existsSync(join(localCanonical, "package.json"))) {
    try {
      const meta = JSON.parse(readFileSync(join(localCanonical, "package.json"), "utf8"));
      if (meta.version === version) {
        const b = tactBinFromDir(localCanonical);
        if (b) return b;
      }
    } catch (_) {}
  }

  return null;
}

function tactBinFromDir(pkgDir) {
  const pkgJsonPath = join(pkgDir, "package.json");
  if (!existsSync(pkgJsonPath)) return null;
  try {
    const meta = JSON.parse(readFileSync(pkgJsonPath, "utf8"));
    const binField = meta.bin;
    let rel;
    if (typeof binField === "string") {
      rel = binField;
    } else if (binField && typeof binField === "object") {
      rel = binField.tact ?? binField.compiler ?? Object.values(binField)[0];
    }
    if (!rel) return null;
    const full = join(pkgDir, rel);
    return existsSync(full) ? full : null;
  } catch (_) {
    return null;
  }
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

  const tactBin = resolveTactBin(version);
  if (!tactBin) {
    process.stderr.write(
      `compile_tact.mjs: unsupported_toolchain: cannot locate tact ${version} ` +
      `(tact-${version} alias not found; NODE_PATH=${process.env.NODE_PATH || ""})\n`
    );
    process.exit(1);
  }
  process.stderr.write(`compile_tact.mjs: tact ${version} bin at ${tactBin}\n`);

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
    process.stderr.write(`compile_tact.mjs: tact ${version} exited ${result.status}\n`);
    if (result.stdout) process.stderr.write("stdout: " + result.stdout.slice(0, 500) + "\n");
    if (result.stderr) process.stderr.write("stderr: " + result.stderr.slice(0, 500) + "\n");
    process.exit(1);
  }

  const bocFiles = findBocFiles(absOut);
  process.stdout.write(`ok: ${bocFiles.length} output files\n`);
  process.exit(0);
}

main();
