#!/usr/bin/env node
/**
 * compile_func.mjs — compile a FunC contract to code cell BoC.
 *
 * Usage:
 *   node compile_func.mjs <version> <entry_fc_path> <output_boc_path> [<root-dir>] [<targets.json>]
 *
 * Uses @ton-community/func-js 0.10.0 FuncCompiler with the func-js-bin of <version>, installed
 * as the npm alias `func-<version>` (the verifier compiler worker's versions, F32). "latest" is
 * the func-js default bin. An unknown version exits 1; there is no fallback.
 *
 * <targets.json>: a JSON list of source paths (relative to root-dir) passed as func targets in
 * that order, exactly as the verifier compiler worker does for a bundle (`include_in_command`).
 * With it, no stdlib is injected and no file is selected heuristically.
 * All .fc files in the same directory as <entry_fc_path> are included as sources
 * so that #include directives resolve correctly.
 *
 * Stdlib note: @ton-community/func-js 0.10.0 does NOT auto-include stdlib.fc —
 * it must be supplied explicitly.  We inject the standard TON stdlib from the
 * @tact-lang/compiler package (same image) under every path variant that
 * projects commonly use (#include "stdlib.fc", "imports/stdlib.fc", etc.).
 * Exit 0 on success, exit 1 on error.
 */
import { existsSync, readFileSync, writeFileSync, readdirSync } from "fs";
import { dirname, resolve, relative, join } from "path";
import { createRequire } from "module";

const require = createRequire(import.meta.url);

// Probe known stdlib.fc locations (from packages bundled in the same image).
// @tact-lang/compiler bundles the standard TON stdlib at a predictable path.
const _STDLIB_PROBE_PATHS = [
  "/opt/ton-node/node_modules/@tact-lang/compiler/dist/stdlib/stdlib/std/stdlib.fc",
];

function loadBundledStdlib() {
  for (const p of _STDLIB_PROBE_PATHS) {
    if (existsSync(p)) {
      try { return readFileSync(p, "utf8"); } catch (_) { /* skip */ }
    }
  }
  return null;
}

// Canonical prefixes under which projects #include stdlib.
const _STDLIB_INCLUDE_NAMES = [
  "stdlib.fc",
  "imports/stdlib.fc",
  "lib/stdlib.fc",
];

async function main() {
  // argv: <version> <entry.fc> <out.boc> [<root-dir>]
  // root-dir (optional): directory from which relative filenames are computed and
  //   from which the full source tree is collected.  Defaults to dirname(entry).
  //   Pass the mounted sources root (e.g. /work/src) when the project has files
  //   in sibling or parent directories of the entry file (e.g. ../stdlib.fc).
  const [version, entryPath, outPath, rootDirArg, targetsArg] = process.argv.slice(2);
  if (!version || !entryPath || !outPath) {
    process.stderr.write("compile_func.mjs: usage: <version> <entry.fc> <out.boc> [root-dir]\n");
    process.exit(1);
  }

  // Load the func-js compiler for exactly this version
  let compileFunc;
  try {
    const funcJs = require("@ton-community/func-js");
    if (version === "latest") {
      compileFunc = funcJs.compileFunc;
    } else {
      if (!/^[0-9][0-9A-Za-z.-]{0,40}$/.test(version)) throw new Error(`bad version ${version}`);
      const compiler = new funcJs.FuncCompiler(require(`func-${version}`).object);
      compileFunc = compiler.compileFunc;
    }
  } catch (e) {
    process.stderr.write(`compile_func.mjs: unsupported_toolchain: cannot load func ${version}: ${e.message}\n`);
    process.exit(1);
  }

  const absEntry = resolve(entryPath);
  // rootDir: base for filename resolution and file collection.
  // When a project places stdlib.fc at the repo root and the entry is in a subdir
  // (e.g. ft/jetton-minter.fc), rootDir must be the repo root, not the subdir.
  const rootDir = rootDirArg ? resolve(rootDirArg) : dirname(absEntry);

  // Build sources array: collect all .fc files from rootDir recursively.
  // Filenames are relative to rootDir so that multi-target paths match the project
  // layout (e.g. "ft/jetton-minter.fc", "stdlib.fc").
  const sources = [];
  function collectFcFiles(dir) {
    try {
      for (const name of readdirSync(dir, { withFileTypes: true })) {
        const fullPath = join(dir, name.name);
        if (name.isFile() && (name.name.endsWith(".fc") || name.name.endsWith(".func"))) {
          try {
            const content = readFileSync(fullPath, "utf8");
            // Use path relative to rootDir as the filename for #include resolution
            const relPath = relative(rootDir, fullPath);
            sources.push({ filename: relPath, content });
          } catch (_) { /* skip unreadable */ }
        } else if (name.isDirectory()) {
          collectFcFiles(fullPath);
        }
      }
    } catch (_) { /* skip unreadable dir */ }
  }
  collectFcFiles(rootDir);

  // Ensure entry file is in sources (may already be there)
  const entryRel = relative(rootDir, absEntry);
  const alreadyAdded = sources.some((s) => s.filename === entryRel);
  if (!alreadyAdded) {
    sources.push({ filename: entryRel, content: readFileSync(absEntry, "utf8") });
  }

  if (targetsArg) {
    // Verifier bundle mode: exact targets, exact sources, nothing injected.
    const targets = JSON.parse(readFileSync(targetsArg, "utf8"));
    if (!Array.isArray(targets) || targets.length === 0 || !targets.every((t) => typeof t === "string")) {
      process.stderr.write("compile_func.mjs: targets.json must be a non-empty list of paths\n");
      process.exit(1);
    }
    const map = {};
    for (const s of sources) map[s.filename] = s.content;
    try {
      const r = await compileFunc({ sources: map, targets });
      if (r.status === "error") {
        process.stderr.write(`compile_func.mjs: compilation error: ${r.message}\n`);
        process.exit(1);
      }
      const buf = Buffer.from(r.codeBoc, "base64");
      writeFileSync(outPath, buf);
      process.stdout.write(`ok: ${buf.length} bytes\n`);
      process.exit(0);
    } catch (e) {
      process.stderr.write(`compile_func.mjs: ${e.message}\n`);
      process.exit(1);
    }
  }

  // @ton-community/func-js 0.10.0 does NOT auto-include stdlib.fc — the project
  // must either #include it explicitly or we must inject it.
  //
  // Strategy:
  //  1. Load the bundled TON stdlib from the image (self-contained, no sub-includes).
  //  2. Register it under every common include path variant so that projects that
  //     DO have `#include "imports/stdlib.fc"` resolve it correctly.
  //  3. If NO source file includes stdlib at all (e.g. older token-contract style
  //     written for the standalone func binary that auto-applies stdlib as a prelude),
  //     create a synthetic wrapper entry: `#include "stdlib.fc"; #include "entry.fc";`
  //     This ensures stdlib is applied exactly once.
  const stdlibContent = loadBundledStdlib();
  if (stdlibContent === null) {
    process.stderr.write("compile_func.mjs: warning: bundled stdlib not found, compilation may fail if stdlib is not in repo\n");
  }
  let compilationTarget = entryRel;

  if (stdlibContent) {
    const existingNames = new Set(sources.map((s) => s.filename));
    for (const stdlibName of _STDLIB_INCLUDE_NAMES) {
      if (!existingNames.has(stdlibName)) {
        sources.push({ filename: stdlibName, content: stdlibContent });
      }
    }

    // Check if ANY source file already includes stdlib (any variant).
    const stdlibIncludePatterns = _STDLIB_INCLUDE_NAMES.map((n) => `"${n}"`).concat(
      _STDLIB_INCLUDE_NAMES.map((n) => `'${n}'`)
    );
    const anyFileIncludesStdlib = sources.some((s) =>
      stdlibIncludePatterns.some((pat) => s.content.includes(pat))
    );

    if (!anyFileIncludesStdlib) {
      // No file includes stdlib and no cross-file #includes.  This is the multi-file
      // compilation model: all .fc files are passed as separate arguments to `func`,
      // which does a two-pass symbol collection (all signatures first, bodies second)
      // so forward references across files work.
      //
      // We replicate that by passing stdlib + all project files as multiple `targets`.
      // func-js forwards them to the WASM binary in order — same as the CLI.
      //
      // Strategy (safe subset — avoid duplicate-definition errors):
      //   Important: contract repos often have MULTIPLE standalone contracts in one dir
      //   (e.g. jetton-minter.fc and jetton-wallet.fc both defining equal_slices).
      //   Including all of them causes "previous type of function" errors.
      //
      //   Safe subset for any entry file:
      //     tier 0: pure constant/opcode files (never conflict)
      //     tier 1: exact "params" name (foundational, no duplicates)
      //     tier 9: entry file ONLY from the "contract" tiers
      //
      //   All other files (tier 2+, non-entry) are excluded — they are separate
      //   standalone contracts or helpers that duplicate the entry's helper functions.
      // entrySubdir: the directory component of the entry path relative to rootDir.
      // Support files (tier 0-2) are restricted to this same directory to avoid
      // pulling in op-codes.fc / params.fc / utils.fc from sibling contract directories
      // (e.g. nft/ vs ft/) which would cause duplicate-definition errors.
      const entrySubdir = entryRel.includes("/")
        ? entryRel.split("/").slice(0, -1).join("/")
        : "";

      function fileTier(filename) {
        if (filename === entryRel) return 9;
        const base = filename.split("/").pop().toLowerCase().replace(/\.(fc|func)$/, "");
        // tier 0: pure opcode/constant files — never conflict across contracts
        if (/^op[_-]?codes?$/.test(base) || base === "opcodes" || base === "op") return 0;
        // tier 1: foundational parameter/config files — single instance per repo
        if (base === "params") return 1;
        // tier 2: shared utility files — helper functions used by multiple contracts;
        //   examples: jetton-utils.fc, utils.fc, helpers.fc, common.fc
        //   These do NOT redefine contract-level functions, so including them is safe.
        if (/utils?$/.test(base) || base === "helpers" || base === "common") return 2;
        return 99; // exclude: standalone contract files that duplicate entry's helpers
      }

      const supportFiles = sources.filter((s) => {
        if (_STDLIB_INCLUDE_NAMES.includes(s.filename)) return false;
        if (s.filename === entryRel) return true;  // always include the entry itself
        if (fileTier(s.filename) > 2) return false;
        // Restrict tier 0-2 support files to the same subdir as the entry.
        // This prevents including nft/op-codes.fc when compiling ft/jetton-minter.fc.
        const fileSubdir = s.filename.includes("/")
          ? s.filename.split("/").slice(0, -1).join("/")
          : "";
        return fileSubdir === entrySubdir;
      });
      supportFiles.sort((a, b) => {
        const ta = fileTier(a.filename);
        const tb = fileTier(b.filename);
        if (ta !== tb) return ta - tb;
        return a.filename.localeCompare(b.filename);
      });
      // stdlib first, then support files, then entry
      const multiTargets = ["stdlib.fc", ...supportFiles.map((s) => s.filename)];
      process.stderr.write(`compile_func.mjs: multi-target: [${multiTargets.join(", ")}]\n`);

      try {
        const r2 = await compileFunc({ sources, targets: multiTargets });
        if (r2.status === "error") {
          process.stderr.write(`compile_func.mjs: compilation error: ${r2.message}\n`);
          process.exit(1);
        }
        const buf2 = Buffer.from(r2.codeBoc, "base64");
        writeFileSync(outPath, buf2);
        process.stdout.write(`ok: ${buf2.length} bytes\n`);
        process.exit(0);
      } catch (e) {
        process.stderr.write(`compile_func.mjs: ${e.message}\n`);
        if (e.stack) process.stderr.write(e.stack + "\n");
        process.exit(1);
      }
    }
  }

  try {
    const result = await compileFunc({
      sources,
      targets: [compilationTarget],
    });
    if (result.status === "error") {
      process.stderr.write(`compile_func.mjs: compilation error: ${result.message}\n`);
      process.exit(1);
    }
    // result.codeBoc is a base64-encoded BoC
    const bocBuffer = Buffer.from(result.codeBoc, "base64");
    writeFileSync(outPath, bocBuffer);
    process.stdout.write(`ok: ${bocBuffer.length} bytes\n`);
    process.exit(0);
  } catch (e) {
    process.stderr.write(`compile_func.mjs: ${e.message}\n`);
    if (e.stack) process.stderr.write(e.stack + "\n");
    process.exit(1);
  }
}

main();
