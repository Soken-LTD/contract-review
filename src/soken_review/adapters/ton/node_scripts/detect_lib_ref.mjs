#!/usr/bin/env node
/**
 * detect_lib_ref.mjs — detect whether the root cell of a BoC is a library reference.
 *
 * Usage:
 *   node detect_lib_ref.mjs <boc_file>
 *
 * Output (JSON on stdout):
 *   {"is_library_ref": false}
 *   {"is_library_ref": true, "library_hash": "<64hex>"}
 *
 * A library ref cell is an exotic cell of type 2 with 256-bit hash data.
 * Uses @ton/core Cell.fromBoc (plan v4 06 4.3).
 * Exit 0 on success, exit 1 on error.
 *
 * Security: must NOT be called in the egress network step; library hash comes
 * from the local code BoC, not from a remote source.
 */
import { readFileSync } from "fs";
import { createRequire } from "module";

const require = createRequire(import.meta.url);

async function main() {
  const arg = process.argv[2];
  if (!arg) {
    process.stderr.write("detect_lib_ref.mjs: usage: <boc_file>\n");
    process.exit(1);
  }
  const bocBytes = readFileSync(arg);
  if (!bocBytes || bocBytes.length === 0) {
    process.stderr.write("detect_lib_ref.mjs: empty input\n");
    process.exit(1);
  }

  let Cell;
  try {
    ({ Cell } = require("@ton/core"));
  } catch {
    try {
      const { Cell: C } = require("ton-core");
      Cell = C;
    } catch (e2) {
      process.stderr.write(`detect_lib_ref.mjs: cannot load @ton/core: ${e2.message}\n`);
      process.exit(1);
    }
  }

  try {
    const cells = Cell.fromBoc(bocBytes);
    if (!cells || cells.length === 0) {
      process.stderr.write("detect_lib_ref.mjs: no cells in BoC\n");
      process.exit(1);
    }
    const root = cells[0];

    // isExotic and type() are available in @ton/core
    // type() === 2 means library reference
    let isLib = false;
    let libHash = null;

    if (typeof root.isExotic !== "undefined" && root.isExotic) {
      // Try to read the exotic type from the bits
      // Library ref: first 8 bits = 0x02
      try {
        const slice = root.beginParse(true); // allowExotics = true
        const exotic_type = slice.loadUint(8);
        if (exotic_type === 2) {
          // Next 256 bits are the library cell hash
          const hash_bits = slice.loadUintBig(256);
          libHash = hash_bits.toString(16).padStart(64, "0");
          isLib = true;
        }
      } catch (parseErr) {
        process.stderr.write(`detect_lib_ref.mjs: parse error: ${parseErr.message}\n`);
      }
    }

    const result = isLib
      ? { is_library_ref: true, library_hash: libHash }
      : { is_library_ref: false };
    process.stdout.write(JSON.stringify(result) + "\n");
    process.exit(0);
  } catch (e) {
    process.stderr.write(`detect_lib_ref.mjs: ${e.message}\n`);
    process.exit(1);
  }
}

main();
