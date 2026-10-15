#!/usr/bin/env node
/**
 * ton_hash.mjs — compute the root code cell representation hash from a BoC.
 *
 * Usage:
 *   node ton_hash.mjs <boc_file>
 *   cat code.boc | node ton_hash.mjs
 *
 * Output: 64-char lowercase hex representation hash (plan v4 06 4.2, F reference pipeline).
 * Uses @ton/core 0.61.0 Cell.fromBoc and cell.hash().
 *
 * Exit 0 on success (hash on stdout), exit 1 on error (message on stderr).
 */
import { readFileSync } from "fs";
import { createRequire } from "module";

const require = createRequire(import.meta.url);

async function main() {
  let bocBytes;
  const arg = process.argv[2];
  if (arg) {
    bocBytes = readFileSync(arg);
  } else {
    // Read from stdin
    const chunks = [];
    for await (const chunk of process.stdin) {
      chunks.push(chunk);
    }
    bocBytes = Buffer.concat(chunks);
  }
  if (!bocBytes || bocBytes.length === 0) {
    process.stderr.write("ton_hash.mjs: empty input\n");
    process.exit(1);
  }

  let Cell;
  try {
    ({ Cell } = require("@ton/core"));
  } catch {
    // Try alternate package name
    try {
      const { Cell: C } = require("ton-core");
      Cell = C;
    } catch (e2) {
      process.stderr.write(`ton_hash.mjs: cannot load @ton/core: ${e2.message}\n`);
      process.exit(1);
    }
  }

  try {
    const cells = Cell.fromBoc(bocBytes);
    if (!cells || cells.length === 0) {
      process.stderr.write("ton_hash.mjs: Cell.fromBoc returned empty array\n");
      process.exit(1);
    }
    // Root cell hash (representation hash)
    const hashBuf = cells[0].hash();
    const hashHex = Buffer.isBuffer(hashBuf)
      ? hashBuf.toString("hex")
      : Buffer.from(hashBuf).toString("hex");
    process.stdout.write(hashHex + "\n");
    process.exit(0);
  } catch (e) {
    process.stderr.write(`ton_hash.mjs: ${e.message}\n`);
    process.exit(1);
  }
}

main();
