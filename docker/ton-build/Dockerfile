# TON build/analyze image (plan v4 06 section 4.2, 4.4).
#
# Compilers baked in at pinned versions (all via npm, no native binaries):
#   FunC   @ton-community/func-js 0.10.0  (lockfile, orchestrator)
#          func-js-bin aliases: 0.2.0, 0.3.0, 0.4.0-0.4.6, 0.4.4-newops, 0.4.4-newops.1, 0.4.6-wasmfix.0
#   Tact   @tact-lang/compiler 1.6.13     (lockfile, default + Misti dep)
#          tact-* aliases: 1.4.0 through 1.6.13  (all npm-published releases)
#   Tolk   @ton/tolk-js 0.12.0 (WASM, lockfile, default)
#          tolk-* aliases: 0.6.0 through 1.5.0
#
# Versions source-of-truth: docker/ton-build/versions.json (baked at /opt/ton-node/versions.json)
# Mirrored in: src/soken_review/adapters/ton/build.py (TACT_VERSIONS, FUNC_VERSIONS, TOLK_VERSIONS)
#
# Analyzers:
#   Misti 0.9.0 (lockfile, symlinked to PATH)
#
# Runtime:
#   @ton/core 0.61.0, @ton/sandbox 0.45.0 (lockfile)
#
# Security (RULES.md "Images", coordinator review 2026-10-09):
#   - Base image pinned by digest (node:22-bookworm-slim)
#   - NO curl|bash: Node.js is the base image; no curl in apt-get
#   - No native binaries: all compilers are WASM/JS (no sha256 risk for binaries)
#   - All npm tools from package.json + package-lock.json via `npm ci --ignore-scripts`
#   - Non-root uid 10001
#   - No ENTRYPOINT: command passed by supervisor
#
# Build (from repo root as context):
#   docker buildx build --platform linux/amd64 \
#     -f docker/ton-build/Dockerfile \
#     -t ghcr.io/soken-ltd/ton-build:0.1.0-dev .
#
# After push, record digest and update images.lock.json:
#   docker inspect --format='{{index .RepoDigests 0}}' ghcr.io/soken-ltd/ton-build:<tag>

# node:22-bookworm-slim — official Node.js 22 LTS on Debian bookworm-slim.
# Digest pinned 2026-10-09 via:
#   docker manifest inspect node:22-bookworm-slim
#   → linux/amd64 manifest sha256:efd0ab5780c2d9ab1f0f869571a00d5edb17793bff4cce4a2792e3eb0ffc7562
#   (index manifest: sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392)
#
# For local arm64 dev (no Rosetta emulation):
#   docker build --build-arg BASE=node:22-bookworm-slim -f docker/ton-build/Dockerfile ...
ARG BASE=node:22-bookworm-slim@sha256:efd0ab5780c2d9ab1f0f869571a00d5edb17793bff4cce4a2792e3eb0ffc7562
FROM ${BASE} AS base

# System deps: ca-certificates only (no curl — no binaries to download)
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Non-root user uid 10001 (matches EVM analyze image convention, 09 4.2)
RUN groupadd -g 10001 soken && useradd -u 10001 -g 10001 -m -s /bin/false soken

# ── npm packages (lockfile-pinned, --ignore-scripts) ─────────────────────────
# package.json + package-lock.json live in docker/ton-build/.
# They include all compiler + analyzer + runtime npm packages.
# npm ci: installs exact versions from lockfile, fails if lockfile is out of date.
# --ignore-scripts: no post-install hooks from any package (security gate).

RUN mkdir -p /opt/ton-node && chown soken:soken /opt/ton-node
WORKDIR /opt/ton-node

COPY docker/ton-build/package.json docker/ton-build/package-lock.json ./

RUN npm ci --ignore-scripts

# Bake versions.json (source of truth, mirrors build.py constants)
COPY docker/ton-build/versions.json ./versions.json

# Symlink Misti CLI to PATH (installed into node_modules/.bin via lockfile)
RUN ln -sf /opt/ton-node/node_modules/.bin/misti /usr/local/bin/misti \
    && misti --version

# Verify all tact-* and tolk-* alias packages are present (fail-fast sanity check)
RUN node - <<'JS'
const fs = require('fs');
const v = JSON.parse(fs.readFileSync('/opt/ton-node/versions.json', 'utf8'));
let ok = true;
for (const ver of v.tact) {
  const pkg = '/opt/ton-node/node_modules/tact-' + ver + '/package.json';
  if (!fs.existsSync(pkg)) { process.stderr.write('MISSING tact-' + ver + '\n'); ok = false; }
}
for (const ver of v.tolk.filter(x => x !== 'latest')) {
  const pkg = '/opt/ton-node/node_modules/tolk-' + ver + '/package.json';
  if (!fs.existsSync(pkg)) { process.stderr.write('MISSING tolk-' + ver + '\n'); ok = false; }
}
if (!ok) process.exit(1);
process.stdout.write('version check ok: ' + v.tact.length + ' tact, ' + v.tolk.length + ' tolk\n');
JS

# Copy node_scripts from the adapter source (repo root is Docker build context)
COPY src/soken_review/adapters/ton/node_scripts/ /opt/ton-node/node_scripts/

# Work dir and cache mount point
RUN mkdir -p /cache /work && chown soken:soken /work

# Switch to non-root
USER 10001:10001
WORKDIR /work

# NODE_PATH allows node_scripts to resolve @ton/core etc. without their own node_modules
ENV NODE_PATH=/opt/ton-node/node_modules

# No ENTRYPOINT — supervisor passes the full command via docker run
