# starknet-caracal: Caracal static-analyzer backend image (depth, Starknet second engine).
#
# Extends starknet-build with Caracal (crytic/caracal), a static analyzer over the SIERRA
# representation of Starknet contracts (the Cairo analogue of Slither). It runs beside
# `scarb lint` + soken-cairo-rules as a second engine in the analyze step, fully offline
# at container run time (no network):
#   - caracal 0.2.3  (pinned release binary, sha256-verified; linux/amd64 only)
#
# Caracal in Scarb mode reuses the Scarb-produced SIERRA, so the Scarb toolchain and the
# already-fetched scarb-cache (mounted from the build step) are all it needs — no corelib
# or network. The reviewed Scarb.toml must declare `[[target.starknet-contract]] sierra = true`
# and `[cairo] sierra-replace-ids = true`; projects without that config make `caracal detect`
# exit non-zero and the adapter marks the tool not_run (analyzer_failed), never "no findings".
#
# Runtime contract (09 4.2, same as starknet-build):
#   uid 10001, read-only root fs, no network, HOME=/tmp.
#   Mount layout: /work/tree r/w (scratch), /work/scarb-cache r/w, /work/cargo-home r/w,
#   /work/output r/w (SCARB_TARGET_DIR).
#
# STAND NOTES (build and verify on x86 before pinning the digest):
#   1. caracal ships a linux x86_64 release only; this image is linux/amd64 (as are all
#      analyze images). In Scarb mode the Scarb-built SIERRA is what caracal reads, but it
#      reads it through the cairo-lang-sierra crate its Cargo.lock pins (2.5.0 for v0.2.3,
#      Sierra 1.4.0): a class compiled by Cairo 2.6 or later (Sierra >= 1.5) makes its
#      ProgramRegistry panic (stand 2026-10-23, OZ presets at Cairo 2.13.1:
#      `UnsupportedId("Const")`, exit 101). images.lock.json `tools` records that ceiling
#      (`cairo-lang`, `sierra`) and the analyze step gates on it before caracal's own build.
#   2. After building, run:
#        docker run --rm <tag> caracal --version
#        docker run --rm <tag> caracal detectors
#      and fill the digest in images.lock.json:
#        docker inspect --format='{{index .RepoDigests 0}}' <tag>
#   3. Trivy scan; block if Critical > 0 (images.yml gate).
#
# Build command (from repo root):
#   docker build --platform linux/amd64 \
#     -f docker/starknet-caracal/Dockerfile \
#     -t ghcr.io/soken-ltd/starknet-caracal:0.1.0-dev \
#     .
#
# starknet-build base digest is pinned here for reproducibility; scripts/images.py overrides
# it at CI build time with the freshly pushed starknet-build digest (--build-context), so a
# dependant never builds on a floating tag.
FROM ghcr.io/soken-ltd/starknet-build:0.1.0-dev@sha256:5d6f6ab827cdf5f5f6ced8424c4373b3dbb50226346d8bb6fdc796a5ce460a86

ARG CARACAL_VERSION=0.2.3
ARG CARACAL_SHA256_AMD64=50d1b2b011313866ef6bc195c053cbcc7e182cf7821aa8d27aa135569e8c0c65

# Switch to root for the install.
USER root

# Pinned release binary (sha256-verified, same pattern as the scarb tarball). The archive
# holds a single `caracal` executable; linux x86_64 is the only published asset.
RUN set -eu; \
    case "$(uname -m)" in \
      x86_64) sum="${CARACAL_SHA256_AMD64}";; \
      *) echo "caracal ships no release for $(uname -m); build this image on linux/amd64"; exit 1;; \
    esac; \
    curl -fsSL -o /tmp/caracal.tgz \
      "https://github.com/crytic/caracal/releases/download/v${CARACAL_VERSION}/caracal-v${CARACAL_VERSION}-linux.tar.gz"; \
    echo "${sum}  /tmp/caracal.tgz" | sha256sum -c -; \
    tar -xzf /tmp/caracal.tgz -C /usr/local/bin caracal; \
    rm /tmp/caracal.tgz; \
    chmod a+rx /usr/local/bin/caracal

# Smoke-test: the binary must respond before we commit the image layer.
RUN caracal --version && caracal detectors > /dev/null

# Back to the sandboxed user.
USER 10001:10001

# Inherit ENV from starknet-build (PATH incl. /opt/scarb/bin and cargo, HOME=/tmp,
# SCARB_CACHE, CARGO_HOME, GIT_TERMINAL_PROMPT=0).
ENV SOKEN_CARACAL_VERSION=${CARACAL_VERSION}
