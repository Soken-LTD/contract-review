# starknet-build: Scarb toolchain image for the Starknet deps, build and analyze steps (07 3.1, 8.2, 8.3).
#
# One image per Cairo version (07 3.1): SCARB_VERSION selects the release, its bundled Cairo compiler
# is the version decoded from the deployed class. Scarb ships the corelib inside the binary and
# writes it to SCARB_CACHE on first use, so every step mounts a per-candidate cache dir.
#
# Security properties (09 4.2):
#   - Base image pinned by digest; the Scarb tarball is checked against the release checksum
#   - Non-root user 10001:10001; read-only root fs at run time (docker_argv)
#   - No network in build and analyze (runsc-none); deps runs `scarb fetch` with egress only
#
# Build: docker build --build-arg SCARB_VERSION=2.13.1 --build-arg SCARB_SHA256_AMD64=... \
#          --build-arg SCARB_SHA256_ARM64=... -t soken/starknet-build:2.13.1 docker/starknet-build
# rust:1.90.0-slim-bookworm (index digest): Scarb runs `cargo` for Cairo procedural macros
# ([cairo-plugin] packages) in the workspace; deps runs `cargo fetch`, build compiles offline.
FROM rust@sha256:64232e656c058f4468e8d024e990acff04f0fd5a5c0a88a574dc37773d7325c9

ARG SCARB_VERSION=2.13.1
ARG SCARB_SHA256_AMD64=c3354866901254d1868dcff7b56bb68822ca54f6a522cf8671685b2448ccdf15
ARG SCARB_SHA256_ARM64=0a0a30e57d7255ac0ca5454d846758e5b5d2d4e15d9866d6095b71db95d21964

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl git \
    && rm -rf /var/lib/apt/lists/* \
    && chmod -R a+rX /usr/local/cargo /usr/local/rustup \
    && groupadd -g 10001 soken && useradd -u 10001 -g 10001 -M -s /usr/sbin/nologin soken

RUN set -eu; \
    case "$(uname -m)" in \
      x86_64) triple=x86_64-unknown-linux-gnu; sum="${SCARB_SHA256_AMD64}";; \
      aarch64) triple=aarch64-unknown-linux-gnu; sum="${SCARB_SHA256_ARM64}";; \
      *) echo "unsupported arch $(uname -m)"; exit 1;; \
    esac; \
    name="scarb-v${SCARB_VERSION}-${triple}"; \
    curl -fsSL -o /tmp/scarb.tgz "https://github.com/software-mansion/scarb/releases/download/v${SCARB_VERSION}/${name}.tar.gz"; \
    echo "${sum}  /tmp/scarb.tgz" | sha256sum -c -; \
    mkdir -p /opt/scarb; tar -xzf /tmp/scarb.tgz -C /opt/scarb --strip-components=1; rm /tmp/scarb.tgz; \
    chmod -R a+rX /opt/scarb

ENV PATH="/opt/scarb/bin:/usr/local/cargo/bin:${PATH}" RUSTUP_HOME=/usr/local/rustup HOME=/tmp SCARB_CACHE=/work/scarb-cache CARGO_HOME=/work/cargo-home \
    GIT_TERMINAL_PROMPT=0 \
    SOKEN_SCARB_VERSION=${SCARB_VERSION}
USER 10001:10001
WORKDIR /work
RUN scarb --version && cargo --version
