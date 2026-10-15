# soken-sbx-solana: Solana build image per version line, and the analysis image (06 3.3.1, 09 4.2)
#
#   target build    one per Solana version line, FROM the upstream solana-verifiable-build image of
#                   that version (pinned by digest in src/soken_review/adapters/solana/data/image_map.json):
#                   the same toolchain, platform-tools, W and CARGO_HOME as `solana-verify build`, so a
#                   sandbox build reproduces its program hash (U-S1). Adds clippy (06 3.4 runs clippy in
#                   the build image).
#   target analyze  FROM build on 4.3.0: adds cargo-audit and Python 3 (06 3.4).
#
#   docker build --build-arg BASE_IMAGE=<repo@digest> --build-arg ACTIVE_TOOLCHAIN=<toolchain> \
#                --target build -t <tag> docker/solana-build
#   (`python -m soken_review.adapters.solana.images build-args <version>` prints both values)
#
# Runtime contract (src/soken_review/adapters/solana/build.py):
#   - runs as 10001:10001, read-only root fs, no network for build (runsc-none)
#   - the per-candidate crate dir is mounted over CARGO_HOME, so cargo binaries live in
#     /opt/soken/cargo-bin (first in PATH) and CARGO_HOME stays the upstream path: registry sources
#     sit where solana-verify puts them (panic strings embed them)
#   - HOME stays the upstream home (/root) where the image's platform-tools and the `solana` rustup
#     toolchain link live; made readable for uid 10001, never writable

ARG BASE_IMAGE=solanafoundation/solana-verifiable-build:4.3.0@sha256:12fd4c0a0790f0fc41ef74b0cdb6bccc167ba6137eb1adb749bac649481c86bd

FROM ${BASE_IMAGE} AS build
# Default matches the default BASE_IMAGE (4.3.0). Overridden per version via --build-arg
# (solana-e2e / the per-version publish flow); the assertion below still pins active==declared.
ARG ACTIVE_TOOLCHAIN=1.97.1-x86_64-unknown-linux-gnu
USER root
# The toolchain the map records is the one solana-verify will read with `rustup show active-toolchain`.
RUN set -eux; \
    active="$(cd / && rustup show active-toolchain | cut -d' ' -f1)"; \
    echo "active toolchain: $active"; \
    test -n "${ACTIVE_TOOLCHAIN}" && test "$active" = "${ACTIVE_TOOLCHAIN}"; \
    rustup component add clippy --toolchain "$active"; \
    command -v cargo-build-sbf; cargo-build-sbf --version; \
    # Warm-up build as the image user: cargo-build-sbf installs (1.18: downloads) its platform-tools and
    # links the rustup toolchain now, so the offline sandbox build finds them and relinks nothing.
    cargo init -q --lib /tmp/warm && cd /tmp/warm && printf '[lib]\ncrate-type = ["cdylib", "lib"]\n' >> Cargo.toml \
      && CARGO_HOME=/tmp/warm-cargo cargo build-sbf && cd / && rm -rf /tmp/warm /tmp/warm-cargo; \
    rustup toolchain list -v; \
    mkdir -p /opt/soken/bin; \
    cp -a "$CARGO_HOME/bin" /opt/soken/cargo-bin; \
    sbfrust="$(rustup toolchain list -v | awk '$1 ~ /sbpf-solana/ {print $NF}' | tail -n1)"; \
    test -n "$sbfrust" || sbfrust="$(rustup toolchain list -v | awk '$1 == "solana" {print $NF}')"; \
    echo "sbf toolchain: $sbfrust"; \
    test -x "$sbfrust/bin/cargo"; \
    printf '#!/bin/sh\n# cargo of the platform-tools cargo-build-sbf links (deps fetch with the build cargo, U-S1).\nexport PATH="%s/bin:$PATH"\nexec "%s/bin/cargo" "$@"\n' "$sbfrust" "$sbfrust" > /opt/soken/bin/sbf-cargo; \
    chmod 755 /opt/soken/bin/sbf-cargo; \
    for f in config config.toml credentials credentials.toml; do test ! -e "$CARGO_HOME/$f"; done; \
    chmod -R a+rX /opt/soken "$RUSTUP_HOME" /root; \
    chmod a+rx /root
ENV PATH="/opt/soken/bin:/opt/soken/cargo-bin:${PATH}"
USER 10001:10001
WORKDIR /build
# Smoke test as the sandbox user with the image's HOME and a fresh empty CARGO_HOME.
RUN set -eux; \
    export HOME=/root CARGO_HOME=/tmp/smoke-cargo; \
    rustc --version; cargo-build-sbf --version; cargo clippy --version; sbf-cargo --version; \
    rm -rf /tmp/smoke-cargo

FROM build AS analyze
ARG CARGO_AUDIT_VERSION=0.22.2
USER root
# cargo-audit from crates.io, --locked against the pinned version (change here and images.lock.json).
RUN CARGO_HOME=/tmp/audit-cargo cargo install cargo-audit --version "${CARGO_AUDIT_VERSION}" --locked \
        --root /usr/local 2>&1 | tail -5 \
    && rm -rf /tmp/audit-cargo \
    && cargo-audit --version
# Security updates of the Debian base (Trivy gate, 09 4.4); toolchains are untouched.
RUN apt-get update -qq \
    && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq \
    && apt-get install -y --no-install-recommends python3 python3-yaml \
    && rm -rf /var/lib/apt/lists/*
USER 10001:10001
WORKDIR /build
RUN cargo-audit --version
