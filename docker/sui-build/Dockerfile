# sui-build: Sui Move build and lint sandbox image (plan v4 07 sections 3, 3.1, 6.2).
#
# One image per Sui toolchain version (07 3.1); this file builds the default pin
# mainnet-v1.81.1. The release tarball is verified against the sha256 digest GitHub publishes
# for the asset before anything is extracted; only the `sui` binary is kept.
#
# Framework packages (07 4: framework packages come from the image) are the sui repository
# `crates/sui-framework/packages` at the tag commit, fetched by commit id and checked with
# `git rev-parse`; they live at /opt/sui-framework.
#
# Runtime contract (09 4.2, RULES.md): uid 10001, read-only root fs, HOME=/tmp,
# MOVE_HOME is a per-job dir filled by the deps step (egress) and read by the build step (no
# network). git is present only for the deps step (Move git dependencies).
FROM debian@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587 AS fetch
ARG TARGETARCH
ARG SUI_TAG=mainnet-v1.81.1
ARG SUI_SHA256_AMD64=d921910fdedf5ae2bc3f08a7236c57819a457ce53a8cc60c85f3653c7831b5d4
ARG SUI_SHA256_ARM64=4c2d948417af9f55cdd1f2f5d8e558533502672004c34f6429aa6cb114a51583
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
RUN set -eu; \
    arch="${TARGETARCH:-$(dpkg --print-architecture)}"; case "$arch" in \
      amd64) asset="sui-${SUI_TAG}-ubuntu-x86_64.tgz"; sum="$SUI_SHA256_AMD64" ;; \
      arm64) asset="sui-${SUI_TAG}-ubuntu-aarch64.tgz"; sum="$SUI_SHA256_ARM64" ;; \
      *) echo "unsupported arch $arch"; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/sui.tgz "https://github.com/MystenLabs/sui/releases/download/${SUI_TAG}/${asset}"; \
    echo "${sum}  /tmp/sui.tgz" | sha256sum -c -; \
    mkdir /tmp/x && tar -xzf /tmp/sui.tgz -C /tmp/x ./sui; \
    bin="$(find /tmp/x -type f -name sui | head -n1)"; \
    install -m 0755 "$bin" /usr/local/bin/sui; \
    rm -rf /tmp/x /tmp/sui.tgz
ARG SUI_COMMIT=e04cf9aa915cb6c069092733bebc3648755998e2
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*
RUN set -eu; \
    git init -q /tmp/sui && cd /tmp/sui; \
    git remote add origin https://github.com/MystenLabs/sui.git; \
    git sparse-checkout set --no-cone /crates/sui-framework/packages; \
    git fetch -q --depth 1 --filter=blob:none origin "$SUI_COMMIT"; \
    git checkout -q FETCH_HEAD; \
    test "$(git rev-parse HEAD)" = "$SUI_COMMIT"; \
    mkdir -p /opt/sui-framework; \
    cp -r crates/sui-framework/packages/. /opt/sui-framework/; \
    printf '%s\n' "$SUI_COMMIT" > /opt/sui-framework/COMMIT

# Runtime: the release binary needs glibc 2.38 (Ubuntu 24.04); bookworm has 2.36.
FROM ubuntu@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates libssl3t64 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 10001 soken && useradd -u 10001 -g 10001 -M -s /usr/sbin/nologin soken
COPY --from=fetch /usr/local/bin/sui /usr/local/bin/sui
COPY --from=fetch /opt/sui-framework /opt/sui-framework
RUN chmod -R a+rX /opt/sui-framework
ENV HOME=/tmp GIT_TERMINAL_PROMPT=0 GIT_CONFIG_NOSYSTEM=1 SUI_SKIP_UPDATE_CHECK=1
USER 10001:10001
WORKDIR /work
RUN sui --version && ls /opt/sui-framework
