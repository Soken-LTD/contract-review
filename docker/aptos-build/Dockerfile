# aptos-build: Aptos Move compile and lint sandbox image (plan v4 07 sections 3, 7.2).
#
# Pin aptos-cli-v9.6.0. The release zip is verified against the sha256 digest GitHub publishes
# for the asset. Licence: aptos-core "Innovation-Enabling Source Code License" (U-21).
#
# Framework packages (07 7.1.4: deps at 0x1, 0x3, 0x4 come from the image) are the sources of
# aptos-core at the tag commit, fetched by commit id (content addressed) and checked with
# `git rev-parse`. The on-chain registry copy of the framework omits the `.spec.move` files the
# inline specs refer to, so it does not type-check; the image copy does.
#
# Runtime contract (09 4.2, RULES.md): uid 10001, read-only root fs, HOME=/tmp, MOVE_HOME per
# job (deps step with egress, compile without network).
FROM debian@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587 AS fetch
ARG TARGETARCH
ARG APTOS_VERSION=9.6.0
ARG APTOS_COMMIT=07490157d3250932a385010878a3c5ae7c1338bb
ARG APTOS_SHA256_AMD64=4e28e71659a53e8eacff29d127685f2f282a8c008ff6e51047daedc72576bb8d
ARG APTOS_SHA256_ARM64=8e26f9ec373247c469c87c5e0003158eea58c68bf94ff03b74d78870cdfa1cbe
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl unzip git \
    && rm -rf /var/lib/apt/lists/*
RUN set -eu; \
    arch="${TARGETARCH:-$(dpkg --print-architecture)}"; case "$arch" in \
      amd64) asset="aptos-cli-${APTOS_VERSION}-Linux-x86_64.zip"; sum="$APTOS_SHA256_AMD64" ;; \
      arm64) asset="aptos-cli-${APTOS_VERSION}-Linux-aarch64.zip"; sum="$APTOS_SHA256_ARM64" ;; \
      *) echo "unsupported arch $arch"; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/aptos.zip "https://github.com/aptos-labs/aptos-core/releases/download/aptos-cli-v${APTOS_VERSION}/${asset}"; \
    echo "${sum}  /tmp/aptos.zip" | sha256sum -c -; \
    unzip -q /tmp/aptos.zip -d /tmp/x; \
    install -m 0755 /tmp/x/aptos /usr/local/bin/aptos; \
    rm -rf /tmp/x /tmp/aptos.zip
RUN set -eu; \
    git init -q /tmp/core && cd /tmp/core; \
    git remote add origin https://github.com/aptos-labs/aptos-core.git; \
    git sparse-checkout set --no-cone /aptos-move/framework/move-stdlib /aptos-move/framework/aptos-stdlib \
      /aptos-move/framework/aptos-framework /aptos-move/framework/aptos-token /aptos-move/framework/aptos-token-objects; \
    git fetch -q --depth 1 --filter=blob:none origin "$APTOS_COMMIT"; \
    git checkout -q FETCH_HEAD; \
    test "$(git rev-parse HEAD)" = "$APTOS_COMMIT"; \
    mkdir -p /opt/aptos-framework; \
    for p in move-stdlib aptos-stdlib aptos-framework aptos-token aptos-token-objects; do \
      cp -r "aptos-move/framework/$p" /opt/aptos-framework/; \
    done; \
    printf '%s\n' "$APTOS_COMMIT" > /opt/aptos-framework/COMMIT

FROM debian@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 10001 soken && useradd -u 10001 -g 10001 -M -s /usr/sbin/nologin soken
COPY --from=fetch /usr/local/bin/aptos /usr/local/bin/aptos
COPY --from=fetch /opt/aptos-framework /opt/aptos-framework
RUN chmod -R a+rX /opt/aptos-framework
ENV HOME=/tmp GIT_TERMINAL_PROMPT=0 GIT_CONFIG_NOSYSTEM=1 APTOS_DISABLE_TELEMETRY=true
USER 10001:10001
WORKDIR /work
RUN aptos --version && ls /opt/aptos-framework
