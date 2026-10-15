# EVM analyze image (09 4.4, plan v4).
#
# Debian bookworm-slim base.  solc binaries are not baked in: they are
# mounted read-only from the supervisor cache at /cache (09 4.4).
#
# Tool versions pinned per 05 section 1:
#   Slither  0.11.6
#   Aderyn   0.6.8  (optional; built from cargo if available)
#
# Build for linux/arm64 and linux/amd64:
#   docker buildx build --platform linux/arm64,linux/amd64 \
#     -t ghcr.io/soken-ltd/evm-analyze:<tag> docker/evm-analyze/
#
# Record digest after push:
#   docker inspect --format='{{index .RepoDigests 0}}' ghcr.io/soken-ltd/evm-analyze:<tag>
# Then update images.lock.json.

FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587 AS base

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv \
        git curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user matching sandbox UID (09 4.2: uid 10001)
RUN groupadd -g 10001 soken && useradd -u 10001 -g 10001 -m -s /bin/false soken

# Install Slither 0.11.6 in a venv owned by root, readable by uid 10001
RUN python3 -m venv /opt/slither-env \
    && /opt/slither-env/bin/pip install --no-cache-dir \
        slither-analyzer==0.11.6 \
    && ln -s /opt/slither-env/bin/slither /usr/local/bin/slither

# Aderyn 0.6.8: release archive verified against the sha256 published with the release.
# Arch from dpkg, so the legacy builder (no TARGETARCH) installs it too.
RUN set -e; \
    case "$(dpkg --print-architecture)" in \
      amd64) triple=x86_64-unknown-linux-gnu; sum=ffd6ca658962e211a3ac821c646f69c8e14bf1b1001cbfe091bcd4535a691e46 ;; \
      arm64) triple=aarch64-unknown-linux-gnu; sum=961070bf5ee4ed0f82f67a261c616e1525ec1b036bae60cdaec94d087eb5e405 ;; \
      *) echo "unsupported arch" >&2; exit 1 ;; \
    esac; \
    apt-get update && apt-get install -y --no-install-recommends xz-utils && rm -rf /var/lib/apt/lists/*; \
    curl -fsSL -o /tmp/aderyn.tar.xz \
      "https://github.com/Cyfrin/aderyn/releases/download/aderyn-v0.6.8/aderyn-${triple}.tar.xz"; \
    echo "${sum}  /tmp/aderyn.tar.xz" | sha256sum -c -; \
    tar -xJf /tmp/aderyn.tar.xz -C /tmp; \
    install -m 755 "/tmp/aderyn-${triple}/aderyn" /usr/local/bin/aderyn; \
    rm -rf /tmp/aderyn*

# forge v1.8.5 (plan 05 B4: forge build --offline --build-info for repo candidates).
#
# sha256 values MUST be taken from the official release checksum file, never invented:
#   https://github.com/foundry-rs/foundry/releases/download/v1.8.5/
#   Download foundry_v1.8.5_linux_amd64.tar.gz and the corresponding .sha256 file,
#   then verify: sha256sum -c foundry_v1.8.5_linux_amd64.tar.gz.sha256
#
# Set these build args from the verified checksums before pushing to production:
#   docker build --build-arg FORGE_SHA256_AMD64=<real sha256> ...
ARG FORGE_VERSION=1.8.5
# PLACEHOLDER — replace with sha256 from the official release checksum file.
# The image build WILL FAIL until real values are supplied (sha256sum -c gate).
ARG FORGE_SHA256_AMD64=6c66ffcc55fa4249197721baa3098bc208014ea1d8aa04b2ed50ac6bccffb226
ARG FORGE_SHA256_ARM64=5bdce3dade8b6f0a65d4fccf6908426aee4905a988b08dce79d0a72fe7498310

RUN set -e; \
    apt-get update && apt-get install -y --no-install-recommends curl xz-utils && rm -rf /var/lib/apt/lists/*; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) triple=linux_amd64; sum=${FORGE_SHA256_AMD64} ;; \
      arm64) triple=linux_arm64; sum=${FORGE_SHA256_ARM64} ;; \
      *) echo "unsupported arch: $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/forge.tar.gz \
      "https://github.com/foundry-rs/foundry/releases/download/v${FORGE_VERSION}/foundry_v${FORGE_VERSION}_${triple}.tar.gz"; \
    echo "${sum}  /tmp/forge.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/forge.tar.gz -C /tmp forge; \
    install -m 755 /tmp/forge /usr/local/bin/forge; \
    rm -f /tmp/forge.tar.gz /tmp/forge; \
    forge --version

# /cache is a read-only mount for solc binaries (09 4.4).
# /work is a bind mount for the job directory.
RUN mkdir -p /cache /work && chown soken:soken /work

# Switch to non-root for image layers
USER 10001:10001
WORKDIR /work

# No ENTRYPOINT: command is passed by the supervisor via docker run
