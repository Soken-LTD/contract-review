# aptos-prove: Move Prover backend sandbox image (plan v4 07 prover integration).
#
# Extends aptos-build with the Move Prover toolchain so `aptos move prove` runs
# fully offline (no network at container run time):
#   - z3 4.8.17  (Debian bookworm apt package; compatible with Move Prover)
#   - Boogie 3.4.3  (dotnet global tool; pinned version, nuget content-addressed)
#   - dotnet-sdk-8.0 (runtime for Boogie; Debian backports / Microsoft feed)
#
# Runtime contract (09 4.2, same as aptos-build):
#   uid 10001, read-only root fs, no network, HOME=/tmp, MOVE_HOME per job.
#   Mount layout: /work/src r/o, /work/out r/w, /work/move r/o.
#
# STAND NOTES (build and verify on x86 before pinning the digest):
#   1. dotnet-sdk-8.0 on Debian bookworm requires the Microsoft APT feed or
#      dotnet-sdk-8.0 from Debian 13 (trixie) backports.  The RUN block below
#      uses the Microsoft feed approach (script from packages.microsoft.com).
#      Alternatively, use the official debian-bookworm dotnet image as a base.
#   2. After building, run:
#        docker run --rm <tag> aptos move prove --version
#        docker run --rm <tag> z3 --version
#        docker run --rm <tag> boogie
#      and fill the digest in images.lock.json:
#        docker inspect --format='{{index .RepoDigests 0}}' <tag>
#   3. Trivy scan; block if Critical > 0 (images.yml gate).
#
# Build command (from repo root):
#   docker build --platform linux/amd64 \
#     -f docker/aptos-prove/Dockerfile \
#     -t ghcr.io/soken-ltd/aptos-prove:aptos-cli-v9.6.0-prove \
#     .
#
# aptos-build base digest is pinned here for reproducibility.
FROM ghcr.io/soken-ltd/aptos-build:aptos-cli-v9.6.0@sha256:096aa9b2d5356e13bf8aa23a4cebb216b734b1f004bae0dd8b7d454b9b3b1645

ARG BOOGIE_VERSION=3.4.3

# Switch to root for package installation.
USER root

# 1. z3: available in Debian bookworm as 'z3' (version 4.8.17).
RUN apt-get update \
    && apt-get install -y --no-install-recommends z3 ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# 2. dotnet-sdk-8.0: use the Microsoft packages feed for Debian bookworm.
#    The feed URL and package are pinned; verify gpg key on the stand.
RUN set -eu; \
    curl -fsSL https://packages.microsoft.com/config/debian/12/packages-microsoft-prod.deb \
        -o /tmp/packages-microsoft-prod.deb; \
    dpkg -i /tmp/packages-microsoft-prod.deb; \
    rm /tmp/packages-microsoft-prod.deb; \
    apt-get update \
    && apt-get install -y --no-install-recommends dotnet-sdk-8.0 \
    && rm -rf /var/lib/apt/lists/*

# 3. Boogie via dotnet global tool (nuget, content-addressed by version).
#    HOME=/root here (root user); boogie lands in /root/.dotnet/tools.
#    Symlink to /usr/local/bin so all users can find it in PATH.
RUN DOTNET_CLI_HOME=/root dotnet tool install --global Boogie --version ${BOOGIE_VERSION} \
    && ln -sf /root/.dotnet/tools/boogie /usr/local/bin/boogie \
    && boogie --version

# Smoke-tests: both tools must respond before we commit the image layer.
RUN z3 --version && boogie --version && aptos move prove --help > /dev/null

# Back to the sandboxed user.
USER 10001:10001

# Inherit ENV from aptos-build: HOME=/tmp, GIT_TERMINAL_PROMPT=0, APTOS_DISABLE_TELEMETRY=true
# Boogie needs DOTNET_* env at runtime; the aptos CLI resolves boogie via PATH (/usr/local/bin).
ENV DOTNET_NOLOGO=1 DOTNET_CLI_TELEMETRY_OPTOUT=1
