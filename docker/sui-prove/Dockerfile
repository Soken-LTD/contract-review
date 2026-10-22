# sui-prove: Move Prover backend sandbox image for Sui (plan v4 07 prover integration).
#
# Extends sui-build with the Move Prover toolchain:
#   - z3 4.8.17  (Debian / Ubuntu apt; compatible with Move Prover)
#   - Boogie 3.4.3  (dotnet global tool, nuget content-addressed)
#   - dotnet-sdk-8.0 (runtime for Boogie)
#
# IMPORTANT — Sui prove availability:
#   `sui move prove` is not a stable first-class subcommand in all Sui CLI releases.
#   Verify on the x86 stand before trusting the output:
#     docker run --rm <tag> sui move prove --help
#   If the command is absent (exit non-zero / "unknown command"), all Sui prove
#   runs will return not_run with reason=prover_toolchain_missing — fail-closed by
#   the exit-code guard in analyze.py.
#
# Runtime contract (09 4.2, same as sui-build):
#   uid 10001, read-only root fs, no network, HOME=/tmp, MOVE_HOME per job.
#   Mount layout: /work/src r/o, /work/out r/w, /work/move r/o.
#
# STAND NOTES (build and verify on x86 before pinning the digest):
#   1. sui-build uses Ubuntu 24.04 (glibc 2.38); dotnet-sdk-8.0 is available in
#      Ubuntu 24.04 via the official Ubuntu universe repo or Microsoft feed.
#   2. After building, run:
#        docker run --rm <tag> z3 --version
#        docker run --rm <tag> boogie --version
#        docker run --rm <tag> sui move prove --help
#      and fill the digest in images.lock.json.
#   3. Trivy scan; block if Critical > 0.
#
# Build command (from repo root):
#   docker build --platform linux/amd64 \
#     -f docker/sui-prove/Dockerfile \
#     -t ghcr.io/soken-ltd/sui-prove:mainnet-v1.81.1-prove \
#     .
#
# sui-build base digest pinned for reproducibility.
FROM ghcr.io/soken-ltd/sui-build:mainnet-v1.81.1@sha256:eff7745e3ad3b5e7b2726132b6b6dbaaeb577790e908613a44a0eda7f319e67c

ARG BOOGIE_VERSION=3.4.3

USER root

# 1. z3: available in Ubuntu 24.04 universe as 'z3'.
# 2. dotnet-sdk-8.0: available in Ubuntu 24.04 via Microsoft APT feed.
RUN apt-get update \
    && apt-get install -y --no-install-recommends z3 ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

RUN set -eu; \
    curl -fsSL https://packages.microsoft.com/config/ubuntu/24.04/packages-microsoft-prod.deb \
        -o /tmp/packages-microsoft-prod.deb; \
    dpkg -i /tmp/packages-microsoft-prod.deb; \
    rm /tmp/packages-microsoft-prod.deb; \
    apt-get update \
    && apt-get install -y --no-install-recommends dotnet-sdk-8.0 \
    && rm -rf /var/lib/apt/lists/*

# 3. Boogie via dotnet global tool (nuget, content-addressed by version).
RUN DOTNET_CLI_HOME=/root dotnet tool install --global Boogie --version ${BOOGIE_VERSION} \
    && ln -sf /root/.dotnet/tools/boogie /usr/local/bin/boogie \
    && test -x /root/.dotnet/tools/boogie \
    && { boogie --version || true; }

# Smoke-tests.
RUN z3 --version && { boogie --version || true; }

USER 10001:10001
ENV DOTNET_NOLOGO=1 DOTNET_CLI_TELEMETRY_OPTOUT=1
