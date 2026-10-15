# soken-fetch: sandboxed repository materializer (09 5.2), used by the repo fetch step only.
# Debian trixie for git 2.47 (GIT_NO_LAZY_FETCH from 2.45, S7). The materializer is
# src/soken_review/sandbox/git_materializer.py (standard library only); it sets the 5.2
# environment and config on every git call itself. Build from the repo root:
#   docker build -f docker/git-fetch/Dockerfile -t ghcr.io/soken-ltd/git-fetch:0.1.0-dev .
# debian:trixie-slim multi-arch index digest, pinned 2026-10-10.
FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates python3 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 10001 soken && useradd -u 10001 -g 10001 -M -s /usr/sbin/nologin soken \
    && git --version && python3 --version
COPY src/soken_review/sandbox/git_materializer.py /usr/local/bin/soken-fetch
RUN sed -i "1i #!/usr/bin/python3 -I" /usr/local/bin/soken-fetch && chmod 0755 /usr/local/bin/soken-fetch && soken-fetch --help >/dev/null
ENV GIT_TERMINAL_PROMPT=0 GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null HOME=/tmp
USER 10001:10001
WORKDIR /work
