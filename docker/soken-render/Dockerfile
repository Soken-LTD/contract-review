# soken-render (plan v4 08 3.2, 09 3.1): report kit build, paged.js in headless Chrome, poppler checks.
# Runs under runsc-none with no network, read-only root, /tmp tmpfs, uid 10001.
#
# linux/amd64: pinned chrome-headless-shell from Chrome for Testing (sha256 below, computed
#   2026-10-10 from the CfT download; CfT publishes no checksum).
# linux/arm64 (local colima only): Debian bookworm `chromium`, because CfT ships no linux-arm64
#   build. U8-1 (headless shell paginates like full Chrome) is settled on amd64.
#
# Build (root context):
#   docker build -f docker/soken-render/Dockerfile -t ghcr.io/soken-ltd/soken-render:0.1.0-dev .

FROM node:22-bookworm-slim@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392 AS node

FROM python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258

ARG CHS_VERSION=155.0.8059.39
ARG CHS_SHA256=39dcb8c46550632a3d911850ab3b8af840b4e3f6d8622faa2018eb8756278786

COPY --from=node /usr/local/bin/node /usr/local/bin/node

# poppler-utils for pdfinfo, pdffonts, pdftotext. No font packages: every glyph comes from the
# embedded kit fonts; a fallback font would fail the pdffonts check (08 3.2).
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends poppler-utils ca-certificates curl unzip; \
    if [ "$(dpkg --print-architecture)" = "amd64" ]; then \
      apt-get install -y --no-install-recommends libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 \
        libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libgbm1 libasound2 \
        libpango-1.0-0 libcairo2 libdbus-1-3 libexpat1 libx11-6 libxcb1 libxext6 fontconfig; \
      curl -fsSL -o /tmp/chs.zip "https://storage.googleapis.com/chrome-for-testing-public/${CHS_VERSION}/linux64/chrome-headless-shell-linux64.zip"; \
      echo "${CHS_SHA256}  /tmp/chs.zip" | sha256sum -c -; \
      unzip -q /tmp/chs.zip -d /opt; rm /tmp/chs.zip; \
      ln -s /opt/chrome-headless-shell-linux64/chrome-headless-shell /usr/local/bin/chrome; \
    else \
      apt-get install -y --no-install-recommends chromium fontconfig; \
      ln -s /usr/bin/chromium /usr/local/bin/chrome; \
    fi; \
    apt-get purge -y curl unzip; apt-get autoremove -y; rm -rf /var/lib/apt/lists/*; \
    pip install --no-cache-dir jsonschema==4.26.0 pyyaml==6.0.3; \
    groupadd -g 10001 soken; useradd -u 10001 -g 10001 -M -s /usr/sbin/nologin soken

COPY contract /opt/app/contract
COPY src/soken_review /opt/app/src/soken_review

ENV PYTHONPATH=/opt/app/src PYTHONDONTWRITEBYTECODE=1 CHROME_BIN=/usr/local/bin/chrome HOME=/tmp TMPDIR=/tmp
USER 10001:10001
WORKDIR /work
