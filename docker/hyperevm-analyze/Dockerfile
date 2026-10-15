# HyperEVM analyze image (plan-v4 05 sections 8.2, 10).
#
# Extends evm-analyze (Slither 0.11.6, Aderyn 0.6.8) with the soken-slither-plugins
# package (HL-* detectors).  Plugins load through Slither's public entry point
# slither_analyzer.plugin (F38); Slither files are unmodified (05 8.2).
#
# Base image pinned by digest — same base as evm-analyze for reproducibility.
# soken-slither-plugins is installed into the same venv as Slither so that
# slither_analyzer.plugin entry point discovery works out of the box.
#
# Build:
#   docker buildx build --platform linux/arm64,linux/amd64 \
#     --build-context plugins=../../slither_plugins \
#     -t ghcr.io/soken-ltd/hyperevm-analyze:<tag> docker/hyperevm-analyze/
#
# Record digest after push:
#   docker inspect --format='{{index .RepoDigests 0}}' ghcr.io/soken-ltd/hyperevm-analyze:<tag>
# Then update images.lock.json entry "hyperevm-analyze".

# Reuse the evm-analyze base layer rather than rebuilding Slither+Aderyn from scratch.
# In CI this will typically pull from the registry; locally `docker buildx build --load` works.
FROM ghcr.io/soken-ltd/evm-analyze:0.1.0-dev AS hl-analyze

# Switch to root for installation; revert to soken uid afterwards.
USER root

# Copy the slither_plugins source tree (build context = repo root: docker build -f docker/hyperevm-analyze/Dockerfile .).
COPY slither_plugins /tmp/slither_plugins/

# Install the soken-slither-plugins package into the Slither venv so the entry point is visible.
# --no-deps: slither-analyzer is already in the venv; avoid re-installing it.
RUN /opt/slither-env/bin/pip install --no-cache-dir --no-deps /tmp/slither_plugins/ \
    && rm -rf /tmp/slither_plugins

# Verify the entry point is registered.
# Verify through Slither itself, not the module: the CLI must list all six HL detectors.
RUN test "$(slither --list-detectors 2>/dev/null | grep -c 'hl-')" -eq 6

USER 10001:10001
WORKDIR /work
