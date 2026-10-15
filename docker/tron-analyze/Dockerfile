# TRON analyze image (plan-v4 05 sections 8.2, F23).
#
# Extends evm-analyze (Slither 0.11.6) with the soken-slither-plugins package
# which registers the TRON shim via the slither_analyzer.plugin entry point.
# When Slither starts it calls make_plugin() -> apply_tron_shim(), patching
# ElementaryTypeName and SOLIDITY_VARIABLES_COMPOSED before any source is parsed.
# This fixes F23: Slither crashes with NonElementaryType on trcToken, msg.tokenid,
# msg.tokenvalue in TRON Solidity contracts.
#
# Identical base image as hyperevm-analyze so both images share the same layer cache.
#
# Build:
#   docker buildx build --platform linux/arm64,linux/amd64 \
#     --build-context plugins=../../slither_plugins \
#     -t ghcr.io/soken-ltd/tron-analyze:<tag> docker/tron-analyze/
#   # or from repo root:
#   docker build --build-context plugins=slither_plugins \
#     -f docker/tron-analyze/Dockerfile -t ghcr.io/soken-ltd/tron-analyze:0.1.0-dev .
#
# Verify (local):
#   SOKEN_IMAGE_TRON_ANALYZE=<image-id> uv run pytest tests/adapters/tron/ -m live -v
#
# Record digest after push:
#   docker inspect --format='{{index .RepoDigests 0}}' ghcr.io/soken-ltd/tron-analyze:<tag>
# Then update images.lock.json entry "tron-analyze".

FROM ghcr.io/soken-ltd/evm-analyze:0.1.0-dev AS tron-analyze

USER root

# Copy the slither_plugins source tree (build context: repo root or --build-context plugins=).
COPY slither_plugins /tmp/slither_plugins/

# Install soken-slither-plugins into the Slither venv; --no-deps avoids re-installing slither.
RUN /opt/slither-env/bin/pip install --no-cache-dir --no-deps /tmp/slither_plugins/ \
    && rm -rf /tmp/slither_plugins

# Verify the entry point is registered and the TRON shim is active.
# This runs make_plugin() (which calls apply_tron_shim()) and checks that
# trcToken is present in ElementaryTypeName.
RUN /opt/slither-env/bin/python - <<'EOF'
from slither_plugins import make_plugin
make_plugin()
from slither.core.solidity_types.elementary_type import ElementaryTypeName
from slither.core.variables.state_variable import SOLIDITY_VARIABLES_COMPOSED
assert "trcToken" in ElementaryTypeName, \
    f"TRON shim failed: trcToken missing from ElementaryTypeName={ElementaryTypeName}"
assert "msg.tokenid" in SOLIDITY_VARIABLES_COMPOSED, \
    "TRON shim failed: msg.tokenid missing from SOLIDITY_VARIABLES_COMPOSED"
assert "msg.tokenvalue" in SOLIDITY_VARIABLES_COMPOSED, \
    "TRON shim failed: msg.tokenvalue missing from SOLIDITY_VARIABLES_COMPOSED"
print("TRON shim OK: trcToken, msg.tokenid, msg.tokenvalue patched")
EOF

# Verify HL detectors still load (regression guard — the shim must not break EVM plugins).
RUN test "$(slither --list-detectors 2>/dev/null | grep -c 'hl-')" -eq 6

USER 10001:10001
WORKDIR /work
