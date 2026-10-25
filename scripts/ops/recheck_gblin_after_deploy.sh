#!/usr/bin/env bash
# recheck_gblin_after_deploy.sh
#
# After deploying fix/related-state-real-data, re-run the GBLIN vault job
# (Base 8453, job_T3A2VX732WAS9CW4PGVKJ55C2S) and verify the three fixed
# bugs are gone in live output.
#
# Run this from the server:
#   bash scripts/ops/recheck_gblin_after_deploy.sh
#
# Prerequisites: soken-wrapped container is running with the new image.

set -euo pipefail

JOB_ID="job_T3A2VX732WAS9CW4PGVKJ55C2S"
PIN_ROOT="${SOKEN_PIN_ROOT:-/opt/soken-audit-test/public-export/.sbx/pins}"
WORK_ROOT="${SOKEN_WORK_ROOT:-/opt/soken-audit-test/public-export/.sbx/work}"
CONTRACT="0xc2181d975c05c8c724b334bcED0764c0b86B1D53"

echo "=== GBLIN post-deploy recheck ==="
echo "Job:      $JOB_ID"
echo "Contract: $CONTRACT (GBLIN vault, Base 8453)"
echo ""

echo "--- Bug 1: related_contracts.json should include WETH address ---"
RELATED="$PIN_ROOT/$JOB_ID/related_contracts.json"
if [ -f "$RELATED" ]; then
  if grep -qi "4200000000000000000000000000000000000006" "$RELATED"; then
    echo "[PASS] WETH address found in related_contracts.json"
  else
    echo "[FAIL] WETH address MISSING from related_contracts.json"
    cat "$RELATED"
  fi
else
  echo "[SKIP] related_contracts.json not found at $RELATED (re-trigger chain_state step first)"
fi
echo ""

echo "--- Bug 2: state facts should have correct types ---"
FACTS="$PIN_ROOT/$JOB_ID/facts.json"
if [ -f "$FACTS" ]; then
  if grep -q '"state.auction_premium_bps"' "$FACTS"; then
    VALUE=$(python3 -c "
import json
facts = json.load(open('$FACTS'))
f = next((x for x in facts if x['key'] == 'state.auction_premium_bps'), None)
print(f['value'] if f else 'MISSING')
")
    if [ "$VALUE" = "-100" ]; then
      echo "[PASS] auctionPremiumBps = $VALUE (correct int256)"
    else
      echo "[FAIL] auctionPremiumBps = $VALUE (expected -100)"
    fi
  else
    echo "[SKIP] state.auction_premium_bps not found in facts.json"
  fi

  if grep -q '"state.domain_separator"' "$FACTS"; then
    VALUE=$(python3 -c "
import json
facts = json.load(open('$FACTS'))
f = next((x for x in facts if x['key'] == 'state.domain_separator'), None)
print(f['value'] if f else 'MISSING')
")
    if echo "$VALUE" | grep -q '^0x'; then
      echo "[PASS] DOMAIN_SEPARATOR = 0x... (correct bytes32 hex)"
    else
      echo "[FAIL] DOMAIN_SEPARATOR = $VALUE (expected 0x-prefixed hex, not decimal)"
    fi
  fi

  if grep -q '"state.weth"' "$FACTS"; then
    echo "[PASS] state.weth present (low-entropy address decoded correctly)"
  else
    echo "[FAIL] state.weth MISSING (low-entropy address 0x4200...0006 still dropped)"
  fi
else
  echo "[SKIP] facts.json not found at $FACTS (re-trigger chain_state step first)"
fi
echo ""

echo "--- Bug 3: suggested_context.json should have no library GitHub URLs ---"
SUGGESTED="$PIN_ROOT/$JOB_ID/suggested_context.json"
if [ -f "$SUGGESTED" ]; then
  if grep -qi "vectorized/solady\|openzeppelin/openzeppelin-contracts\|uniswap/permit2\|transmissions11/solmate\|ethereum/eips" "$SUGGESTED"; then
    echo "[FAIL] Library URLs still present in suggested_context.json:"
    cat "$SUGGESTED"
  else
    echo "[PASS] No library URLs in suggested_context.json ($(python3 -c "import json; print(len(json.load(open('$SUGGESTED'))))" 2>/dev/null || echo '?') items)"
  fi
else
  echo "[INFO] suggested_context.json not present (no NatSpec @custom:website in GBLIN source - expected)"
fi

echo ""
echo "=== Done ==="
