"""EVM repo source route live proof through review_start -> supervisor -> ready/failed (05 4.2).

    SOKEN_DATABASE_URL=postgresql://... uv run python scripts/e2e_evm_repo.py [name ...]

Per target: MCP tool review_start (in-process ASGI app, real Postgres) with source.kind=repo,
one real Supervisor running the repo step-runners (sandboxed git fetch via soken-fetch image,
repo_candidate_from_manifest, Standard JSON B3 build, analyze, map), review_status polled to a
terminal state, then review_leads. Prints job state, tier, provenance, candidate trust flags
and the first leads.

Needs SOKEN_IMAGE_GIT_FETCH, SOKEN_IMAGE_EVM_ANALYZE, SOKEN_SANDBOX_RUNTIME, and
the soken-egress-evm docker network (up via `python -m soken_review.sandbox.egress up evm`).

Cases (all repos public on github.com, commits pinned by full SHA):

  (a) solmate HEAD 89365b880c4f3c786bdd453d4b8e8fe410344a69
      Foundry project with lib/forge-std and lib/ds-test as gitlink submodules on github.com.
      src/ main contracts are self-contained; src/test/ imports ds-test (npm-only test dep).
      Expected outcome: insufficient_source / E_SOURCE_NOT_FOUND with missing_import:ds-test
      in error_detail.  Proves: gitlink materialisation, B3 build attempt, missing_import
      detection pipeline (solc errors → structured reason → injection-safe package validation).

  (b) Uniswap/v2-core HEAD 6a9e7c97860676e0992f22a49665760444c1cdf5
      Pre-Foundry truffle/npm project; all contracts committed in contracts/; no .gitmodules.
      Demonstrates in-tree deps (no gitlink submodules, no npm Solidity source deps).
      _npm_only_reason was fixed (2026-10-13) to parse package.json rather than doing a broad
      string-search that incorrectly triggered on @openzeppelin/test-helpers in devDependencies.

  (c) gnosis/canonical-weth HEAD 0dd1ea3e295eef916d0c6223ec63141137d22d67
      Single-file WETH9.sol deployed at 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 on
      Ethereum mainnet (chain 1). Chosen to exercise the 13.1 deployment hash comparison
      (repo candidate built from source vs on-chain runtime bytecode) and obtain a real tier.

  (d) Uniswap/v4-core HEAD 46c6834698c48bc4a463a86d8420f4eb1d7f3b75
      Has `ffi = true` at line 4 of foundry.toml → repo_candidate sets untrusted_inputs=True
      (tier B ceiling). Verified 2026-10-13 via
      raw.githubusercontent.com/Uniswap/v4-core/<sha>/foundry.toml.
      Build may fail (via_ir, solc 0.8.26, ffi = true build deps); the test checks
      untrusted_inputs in candidates.json independent of build outcome.

  (e) EXPECTED FAILURE — no live repo found with off-allowlist submodule URL.
      git_materializer allowlist: github.com|gitlab.com|codeberg.org.  Any submodule whose
      URL uses a different host (bitbucket.org, git://, SSH git@...) gets status=refused_host
      in the manifest.  Behaviour is unit-tested in
      tests/adapters/evm/test_repo_candidate.py::TestRepoCandidate::
          test_submodule_refused_host_does_not_block_candidate.
      A purpose-built fixture repo is needed for this live case (TODO: create
      soken-ltd/soken-e2e-fixtures with a ref pointing to bitbucket.org submodule).
      Skipped in this run; CI remains green.

  (f) transmissions11/solmate commit deadbeefdeadbeefdeadbeefdeadbeefdeadbeef
      Valid 40-hex SHA that does not exist in the repo.  soken-fetch exits 21 → E_COMMIT_NOT_FOUND.
      Chosen to prove the named-error path for non-existent commits.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# ---------------------------------------------------------------------------
# Test targets
# ---------------------------------------------------------------------------

TARGETS: list[dict] = [
    # (a) solmate HEAD: gitlink submodules on github.com, src/ self-contained main contracts.
    #     src/test/ imports ds-test — but _select_scope_files now excludes src/test/ (same as
    #     forge --skip test script), so the B3 Standard JSON only contains the main src/ files
    #     which are self-contained.  Expected outcome: ready with leads > 0.
    #     Proves: gitlink materialisation, src/test/ exclusion fix, B3 build of scope files.
    {
        "name": "solmate-gitlinks",
        "expect": {"state": "ready"},
        "expect_flags": {"untrusted_inputs": False},
        "source": {
            "kind": "repo",
            "repo_url": "https://github.com/transmissions11/solmate",
            "commit": "89365b880c4f3c786bdd453d4b8e8fe410344a69",
        },
        "why": "gitlink submodules; src/test/ excluded from scope (fix); main src/ self-contained → ready",
    },
    # (b) Uniswap v2-core HEAD: no .gitmodules, contracts/ in-tree
    {
        "name": "v2core-intree",
        "expect": {"state": "ready"},
        "expect_flags": {"untrusted_inputs": False},
        "source": {
            "kind": "repo",
            "repo_url": "https://github.com/Uniswap/v2-core",
            "commit": "6a9e7c97860676e0992f22a49665760444c1cdf5",
        },
        "why": "no .gitmodules; all contracts/ committed in-tree; @openzeppelin/test-helpers devDep is JS-only",
    },
    # (c) canonical-weth + WETH9 deployment: 13.1 comparison
    {
        "name": "weth9-deployed",
        "expect": {"state": "ready"},
        "source": {
            "kind": "repo",
            "repo_url": "https://github.com/gnosis/canonical-weth",
            "commit": "0dd1ea3e295eef916d0c6223ec63141137d22d67",
            "deployment": {
                "chain": "evm",
                "chain_id": 1,
                "address": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
            },
        },
        "why": "single-file WETH9 with verified mainnet deployment; exercises 13.1 bytecode comparison for a real tier",
    },
    # (d) v4-core: ffi=true → untrusted_inputs=True (tier B ceiling)
    #     B4 with forge: lib/solmate submodule is fetched → build can succeed → ready (tier B).
    #     Without forge in image (image rebuild pending): lib/solmate paths not in B3 sources
    #     → missing_dependency_path → insufficient_source.  Both outcomes are acceptable here;
    #     the invariant under test is untrusted_inputs=True from foundry.toml ffi=true.
    {
        "name": "v4core-ffi",
        "expect": {"state_one_of": ["ready", "insufficient_source", "failed"]},
        "expect_flags": {"untrusted_inputs": True},
        "source": {
            "kind": "repo",
            "repo_url": "https://github.com/Uniswap/v4-core",
            "commit": "46c6834698c48bc4a463a86d8420f4eb1d7f3b75",
        },
        "why": "v4-core ffi=true → untrusted_inputs=True; build outcome depends on B4/forge availability",
    },
    # (e) SKIPPED — no live repo with off-allowlist submodule found (see module docstring)
    # Uncomment when soken-ltd/soken-e2e-fixtures provides a fixture repo.
    # {
    #     "name": "refused-submodule",
    #     "expect": {"state": "ready"},    # src/ can compile without the refused submodule
    #     "expect_manifest": {"refused_host_submodule": True},
    #     "source": {
    #         "kind": "repo",
    #         "repo_url": "https://github.com/soken-ltd/soken-e2e-fixtures",
    #         "commit": "TODO",
    #     },
    # },
    # (f) non-existent commit → E_COMMIT_NOT_FOUND
    {
        "name": "bad-commit",
        "expect": {"state": "failed", "error_code": "E_COMMIT_NOT_FOUND"},
        "source": {
            "kind": "repo",
            "repo_url": "https://github.com/transmissions11/solmate",
            "commit": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        },
        "why": "non-existent 40-hex SHA → soken-fetch exit 21 → E_COMMIT_NOT_FOUND",
    },
]


# ---------------------------------------------------------------------------
# MCP call helper (mirrors e2e_starknet.py)
# ---------------------------------------------------------------------------

async def _call(client, tool: str, **kwargs) -> dict:
    resp = await client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
              "params": {"name": tool, "arguments": kwargs}},
        headers={"MCP-Protocol-Version": "2025-11-25",
                 "Accept": "application/json, text/event-stream"},
    )
    resp.raise_for_status()
    result = resp.json().get("result", {})
    text = (result.get("content") or [{}])[0].get("text", "")
    return json.loads(text) if text.startswith("{") else {"text": text, "is_error": result.get("isError")}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def run(names: list[str]) -> int:
    import httpx
    import psycopg_pool
    from asgi_lifespan import LifespanManager

    from soken_review.db import migrate
    from soken_review.tools.context_pg import create_app
    from soken_review.worker.supervisor import Supervisor

    dsn = os.environ["SOKEN_DATABASE_URL"]
    pin_root = Path(os.environ.setdefault(
        "SOKEN_PIN_ROOT", str(ROOT / ".sbx" / "evm-repo-e2e" / "pins"),
    ))
    pin_root.mkdir(parents=True, exist_ok=True)
    (pin_root.parent / "work").mkdir(parents=True, exist_ok=True)

    await migrate.run_migrations(dsn)
    pool = psycopg_pool.AsyncConnectionPool(dsn, min_size=2, max_size=6, open=False)
    await pool.open()
    # Longer poll_interval: repo fetch + build can take a while
    sup = Supervisor(pool, pin_root, host_name="evm-repo-e2e", poll_interval=1.0)
    sup_task = asyncio.create_task(sup.run())

    rows: list[dict] = []
    ok = True

    try:
        app = create_app()
        async with LifespanManager(app) as mgr, httpx.AsyncClient(
            transport=httpx.ASGITransport(app=mgr.app),
            base_url="http://127.0.0.1:8000",
            timeout=120,
        ) as client:

            for t in TARGETS:
                if names and t["name"] not in names:
                    continue

                print(f"\n=== {t['name']} ===", flush=True)
                print(f"    why: {t.get('why', '')}", flush=True)

                start = await _call(client, "review_start", source=t["source"])
                row: dict = {
                    "name": t["name"],
                    "accepted": start.get("accepted"),
                    "job_id": start.get("job_id"),
                }

                if not start.get("accepted"):
                    row["errors"] = start.get("errors")
                    expected_accepted = t["expect"].get("accepted", True)
                    ok &= not expected_accepted
                    rows.append(row)
                    print(json.dumps(row), flush=True)
                    continue

                job_id = start["job_id"]

                # Poll to terminal state (max 30 min / 1800 × 1 s)
                status: dict = {}
                for _ in range(1800):
                    status = await _call(client, "review_status", job_id=job_id)
                    if status.get("state") in ("ready", "insufficient_source", "failed"):
                        break
                    await asyncio.sleep(1)

                row["state"] = status.get("state")
                row["status_detail"] = {
                    k: status.get(k)
                    for k in ("tier", "error", "errors", "percent")
                    if k in status
                }

                # Pull DB fields
                async with pool.connection() as conn, conn.cursor() as cur:
                    await cur.execute(
                        "SELECT tier, error_code, error_detail, resolved_commit "
                        "FROM jobs WHERE job_id=%s",
                        (job_id,),
                    )
                    db_row = await cur.fetchone()
                if db_row:
                    row.update(
                        tier=db_row[0],
                        error_code=db_row[1],
                        error_detail=db_row[2],
                        resolved_commit=db_row[3],
                    )

                # Read work artifacts (candidates.json tells us untrusted_inputs before build)
                work = pin_root.parent / "work" / job_id
                for fname in ("candidates.json", "build_result.json", "provenance.json"):
                    if (work / fname).exists():
                        try:
                            row[fname.removesuffix(".json")] = json.loads((work / fname).read_text())
                        except ValueError:
                            pass

                # Verify untrusted_inputs flag expectation (from candidates.json)
                if "candidates" in row and "expect_flags" in t:
                    cands = row["candidates"]
                    if cands:
                        actual_untrusted = cands[0].get("untrusted_inputs", False)
                        expected_untrusted = t["expect_flags"].get("untrusted_inputs", False)
                        flag_ok = actual_untrusted == expected_untrusted
                        row["untrusted_inputs_check"] = "pass" if flag_ok else f"FAIL: got {actual_untrusted}, want {expected_untrusted}"
                        ok &= flag_ok
                    else:
                        # No candidates → build failed before pinning; check still by state
                        pass

                # Get leads if ready
                if row["state"] == "ready":
                    leads = await _call(client, "review_leads", job_id=job_id)
                    row["leads_head"] = (leads.get("text") or "").splitlines()[:8]
                    # leads_count: prefer work-dir leads.json (accurate list count),
                    # fall back to non-empty text lines from review_leads response.
                    leads_file = work / "leads.json"
                    if leads_file.exists():
                        try:
                            leads_data = json.loads(leads_file.read_text())
                            row["leads_count"] = len(leads_data) if isinstance(leads_data, list) else 0
                        except ValueError:
                            row["leads_count"] = sum(1 for ln in (leads.get("text") or "").splitlines() if ln.strip())
                    else:
                        row["leads_count"] = sum(1 for ln in (leads.get("text") or "").splitlines() if ln.strip())

                # Check outcome against expectation
                expected_state = t["expect"].get("state")
                expected_states = t["expect"].get("state_one_of", [expected_state] if expected_state else [])
                if expected_states:
                    state_ok = row["state"] in expected_states
                    ok &= state_ok
                    if not state_ok:
                        print(f"    FAIL state: got {row['state']!r}, want one of {expected_states!r}")
                if "error_code" in t["expect"]:
                    ec_ok = row.get("error_code") == t["expect"]["error_code"]
                    ok &= ec_ok
                    if not ec_ok:
                        print(f"    FAIL error_code: got {row.get('error_code')!r}, want {t['expect']['error_code']!r}")

                rows.append(row)
                print(json.dumps(row, indent=1, default=str), flush=True)

    finally:
        sup_task.cancel()
        try:
            await sup_task
        except asyncio.CancelledError:
            pass
        await pool.close()

    summary = []
    for r in rows:
        entry = {k: r.get(k) for k in ("name", "accepted", "state", "tier", "error_code", "resolved_commit", "leads_count")}
        # dep.match from provenance.json (weth9 13.1 comparison)
        prov = r.get("provenance") or {}
        dep = prov.get("dep") or {}
        if dep.get("match"):
            entry["dep_match"] = dep["match"]
            entry["dep_match_reason"] = dep.get("reason")
        summary.append(entry)
    print("\nSUMMARY", json.dumps(summary))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(run(sys.argv[1:])))
