"""TON build e2e proof (plan v4 06 section 4.2, coordinator requirement 2026-10-09).

Runs 3 real TON targets through fetch -> build inside sandbox.
Reports build status=ok and code_hash for each.

Env vars required for local dev:
  SOKEN_IMAGE_TON_BUILD=ghcr.io/soken-ltd/ton-build:dev-arm64   (local image)
  SOKEN_SANDBOX_RUNTIME=runc                                      (no gVisor in dev)

Targets:
  1. FunC — ton-blockchain/token-contract ft/ dir (latest func-js)
  2. Tact — tact-lang/jetton project root (tact.config.json)
  3. Tolk — inline minimal Tolk contract

Usage:
    SOKEN_IMAGE_TON_BUILD=... SOKEN_SANDBOX_RUNTIME=runc uv run python scripts/e2e_ton_builds.py
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


TARGETS: list[dict] = [
    {
        "name": "ton-blockchain/token-contract (FunC, ft/ subdir)",
        "repo_url": "https://github.com/ton-blockchain/token-contract",
        "repo_commit": "main",
        # Fetch from repo root (not ft/) so that stdlib.fc at the root is included.
        # token-contract uses ../stdlib.fc in its compile.sh; the root stdlib defines
        # equal_slices which is absent from the tact-lang bundled stdlib.
        "repo_subdir": "",
        # ton-blockchain/token-contract does not pin @ton-community/func-js;
        # use "latest" from the image (0.10.0 in our lockfile = latest stable).
        "compiler_version": "latest",
        "language": "func",
        # jetton-minter.fc is the entry contract.  Path is relative to repo root.
        "entry": "ft/jetton-minter.fc",
    },
    {
        "name": "tact-lang/jetton (Tact, project root)",
        "repo_url": "https://github.com/tact-lang/jetton",
        "repo_commit": "main",
        "repo_subdir": "",  # tact.config.json is at project root
        # tact-lang/jetton pins @tact-lang/compiler 1.6.7;
        # image has 1.6.13 (backward compatible).
        "compiler_version": "1.6.13",
        "language": "tact",
        # hash of the first contract with the project's documented options passed through
        # (tact_config.py); without them the rebuild differs (bff870e2..., 2026-10-10)
        "expect_hash": "74b59fb3e7586fd7",
        "expect_trusted": True,
    },
    {
        "name": "inline Tolk counter contract",
        "user_files": {
            "counter.tolk": """\
// Minimal Tolk counter contract (plan v4 06 e2e proof).
global counter: int;

fun onInternalMessage(myBalance: int, msgValue: int, msgFull: cell, msgBody: slice) {
    counter += 1;
}

get fun getCounter(): int {
    return counter;
}
""",
        },
        "compiler_version": "0.12.0",
        "language": "tolk",
    },
]


async def run_target(target: dict) -> dict:
    """Fetch + build one TON target. Returns result dict."""
    from soken_review.adapters.ton.build import build as _build
    from soken_review.adapters.ton.fetch import fetch_ton_sources, make_user_candidate

    name = target["name"]

    user_files = target.get("user_files")
    repo_url = target.get("repo_url")
    repo_commit = target.get("repo_commit")
    repo_subdir = target.get("repo_subdir", "")
    compiler_version = target.get("compiler_version")
    language = target.get("language")

    # Fetch
    if user_files:
        candidates = [make_user_candidate(user_files, compiler_version=compiler_version, language=language)]
    else:
        candidates = await fetch_ton_sources(
            raw_address=None,
            code_hash=None,
            user_files=None,
            repo_url=repo_url,
            repo_commit=repo_commit,
            repo_subdir=repo_subdir,
        )
        if not candidates:
            return {"name": name, "status": "failed", "reason": "no_candidates_fetched"}

        # Override compiler version from the repository's package.json hint
        cand = candidates[0]
        from soken_review.adapters.base import Compiler
        if compiler_version and (cand.compiler is None or not cand.compiler.version):
            object.__setattr__(cand, "compiler", Compiler(version=compiler_version, version_pinned_by="e2e_repo_pkg"))

        # Override entry point if the target explicitly specifies one
        entry_override = target.get("entry")
        if entry_override:
            merged_settings = {**(cand.settings or {}), "entry": entry_override}
            object.__setattr__(cand, "settings", merged_settings)

    cand = candidates[0]
    print(f"  Fetched: {len(cand.files)} files, language={cand.language}, "
          f"compiler={cand.compiler.version if cand.compiler else 'unset'}")

    # Build (inside sandbox — DIRECT must not be set)
    result = _build(cand)

    if result.status == "ok":
        code_hash = None
        if result.artifacts:
            code_hash = result.artifacts[0].runtime
        cfg = (cand.settings or {}).get("tact_build_config")
        if cfg:
            print(f"  tact_build_config: {json.dumps(cfg)}")
        expect = target.get("expect_hash")
        if expect and not (code_hash or "").startswith(expect):
            return {"name": name, "status": "failed", "reason": f"hash {code_hash} != expected {expect}..."}
        if target.get("expect_trusted") and cand.untrusted_inputs:
            return {"name": name, "status": "failed", "reason": "trust scan flagged the candidate"}
        return {
            "name": name,
            "status": "ok",
            "code_hash": code_hash,
            "nsloc": result.nsloc,
        }
    else:
        return {
            "name": name,
            "status": "failed",
            "reason": result.reason or "unknown",
            "stderr_head": result.stderr_head,
        }


async def main() -> int:
    # Validate that DIRECT mode is NOT set
    if os.environ.get("SOKEN_TON_BUILD_DIRECT", "0") == "1":
        print("ERROR: SOKEN_TON_BUILD_DIRECT=1 is set — builds must run in sandbox", file=sys.stderr)
        return 1

    image = os.environ.get("SOKEN_IMAGE_TON_BUILD")
    runtime = os.environ.get("SOKEN_SANDBOX_RUNTIME")
    if not image:
        print("ERROR: SOKEN_IMAGE_TON_BUILD not set. Use the locally built dev image.", file=sys.stderr)
        return 1
    print(f"Sandbox image : {image}")
    print(f"Sandbox runtime: {runtime or 'default (gVisor)'}")
    print()

    failed = 0
    results = []
    for i, target in enumerate(TARGETS, 1):
        print(f"[{i}/{len(TARGETS)}] {target['name']}")
        try:
            res = await run_target(target)
        except Exception as exc:  # noqa: BLE001
            res = {"name": target["name"], "status": "error", "reason": str(exc)}
        results.append(res)
        status = res.get("status", "?")
        if status == "ok":
            print(f"  PASS  code_hash={res.get('code_hash', '?')[:16]}... nsloc={res.get('nsloc')}")
        else:
            failed += 1
            print(f"  FAIL  reason={res.get('reason')} stderr={str(res.get('stderr_head', ''))[:200]}")
        print()

    out_dir = Path(__file__).resolve().parents[1] / ".sbx" / "ton-cases"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "e2e_results.json").write_text(json.dumps(results, indent=2))
    print(f"Results written to {out_dir / 'e2e_results.json'}")
    print(f"\nSummary: {len(TARGETS) - failed}/{len(TARGETS)} targets OK")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
