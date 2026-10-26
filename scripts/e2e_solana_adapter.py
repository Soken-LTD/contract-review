"""Solana live proof through the adapter code path only (06 2.4, 3.2, 3.3; 09 5.2; U-S1).

    uv run python scripts/e2e_solana_adapter.py [name ...]
    uv run python scripts/e2e_solana_adapter.py --versions      # image versions the targets need

Per target, all through adapter code:
  1. chain read by the supervisor (onchain.deployed_program): deployed F5 hash, upgrade authority, slot
  2. owner-linked source: the OtterSec verify PDA written by that upgrade authority
     (onchain.owner_linked_verify_pdas): repo, commit, solana-verify args
  3. sandboxed git fetch of that commit (fetch._clone_repo) -> Candidate with the verify args
  4. SolanaAdapter().build: image of the program's Solana version line, deps, offline build;
     the supervisor hashes the .so
  5. SolanaAdapter().analyze: clippy in the build image, cargo-audit with the pinned RustSec snapshot
  6. SolanaAdapter().map -> resolve_provenance: the tier decision
Each target states what the decision must be; the run fails when any row differs.

Controls: `*-mutated` changes one constant in the source (hash must differ, never A); `*-toolchain` adds
a rust-toolchain.toml naming another toolchain and `*-committed-so` adds an ELF fixture to the checkout,
both dropped from the build, so the hash still equals the deployed one and only the trust flag can
keep the decision off tier A.

Needs SOKEN_IMAGE_GIT_FETCH, SOKEN_IMAGE_SOLANA_BUILD_<x_y_z> per version, SOKEN_IMAGE_SOLANA_ANALYZE,
SOKEN_SANDBOX_RUNTIME, the soken-solana-egress network and a fetched RustSec snapshot
(python -m soken_review.adapters.solana.rustsec fetch). SOKEN_SOLANA_DIRECT must be unset.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any

from soken_review.adapters.base import ChainValue
from soken_review.adapters.solana import SolanaAdapter
from soken_review.adapters.solana import images as solana_images
from soken_review.adapters.solana.fetch import (
    _clone_repo,
    _fetch_osec_verify,
    _make_candidate,
    _walk_source_files,
)
from soken_review.adapters.solana.onchain import deployed_program, owner_linked_verify_pdas

# version: image the target needs (printed by --versions for the image build step)
TARGETS: list[dict[str, Any]] = [
    # 1.18 line: one measurement target only. wagon's Cargo.lock is version=3; cargo 1.75.0 (both
    # sbf-cargo and host active_toolchain) refuses --locked on v3 with "needs to be updated but
    # --locked was passed".  No unlocked fallback is permitted (security).  The expected outcome
    # is deps_failed; this target documents the measured 1.18 status and stays green on that reason.
    # Controls that require a successful build are on ripstr (3.1.10) below.
    {"name": "wagon", "program_id": "2kZqCjGfKgVR8dUkv4PCogFsFgN3EoSSNX41HN1cBfBA", "version": "1.18.26",
     "expect_build_failure": "deps_failed"},
    # 3.1 line: ripstr-token-hook is the U-S1 reference (hash_equal proven in run 38288915563).
    # The negative controls (mutated/toolchain/committed-so) are on ripstr because it builds
    # successfully, giving each control a real binary to compare.
    {"name": "ripstr-token-hook", "program_id": "2k9FaQJGXzUxFcdJmdhY9VxNJZSAyo2qtXeTsLneM8PM", "version": "3.1.10",
     "expect": {"hash_equal": True, "untrusted": False}},
    {"name": "ripstr-mutated", "program_id": "2k9FaQJGXzUxFcdJmdhY9VxNJZSAyo2qtXeTsLneM8PM", "version": "3.1.10",
     "mutate": "program_id", "expect": {"hash_equal": False, "untrusted": False}},
    {"name": "ripstr-toolchain", "program_id": "2k9FaQJGXzUxFcdJmdhY9VxNJZSAyo2qtXeTsLneM8PM", "version": "3.1.10",
     "mutate": "toolchain", "expect": {"hash_equal": True, "untrusted": True}},
    {"name": "ripstr-committed-so", "program_id": "2k9FaQJGXzUxFcdJmdhY9VxNJZSAyo2qtXeTsLneM8PM", "version": "3.1.10",
     "mutate": "committed_so", "expect": {"hash_equal": True, "untrusted": True}},
    # Token-2022 (3.1.8): rust-toolchain.toml 1.93.0 and committed test .so fixtures -> untrusted
    {"name": "spl-token-2022", "program_id": "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb", "version": "3.1.8",
     "expect": {"hash_equal": True, "untrusted": True}},
    # 4.3 line: bordrless-token. No owner-linked PDA exists (OtterSec entry signed by a key other
    # than the upgrade authority; all 580 OtterSec verified programs were checked: zero owner-linked
    # 4.3.0 entries). repo/commit/args are hardcoded from the OtterSec API record for e2e measurement
    # only. The product path (fetch.py / supervisor) always requires an owner-linked PDA and never
    # uses these hardcoded fields; confirmed by grep of src/soken_review/ (zero matches for the bypass).
    # Expected tier: B/SOURCE_NOT_REBUILT (4.3 line has not passed U-S1; tier A requires line_passed).
    {"name": "bordrless-token", "program_id": "2XoEWp8cF3kRXg74eVwPAyTFhVCAztn3V88komxAvr22",
     "version": "4.3.0",
     "repo": "https://github.com/BordrlessDex/bordrless-programs",
     "commit": "be0f9feb5503d246f3d71d7d641cc325c8ec2e08",
     "args": ["--library-name", "bordrless_token",
              "--base-image", "solanafoundation/solana-verifiable-build:4.3.0",
              "--arch", "v3"],
     "expect": {"hash_equal": True, "untrusted": False}},
]

_ELF_FIXTURE = b"\x7fELF\x02\x01\x01" + b"\x00" * 57


def _expected_decision(t: dict[str, Any], version: str | None) -> tuple[str, str]:
    """(tier, reason) 06 2.4 requires for this target, given the U-S1 row of its line today."""
    exp = t["expect"]
    if exp["untrusted"]:
        return "B", "BUILD_INPUT_UNTRUSTED"
    if exp["hash_equal"]:
        return ("A", "MATCH_REBUILD") if solana_images.line_passed(version) else ("B", "SOURCE_NOT_REBUILT")
    return "B", "SOURCE_NOT_REBUILT"   # differing rebuild, owner-linked OtterSec is_verified: third party


def _mutate(t: dict[str, Any], files: dict[str, str], work_dir: Path) -> dict[str, str]:
    """Apply a source mutation for a control target.

    work_dir is the target's top-level work directory (root/name).  Sandbox mode puts the
    fetched tree at work_dir/src; direct-clone mode puts it at work_dir/clone.  For the
    committed_so control the .so is written into the actual source directory so the normal
    _walk_source_files scan finds it — the control tests the whole detection path, not just
    the unread_paths injection point.
    """
    kind = t.get("mutate")
    if kind == "program_id":
        changed = {p: c.replace(t["program_id"], "11111111111111111111111111111112")
                   for p, c in files.items() if p.endswith(".rs") and t["program_id"] in c}
        if not changed:
            raise RuntimeError("mutation found no program id literal")
        files = type(files)(files)
        files.update(changed)
        return files
    if kind == "toolchain":
        files = type(files)(files)
        files["rust-toolchain.toml"] = '[toolchain]\nchannel = "1.60.0"\n'
        return files
    if kind == "committed_so":
        # Write a real ELF fixture to the actual source directory and re-scan so the normal
        # trust-scan path (_walk_source_files → _trust_relevant_unread → unread_paths →
        # scan_candidate_files → untrusted_inputs=True) is exercised end-to-end.
        # Injecting the path directly into unread_paths would be a tautology: it would bypass
        # the very detection mechanism the control is meant to test.
        src_dir = work_dir / "src"          # sandbox mode (materialize_repo output)
        if not src_dir.is_dir():
            src_dir = work_dir / "clone"    # direct-clone mode (SOKEN_SOLANA_DIRECT=1)
        if not src_dir.is_dir():
            raise RuntimeError(
                f"committed_so: source dir not found in {work_dir}; "
                "expected work/src (sandbox) or work/clone (direct)"
            )
        fixture_dir = src_dir / "fixtures"
        fixture_dir.mkdir(exist_ok=True)
        (fixture_dir / "prebuilt.so").write_bytes(_ELF_FIXTURE)
        return _walk_source_files(src_dir)
    return files


def run(t: dict[str, Any], root: Path) -> dict[str, Any]:
    out: dict[str, Any] = {"name": t["name"], "program_id": t["program_id"]}
    dp = deployed_program(t["program_id"])
    out.update(slot=dp.slot, deployed_hash=dp.hash, upgrade_authority=dp.upgrade_authority, chain_why=dp.why)
    if not dp.hash or not dp.upgrade_authority:
        return {**out, "stage": "chain", "ok": False}

    # Hardcoded targets (no owner-linked PDA: zero entries in OtterSec's 580 verified programs
    # match this version line and upgrade authority).  repo/commit/args come from the OtterSec API
    # record; chain read above still validates the program exists with an upgrade authority.
    if "repo" in t and "commit" in t and "args" in t:
        repo = t["repo"].rstrip("/").removesuffix(".git")
        commit = t["commit"]
        verify_args = list(t["args"])
        out.update(repo=repo, commit=commit, verify_args=verify_args, pda_signer="hardcoded")
    else:
        pdas = owner_linked_verify_pdas(t["program_id"], dp.upgrade_authority)
        if not pdas:
            return {**out, "stage": "owner_linked_pda", "ok": False}
        pda = pdas[0]
        repo = pda.git_url.rstrip("/").removesuffix(".git")
        commit = pda.commit
        verify_args = list(pda.args)
        out.update(repo=repo, commit=commit, verify_args=verify_args, pda_signer=pda.signer)

    work = root / t["name"]
    work.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    files = _clone_repo(repo, commit, work)
    if not files:
        return {**out, "stage": "fetch", "ok": False}
    files = _mutate(t, files, work)   # pass work so committed_so can find work/src
    cand = _make_candidate(files, provider="repo", repo_url=repo, commit=commit)
    cand.settings["verify_args"] = verify_args
    cand.settings["commit"] = commit
    cand.program_id = t["program_id"]  # type: ignore[attr-defined]  # Cargo.lock required with an address

    adapter = SolanaAdapter()
    result = adapter.build(cand)
    out.update(files=len(files), build=result.status, build_reason=result.reason, build_s=round(time.time() - t0),
               untrusted=cand.untrusted_inputs,
               untrusted_reasons=(cand.settings.get("unread_paths") or [])[:2])

    # Targets with expect_build_failure: the expected outcome IS a named build failure (e.g. wagon
    # with Cargo.lock v3 gives deps_failed under --locked-only policy).  A matching reason is ok=True.
    if "expect_build_failure" in t:
        expected_reason = t["expect_build_failure"]
        ok = result.status == "failed" and result.reason == expected_reason
        out.update(checks={"build_failure": ok},
                   expected_failure=expected_reason,
                   stderr=(result.stderr_head or "")[-500:],
                   ok=ok)
        return out

    if result.status != "ok":
        out["stderr"] = (result.stderr_head or "")[-1500:]
        return {**out, "stage": "build", "ok": False}
    host = Path(result.work_dir or "") / "host"
    if (host / "untrusted_inputs.txt").is_file():
        out["untrusted_reasons"] = (host / "untrusted_inputs.txt").read_text().splitlines()[:3]

    leads, static_map, _ = adapter.analyze(result)
    static_map["verify_items"] = _fetch_osec_verify(t["program_id"])
    chain_state = {
        "upgrade_authority": ChainValue(dp.upgrade_authority, "rpc_finalized", block=dp.slot),
        "deployed_program_hash": ChainValue(dp.hash, "rpc_finalized", block=dp.slot),
    }
    extras, _rows = adapter.map(result, static_map, chain_state)
    prov = extras["provenance"]
    audit = (static_map.get("tools") or {}).get("cargo_audit") or {}
    clippy = (static_map.get("tools") or {}).get("clippy") or {}
    want_tier, want_reason = _expected_decision(t, prov.get("version"))
    checks = {
        "hash_equal": prov.get("hash_equal") == t["expect"]["hash_equal"],
        "untrusted": cand.untrusted_inputs == t["expect"]["untrusted"],
        "decision": (prov.get("tier"), prov.get("reason")) == (want_tier, want_reason),
        "cargo_audit_ran": audit.get("status") == "ok",
    }
    out.update(
        version=prov.get("version"), image=prov.get("image"), build_hash=prov.get("hash"),
        osec_hashes=sorted({i.get("executable_hash") for i in static_map["verify_items"] if i.get("executable_hash")}),
        hash_equal=prov.get("hash_equal"), line_passed=prov.get("version_line_passed"),
        tier=prov.get("tier"), match=prov.get("match"), reason=prov.get("reason"), why=prov.get("why"),
        expected=[want_tier, want_reason],
        analyze=static_map.get("status"), degraded_reasons=static_map.get("degraded_reasons"),
        clippy=[clippy.get("status"), clippy.get("reason"), len(clippy.get("items") or [])],
        clippy_tail=clippy.get("stderr_tail"),
        cargo_audit=[audit.get("status"), audit.get("reason"), audit.get("advisory_count"),
                     audit.get("vulnerabilities")],
        cargo_audit_tail=audit.get("stderr_tail"),
        rustsec=(audit.get("db") or {}) and {k: audit["db"][k] for k in ("commit", "commit_date", "age_days", "stale")},
        leads=len(leads), checks=checks, ok=all(checks.values()),
    )
    return out


def main(argv: list[str]) -> int:
    if argv[:1] == ["--versions"]:
        print(" ".join(sorted({t["version"] for t in TARGETS})))
        return 0
    if os.environ.get("SOKEN_SOLANA_DIRECT") == "1":
        print("SOKEN_SOLANA_DIRECT must be unset: this run proves the sandbox path", file=sys.stderr)
        return 2
    root = Path(__file__).resolve().parents[1] / ".sbx" / "solana-e2e"
    rows = []
    for t in TARGETS:
        if argv and t["name"] not in argv:
            continue
        try:
            row = run(t, root)
        except Exception as exc:  # noqa: BLE001 - one target's crash is that target's failed row
            row = {"name": t["name"], "stage": "crash", "error": repr(exc)[:500], "ok": False}
        print(json.dumps(row), flush=True)
        rows.append(row)
    print(json.dumps({"summary": [[r["name"], r.get("tier"), r.get("reason"), r.get("hash_equal"),
                                   r.get("analyze"), r.get("ok")] for r in rows]}, indent=1))
    return 0 if rows and all(r.get("ok") for r in rows) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
