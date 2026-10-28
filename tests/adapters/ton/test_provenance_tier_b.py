"""Unit tests for the TON toolchain-gap → tier B promotion (fix/ton-verifier-tier-b).

Scenarios covered
-----------------
1. toolchain_gap + attested_hash == dep.hash  → SOURCE_TOOLCHAIN_GAP, tier B, src == i.
2. toolchain_gap, but hash_attested missing   → SOURCE_NOT_OWNER_LINKED (tier D unchanged).
3. toolchain_gap, but code_hash != dep.hash   → SOURCE_NOT_OWNER_LINKED (unchanged).
4. untrusted_inputs on the ton_verifier cand  → SOURCE_NOT_OWNER_LINKED (unchanged).
5. unsupported_toolchain on non-ton_verifier  → SOURCE_NOT_OWNER_LINKED (unchanged).
6. one ok attempt exists (no hash match)      → SOURCE_NOT_OWNER_LINKED (unchanged).
7. ok attempt + hash match                    → MATCH_REBUILD (tier A, baseline).
"""

from __future__ import annotations

from typing import Any

from soken_review.adapters.base import Candidate, Compiler
from soken_review.adapters.ton.provenance import (
    MATCH_REBUILD,
    SOURCE_NOT_OWNER_LINKED,
    SOURCE_TOOLCHAIN_GAP,
    SOURCE_UNLINKED,
    Attempt,
    Dep,
    resolve_provenance,
)

# ── helpers ────────────────────────────────────────────────────────────────

DEP_HASH = "c845917da4a4ce1cb22aa00f65a82c3775e4c6a3c74453f9352e96d8d14fbfea"
OTHER_HASH = "aabbcc" + "0" * 58


def _dep(hash_: str = DEP_HASH) -> Dep:
    return Dep(address="EQAvJuEl", status="active", hash=hash_)


def _cand(
    provider: str = "ton_verifier",
    language: str = "tact",
    compiler_version: str | None = "1.6.5",
    code_hash: str = DEP_HASH,
    hash_attested: bool = True,
    verifier_id: str = "orbs.com",
    source_item_address: str = "EQCsource",
    untrusted: bool = False,
    extra_verifier: dict | None = None,
) -> Candidate:
    verifier: dict[str, Any] = {
        "code_hash": code_hash,
        "verifier_id": verifier_id,
        "source_item_address": source_item_address,
        "compiler": {"name": language, "version": compiler_version, "params": None},
    }
    if hash_attested:
        verifier["hash_attested"] = True
    if extra_verifier:
        verifier.update(extra_verifier)
    c = Candidate(
        provider=provider,
        files={"contracts/main.tact": "contract Main {}"},
        sha256="0" * 64,
        language=language,
        compiler=Compiler(version=compiler_version, version_pinned_by=provider) if compiler_version else None,
        settings={"verifier": verifier},
        std_json_input=None,
        entry_contract="contracts/main.tact",
    )
    c.untrusted_inputs = untrusted
    return c


def _attempt_fn(
    status: str,
    hashes: dict[str, str] | None = None,
    untrusted: bool = False,
) -> Any:
    """Return a callable that produces a fixed Attempt for any (i, cand) pair."""
    def _fn(i: int, c: Candidate) -> Attempt:
        return Attempt(
            cand_index=i,
            provider=c.provider,
            status=status,
            hashes=hashes or {},
            untrusted_inputs=untrusted,
            build_config=None,
        )
    return _fn


# ── 1. toolchain gap + attested hash → tier B ──────────────────────────────


class TestToolchainGapTierB:
    def test_returns_source_toolchain_gap(self) -> None:
        cand = _cand()
        out = resolve_provenance(_dep(), [cand], _attempt_fn("unsupported_toolchain"))
        assert out.reason == SOURCE_TOOLCHAIN_GAP

    def test_tier_is_b(self) -> None:
        cand = _cand()
        out = resolve_provenance(_dep(), [cand], _attempt_fn("unsupported_toolchain"))
        assert out.tier == "B"

    def test_src_points_to_candidate(self) -> None:
        cand = _cand()
        out = resolve_provenance(_dep(), [cand], _attempt_fn("unsupported_toolchain"))
        assert out.src == 0

    def test_match_is_none(self) -> None:
        cand = _cand()
        out = resolve_provenance(_dep(), [cand], _attempt_fn("unsupported_toolchain"))
        assert out.match is None

    def test_dep_hash_recorded(self) -> None:
        cand = _cand()
        out = resolve_provenance(_dep(), [cand], _attempt_fn("unsupported_toolchain"))
        assert out.dep_hash == DEP_HASH

    def test_why_mentions_compiler_not_installed(self) -> None:
        cand = _cand(compiler_version="1.6.5")
        out = resolve_provenance(_dep(), [cand], _attempt_fn("unsupported_toolchain"))
        assert out.why is not None
        assert "1.6.5" in out.why
        assert "not installed" in out.why

    def test_why_mentions_verifier_id(self) -> None:
        cand = _cand(verifier_id="orbs.com")
        out = resolve_provenance(_dep(), [cand], _attempt_fn("unsupported_toolchain"))
        assert "orbs.com" in (out.why or "")

    def test_why_mentions_registry_item(self) -> None:
        cand = _cand(source_item_address="EQCsource123")
        out = resolve_provenance(_dep(), [cand], _attempt_fn("unsupported_toolchain"))
        assert "EQCsource123" in (out.why or "")

    def test_to_json_contains_tier_b(self) -> None:
        cand = _cand()
        out = resolve_provenance(_dep(), [cand], _attempt_fn("unsupported_toolchain"))
        js = out.to_json()
        assert js["tier"] == "B"
        assert js["reason"] == SOURCE_TOOLCHAIN_GAP
        assert js["src"] == 0

    def test_second_candidate_promoted_when_first_is_user(self) -> None:
        """User source fails for a non-toolchain reason; ton_verifier is second."""
        user_cand = Candidate(
            provider="user",
            files={"main.tact": "contract A {}"},
            sha256="0" * 64,
            language="tact",
            compiler=None,
            settings={},
            std_json_input=None,
            entry_contract=None,
        )
        ton_cand = _cand()

        def attempt_fn(i: int, c: Candidate) -> Attempt:
            if c.provider == "user":
                return Attempt(i, "user", "compile_error", {})
            return Attempt(i, "ton_verifier", "unsupported_toolchain", {})

        out = resolve_provenance(_dep(), [user_cand, ton_cand], attempt_fn)
        assert out.reason == SOURCE_TOOLCHAIN_GAP
        assert out.src == 1


# ── 2. toolchain gap without attestation → tier D (unchanged) ─────────────


class TestToolchainGapWithoutAttestation:
    def test_no_hash_attested_field_stays_d(self) -> None:
        cand = _cand(hash_attested=False)
        out = resolve_provenance(_dep(), [cand], _attempt_fn("unsupported_toolchain"))
        assert out.reason == SOURCE_NOT_OWNER_LINKED
        assert out.tier == "D"

    def test_hash_attested_false_stays_d(self) -> None:
        # Explicitly set to False
        cand = _cand(hash_attested=False, extra_verifier={"hash_attested": False})
        out = resolve_provenance(_dep(), [cand], _attempt_fn("unsupported_toolchain"))
        assert out.tier == "D"

    def test_non_verifier_provider_no_settings_stays_d(self) -> None:
        cand = Candidate(
            provider="ton_verifier",
            files={"main.tact": "contract A {}"},
            sha256="0" * 64,
            language="tact",
            compiler=None,
            settings={},
            std_json_input=None,
            entry_contract=None,
        )
        out = resolve_provenance(_dep(), [cand], _attempt_fn("unsupported_toolchain"))
        assert out.tier == "D"


# ── 3. hash mismatch → tier D (unchanged) ─────────────────────────────────


class TestHashMismatchUnchanged:
    def test_attested_but_wrong_code_hash_stays_d(self) -> None:
        """Candidate's code_hash != dep.hash even with hash_attested=True."""
        cand = _cand(code_hash=OTHER_HASH)
        out = resolve_provenance(_dep(), [cand], _attempt_fn("unsupported_toolchain"))
        assert out.reason == SOURCE_NOT_OWNER_LINKED
        assert out.tier == "D"

    def test_ok_build_wrong_hash_stays_d(self) -> None:
        """A successful rebuild but wrong hash → D, regardless of attestation."""
        cand = _cand()
        out = resolve_provenance(_dep(), [cand], _attempt_fn("ok", hashes={"main": OTHER_HASH}))
        assert out.tier == "D"


# ── 4. untrusted_inputs → tier D (unchanged) ──────────────────────────────


class TestUntrustedInputsUnchanged:
    def test_candidate_untrusted_inputs_stays_d(self) -> None:
        cand = _cand(untrusted=True)
        out = resolve_provenance(_dep(), [cand], _attempt_fn("unsupported_toolchain"))
        assert out.tier == "D"

    def test_attempt_untrusted_inputs_stays_d(self) -> None:
        cand = _cand()
        out = resolve_provenance(_dep(), [cand], _attempt_fn("unsupported_toolchain", untrusted=True))
        assert out.tier == "D"


# ── 5. unsupported_toolchain on non-ton_verifier → tier D (unchanged) ─────


class TestNonVerifierProviderUnchanged:
    def test_user_provider_is_reviewed_unlinked_never_toolchain_gap(self) -> None:
        """A requester's own source never takes the verifier attestation (no tier B third party)
        and never stops the job: SOURCE_UNLINKED, tier B (Hipo blind run 2026-10-27)."""
        cand = Candidate(
            provider="user",
            files={"main.tact": "contract A {}"},
            sha256="0" * 64,
            language="tact",
            compiler=None,
            settings={"verifier": {"code_hash": DEP_HASH, "hash_attested": True}},
            std_json_input=None,
            entry_contract=None,
        )
        out = resolve_provenance(_dep(), [cand], _attempt_fn("unsupported_toolchain"))
        assert out.reason == SOURCE_UNLINKED and out.tier == "B" and out.src == 0
        assert out.why == "unsupported_toolchain"


# ── 6. ok attempt without hash match → tier D (unchanged) ─────────────────


class TestOkBuildNoMatchUnchanged:
    def test_ok_build_present_blocks_toolchain_gap(self) -> None:
        """If any build succeeded (even with wrong hash), toolchain gap does not apply."""
        cand = _cand()

        calls: list[int] = []

        def attempt_fn(i: int, c: Candidate) -> Attempt:
            calls.append(i)
            # First call: ok build with wrong hash
            if len(calls) == 1:
                return Attempt(i, c.provider, "ok", {"main": OTHER_HASH})
            return Attempt(i, c.provider, "unsupported_toolchain", {})

        out = resolve_provenance(_dep(), [cand], attempt_fn)
        assert out.tier == "D"


# ── 7. MATCH_REBUILD baseline ──────────────────────────────────────────────


def test_match_rebuild_tier_a() -> None:
    """Rebuild succeeds and hash matches → tier A, SOURCE_TOOLCHAIN_GAP not triggered."""
    cand = _cand()
    out = resolve_provenance(_dep(), [cand], _attempt_fn("ok", hashes={"main": DEP_HASH}))
    assert out.reason == MATCH_REBUILD
    assert out.tier == "A"
    assert out.src == 0
