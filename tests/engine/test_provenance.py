"""dep.match (05 13.3) and tier (04 section 3) at the provenance decision point."""

from __future__ import annotations

import pytest
import yaml

from soken_review.adapters.base import Artifact, BuildResult, Candidate, Compiler
from soken_review.adapters.evm.compare import compare_runtime
from soken_review.engine.provenance import (
    RUBRIC_DIR,
    DepResult,
    code_tier,
    dep_match_vocabulary,
    evm_dep_match,
    evm_deployment_check,
    resolve_provenance,
    unit_tier,
)
from soken_review.errors import ReviewError
from tests.adapters.evm.test_compare import IMM, local_runtime, onchain_runtime, x2_for


def cand(pinned_by: str = "sourcify", *, language: str = "solidity", untrusted: bool = False,
         entry: str | None = "A.sol:A") -> Candidate:
    return Candidate(provider="sourcify", files={}, sha256="00" * 32, language=language,
                     compiler=Compiler("0.8.24+commit.e11b9ed9", pinned_by), settings={},
                     std_json_input=None, entry_contract=entry, untrusted_inputs=untrusted)


def build_of(candidate: Candidate, runtime: bytes, x2: list | None = None) -> BuildResult:
    art = Artifact(contract="A.sol:A", creation="", runtime=runtime.hex(), immutable_refs=IMM,
                   link_refs={}, source_map="", storage_layout=None)
    other = Artifact(contract="B.sol:B", creation="", runtime="6080", immutable_refs={},
                     link_refs={}, source_map="", storage_layout=None)
    aux = {"A.sol:A": x2 if x2 is not None else x2_for(runtime)}
    return BuildResult(candidate=candidate, status="ok", artifacts=[other, art], auxdata_ranges=aux)


TAMPERED = bytearray(onchain_runtime())
TAMPERED[60] ^= 1


class TestVocabulary:
    def test_values_come_from_dep_match_yaml(self) -> None:
        values, reasons = dep_match_vocabulary()
        data = yaml.safe_load((RUBRIC_DIR / "dep_match.yaml").read_text())
        assert values == set(data)
        assert "auxdata_rule_missing" in reasons and "tron_compiler_unmapped" in reasons


class TestDepMatch:
    def _diff(self):
        loc = local_runtime()
        return compare_runtime(loc.hex(), bytes(TAMPERED).hex(), immutable_refs=IMM, x2_ranges=x2_for(loc))

    def test_differs_with_recorded_settings_is_mismatch(self) -> None:
        dep = evm_dep_match(family="evm", candidate=cand(), build_status="ok", build_reason=None,
                            comparison=self._diff())
        assert dep.match == "mismatch"

    @pytest.mark.parametrize("pinned_by", ["pragma", "pragma_guess", "cbor"])
    def test_differs_without_recorded_settings_is_not_checkable(self, pinned_by: str) -> None:
        dep = evm_dep_match(family="evm", candidate=cand(pinned_by), build_status="ok", build_reason=None,
                            comparison=self._diff())
        assert (dep.match, dep.reason) == ("not_checkable", "settings_unknown")

    def test_tron_difference_without_uv5_05_is_not_mismatch(self) -> None:
        dep = evm_dep_match(family="tron", candidate=cand("tronscan"), build_status="ok", build_reason=None,
                            comparison=self._diff())
        assert (dep.match, dep.reason) == ("not_checkable", "tron_compiler_unmapped")
        dep = evm_dep_match(family="tron", candidate=cand("tronscan"), build_status="ok", build_reason=None,
                            comparison=self._diff(), uv5_05_passed=True)
        assert dep.match == "mismatch"

    def test_difference_with_trailer_only_auxdata_is_not_mismatch(self) -> None:
        loc = local_runtime()
        cmp = compare_runtime(loc.hex(), bytes(TAMPERED).hex(), immutable_refs=IMM, x2_ranges=None)
        dep = evm_dep_match(family="evm", candidate=cand(), build_status="ok", build_reason=None, comparison=cmp)
        assert (dep.match, dep.reason) == ("not_checkable", "auxdata_rule_missing")

    def test_vyper_difference_is_auxdata_rule_missing(self) -> None:
        dep = evm_dep_match(family="evm", candidate=cand(language="vyper"), build_status="ok",
                            build_reason=None, comparison=self._diff())
        assert (dep.match, dep.reason) == ("not_checkable", "auxdata_rule_missing")

    @pytest.mark.parametrize(("detail", "reason"), [
        ("compiler_binary_missing", "compiler_binary_missing"),
        ("compiler_version_unknown", "settings_unknown"),
        ("tron_compiler_unmapped", "tron_compiler_unmapped"),
        ("sandbox_unavailable", "build_failed"),
        (None, "build_failed"),
    ])
    def test_build_failure_reasons(self, detail: str | None, reason: str) -> None:
        dep = evm_dep_match(family="evm", candidate=cand(), build_status="failed", build_reason=detail,
                            comparison=None)
        assert (dep.match, dep.reason) == ("not_checkable", reason)


class TestTier:
    @pytest.mark.parametrize(("src", "addr", "match", "tier"), [
        (False, "0x1", "exact", "D"),
        (True, None, None, "B"),
        (True, "0x1", "exact", "A"),
        (True, "0x1", "metadata_only", "A"),
        (True, "0x1", "third_party_verified_only", "B"),
        (True, "0x1", "not_checkable", "B"),
        (True, "0x1", "mismatch", "C"),
    ])
    def test_code_tier_table(self, src: bool, addr: str | None, match: str | None, tier: str) -> None:
        assert code_tier(src, addr, match) == tier

    @pytest.mark.parametrize("bad", [None, "", "full", "partial"])
    def test_unknown_match_fails_e_tier_unknown(self, bad: str | None) -> None:
        with pytest.raises(ReviewError) as exc:
            code_tier(True, "0x1", bad)
        assert exc.value.code == "E_TIER_UNKNOWN"

    def test_unit_tier_proxy(self) -> None:
        assert unit_tier("A", None) == ("A", None)
        assert unit_tier("A", {"runtime_matches_standard_proxy": True}) == ("A", None)
        assert unit_tier("A", {"tier": "C"}) == ("C", None)
        assert unit_tier("A", {}) == ("B", "proxy_unmatched")


class TestDecisionPoint:
    """resolve_provenance + evm_deployment_check: what the supervisor calls."""

    def test_masked_match_gives_tier_a(self) -> None:
        c = cand()
        dep = evm_deployment_check(family="evm", build=build_of(c, local_runtime()),
                                   onchain_runtime="0x" + onchain_runtime(hash_byte=0xBB).hex())
        assert (dep.match, dep.contract) == ("metadata_only", "A.sol:A")
        assert resolve_provenance(candidate=c, address="0x1", dep=dep)["tier"] == "A"

    def test_tampered_byte_is_not_tier_a(self) -> None:
        c = cand()
        dep = evm_deployment_check(family="evm", build=build_of(c, local_runtime()),
                                   onchain_runtime=bytes(TAMPERED).hex())
        prov = resolve_provenance(candidate=c, address="0x1", dep=dep)
        assert dep.match == "mismatch" and prov["tier"] == "C"
        assert prov["dep"]["comparison"]["differing"] == [[60, 61]]

    def test_untrusted_inputs_never_tier_a(self) -> None:
        """06 3.3.4 trust flag reaches the decision: an exact rebuild is still not tier A."""
        c = cand(untrusted=True)
        dep = evm_deployment_check(family="evm", build=build_of(c, local_runtime()),
                                   onchain_runtime=onchain_runtime().hex())
        assert dep.match == "exact"
        prov = resolve_provenance(candidate=c, address="0x1", dep=dep)
        assert prov["tier"] == "B"
        assert prov["dep"]["match"] == "not_checkable"
        assert prov["dep"]["reason"] == "untrusted_build_inputs"

    def test_no_onchain_runtime_is_not_checkable(self) -> None:
        dep = evm_deployment_check(family="evm", build=build_of(cand(), local_runtime()), onchain_runtime="0x")
        assert (dep.match, dep.reason) == ("not_checkable", "state_changed_during_read")

    def test_unnamed_entry_picks_matching_artifact(self) -> None:
        c = cand(entry=None)
        dep = evm_deployment_check(family="tron", build=build_of(c, local_runtime()),
                                   onchain_runtime=onchain_runtime().hex())
        assert (dep.match, dep.contract) == ("exact", "A.sol:A")

    def test_unnamed_entry_without_match_is_not_mismatch(self) -> None:
        c = cand(entry=None)
        dep = evm_deployment_check(family="evm", build=build_of(c, local_runtime()),
                                   onchain_runtime=bytes(TAMPERED).hex())
        assert dep.match == "not_checkable"

    def test_build_failed_is_tier_b(self) -> None:
        c = cand()
        br = BuildResult(candidate=c, status="failed", reason="compiler_binary_missing")
        dep = evm_deployment_check(family="evm", build=br, onchain_runtime="0x6080")
        assert resolve_provenance(candidate=c, address="0x1", dep=dep)["tier"] == "B"

    def test_no_source_is_tier_d_and_no_address_is_b(self) -> None:
        assert resolve_provenance(candidate=None, address="0x1", dep=None)["tier"] == "D"
        assert resolve_provenance(candidate=cand(), address=None, dep=None)["tier"] == "B"

    def test_dep_outside_vocabulary_fails(self) -> None:
        with pytest.raises(ReviewError):
            resolve_provenance(candidate=cand(), address="0x1", dep=DepResult("partial"))
