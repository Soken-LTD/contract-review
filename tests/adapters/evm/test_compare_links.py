"""Security review round 2 (2026-10-10): library self-address and linked libraries."""

from __future__ import annotations

from soken_review.adapters.base import Artifact, BuildResult, Candidate, Compiler
from soken_review.adapters.evm.compare import compare_runtime
from soken_review.engine.provenance import evm_deployment_check, resolve_provenance
from tests.adapters.evm.test_compare import CODE, IMM, auxdata, local_runtime, onchain_runtime, x2_for

SELF = "0x" + "ab" * 20


def _library(addr: bytes) -> bytes:
    return b"\x73" + addr + b"\x30\x14" + CODE + auxdata(0xAA)


def test_library_self_address_must_be_own_address() -> None:
    loc = _library(b"\x00" * 20)
    foreign = _library(b"\x99" * 20)
    cmp = compare_runtime(loc.hex(), foreign.hex(), immutable_refs={}, x2_ranges=x2_for(loc), self_address=SELF)
    assert cmp.outcome == "differs"
    own = _library(bytes.fromhex(SELF[2:]))
    cmp = compare_runtime(loc.hex(), own.hex(), immutable_refs={}, x2_ranges=x2_for(loc), self_address=SELF)
    assert cmp.outcome == "exact"


def test_library_self_address_unknown_is_differs() -> None:
    loc = _library(b"\x00" * 20)
    own = _library(bytes.fromhex(SELF[2:]))
    cmp = compare_runtime(loc.hex(), own.hex(), immutable_refs={}, x2_ranges=x2_for(loc), self_address=None)
    assert cmp.outcome == "differs"


def _linked(addr_a: bytes, addr_b: bytes) -> tuple[str, bytes, dict]:
    loc = local_runtime()
    h = loc.hex()
    ph = "__$" + "a" * 34 + "$__"
    h = h[:2 * 50] + ph + h[2 * 70:2 * 75] + ph + h[2 * 95:]
    chain = bytearray(onchain_runtime())
    chain[50:70] = addr_a
    chain[75:95] = addr_b
    links = {"L.sol": {"L": [{"start": 50, "length": 20}, {"start": 75, "length": 20}]}}
    return h, bytes(chain), links


def test_one_library_has_one_address() -> None:
    h, chain, links = _linked(b"\x42" * 20, b"\x43" * 20)
    cmp = compare_runtime(h, chain.hex(), immutable_refs=IMM, link_refs=links, x2_ranges=x2_for(local_runtime()))
    assert cmp.outcome == "differs"


def test_settings_libraries_are_stripped_and_not_tier_a() -> None:
    """solc links `settings.libraries` itself, so no linkReferences appear; the build must leave
    them unlinked and the decision must list them and withhold tier A."""
    from soken_review.adapters.evm.build import sanitize_std_input

    libs = {"L.sol": {"L": "0x" + "42" * 20}}
    std = {"language": "Solidity", "sources": {"A.sol": {"content": "x"}}, "settings": {"libraries": libs}}
    assert "libraries" not in sanitize_std_input(std)["settings"]

    loc = local_runtime()
    cand = Candidate(provider="sourcify", files={}, sha256="0" * 64, language="solidity",
                     compiler=Compiler("0.8.24", "sourcify"), settings={"libraries": libs},
                     std_json_input=None, entry_contract="A.sol:A")
    art = Artifact(contract="A.sol:A", creation="", runtime=loc.hex(), immutable_refs=IMM, link_refs={},
                   source_map="", storage_layout=None)
    build = BuildResult(candidate=cand, status="ok", artifacts=[art], auxdata_ranges={"A.sol:A": x2_for(loc)})
    dep = evm_deployment_check(family="evm", build=build, onchain_runtime=onchain_runtime().hex(), address="0x1")
    assert dep.match == "exact"
    prov = resolve_provenance(candidate=cand, address="0x1", dep=dep)
    assert (prov["tier"], prov["label_reason"]) == ("B", "libraries_unverified")
    assert {"check": "libraries", "result": "unverified", "library": "L.sol:L",
            "address": "0x" + "42" * 20, "source": "settings.libraries"} in prov["checks"]


def test_linked_library_unverified_is_not_tier_a() -> None:
    h, chain, links = _linked(b"\x42" * 20, b"\x42" * 20)
    loc = local_runtime()
    cand = Candidate(provider="sourcify", files={}, sha256="0" * 64, language="solidity",
                     compiler=Compiler("0.8.24", "sourcify"), settings={}, std_json_input=None, entry_contract="A.sol:A")
    art = Artifact(contract="A.sol:A", creation="", runtime=h, immutable_refs=IMM, link_refs=links,
                   source_map="", storage_layout=None)
    build = BuildResult(candidate=cand, status="ok", artifacts=[art], auxdata_ranges={"A.sol:A": x2_for(loc)})
    dep = evm_deployment_check(family="evm", build=build, onchain_runtime=chain.hex(), address="0x1")
    assert dep.match == "exact"
    assert dep.comparison["linked_libraries"] == {"L.sol:L": "0x" + "42" * 20}
    prov = resolve_provenance(candidate=cand, address="0x1", dep=dep)
    assert prov["tier"] == "B"
    assert prov["label_reason"] == "libraries_unverified"
    assert prov["checks"] == [{"check": "libraries", "result": "unverified", "library": "L.sol:L",
                               "address": "0x" + "42" * 20}]
