"""Hashes, version decode, canonical felts and facts from the hashed program (07 5.1, 8.1, 8.2)."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from soken_review.adapters.starknet.felt import (
    NonCanonicalFelt,
    P,
    keccak256,
    normalize_address,
    parse_felt,
    poseidon_hash,
    selector,
)
from soken_review.adapters.starknet.map import nr_predicates
from soken_review.adapters.starknet.sierra import (
    ClassFacts,
    class_facts,
    class_hash,
    decode_versions,
    hex_felt,
    is_cairo0,
)
from soken_review.adapters.starknet.sierra_decode import (
    ARG_USER_FUNC,
    LibfuncDecl,
    Program,
    SierraDecodeError,
    Statement,
    reachable_statements,
)

FIX = Path(__file__).resolve().parents[2] / "fixtures" / "starknet"
UDC_HASH = "0x01b2df6d8861670d4a8ca4670433b2418d78169c2947f46dc614e69f333745c8"


@pytest.fixture
def udc() -> dict:
    # starknet_getClass of the mainnet UDC class (0x02ceed65...a2125), read 2026-10-10
    return json.loads((FIX / "udc_class_0x1b2df6d8.json").read_text())


def test_keccak_and_selector_vectors() -> None:
    assert keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    assert hex(selector("transfer")) == "0x83afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e"


def test_class_hash_matches_live_class(udc: dict) -> None:
    """Poseidon, sn_keccak and the class hash layout reproduce the mainnet class hash exactly."""
    assert hex_felt(class_hash(udc)) == UDC_HASH
    assert 0 <= poseidon_hash(1, 2) < P


def test_versions_decoded(udc: dict) -> None:
    v = decode_versions(udc["sierra_program"])
    assert (v.sierra, v.cairo) == ("1.7.0", "2.11.4")


def test_cairo0_class_detected() -> None:
    c0 = json.loads((FIX / "udc_cairo0_class_0x7b3e05f4.json").read_text())
    assert is_cairo0(c0)
    facts = class_facts(c0)
    assert not facts.complete and facts.error == "cairo0_class"


@pytest.mark.parametrize("bad", [P, P + 5, -1, "5", "0x" + "f" * 64, True, 1.0, "0xzz"])
def test_parse_felt_refuses_non_canonical(bad: object) -> None:
    with pytest.raises(NonCanonicalFelt):
        parse_felt(bad)


def test_felt_plus_p_in_program_is_refused_not_aliased(udc: dict) -> None:
    tampered = copy.deepcopy(udc)
    x = int(tampered["sierra_program"][10], 16)
    tampered["sierra_program"][10] = hex(x + P)   # same value mod P
    with pytest.raises(NonCanonicalFelt):
        class_hash(tampered)
    assert not class_facts(tampered).complete


def test_selector_alias_refused(udc: dict) -> None:
    tampered = copy.deepcopy(udc)
    ep = tampered["entry_points_by_type"]["EXTERNAL"][0]
    ep["selector"] = hex(int(ep["selector"], 16) + P)
    with pytest.raises(NonCanonicalFelt):
        class_hash(tampered)


@pytest.mark.parametrize("idx", [10_000, -1, "1", True])
def test_out_of_range_function_idx_gives_unknown_facts(udc: dict, idx: object) -> None:
    tampered = copy.deepcopy(udc)
    tampered["entry_points_by_type"]["EXTERNAL"][0]["function_idx"] = idx
    facts = class_facts(tampered)
    assert not facts.complete
    assert set(nr_predicates(facts).values()) == {"unknown"}


def test_out_of_range_user_func_arg_raises() -> None:
    prog = Program(types=[], libfuncs=[LibfuncDecl("function_call", [(ARG_USER_FUNC, 7)])],
                   statements=[Statement(0, [None]), Statement(None, [])], func_entries=[0])
    with pytest.raises(SierraDecodeError):
        reachable_statements(prog, [0])
    with pytest.raises(SierraDecodeError):
        reachable_statements(prog, [3])


def test_facts_from_hashed_program_ignore_tampered_debug_table(udc: dict) -> None:
    """The debug table is not hashed: renaming or removing names there changes nothing."""
    honest = class_facts(udc)
    assert "deploy_syscall" in honest.libfuncs
    tampered = copy.deepcopy(udc)
    tampered["sierra_program_debug_info"] = {
        "type_names": [], "user_func_names": [],
        "libfunc_names": [[0, "felt252_add"], [1, "renamed_call_contract_syscall"]],
    }
    facts = class_facts(tampered)
    assert facts.libfuncs == honest.libfuncs
    assert nr_predicates(facts)["nr_no_external_call"] == "false"


def test_udc_facts_and_predicates(udc: dict) -> None:
    facts = class_facts(udc)
    assert facts.complete
    assert "deploy_syscall" in facts.reachable["EXTERNAL"]
    nr = nr_predicates(facts)
    assert nr["nr_no_external_call"] == "false"      # deploy_syscall is a calling syscall
    assert nr["nr_no_upgrade_path"] == "true"


def _facts(libs: set[str]) -> ClassFacts:
    return ClassFacts(frozenset(libs), {}, frozenset(), complete=True)


def test_unknown_syscall_gives_unknown() -> None:
    nr = nr_predicates(_facts({"storage_read_syscall", "foo_syscall"}))
    assert nr["nr_no_external_call"] == "unknown"
    assert nr["nr_no_upgrade_path"] == "unknown"
    assert nr_predicates(_facts({"deploy_syscall"}))["nr_no_external_call"] == "false"
    assert nr_predicates(_facts({"meta_tx_v0_syscall"}))["nr_no_external_call"] == "false"
    assert nr_predicates(_facts({"storage_read_syscall"}))["nr_no_external_call"] == "true"
    assert set(nr_predicates(None).values()) == {"unknown"}


def test_token_transfer_needs_selector_and_call() -> None:
    f = ClassFacts(frozenset({"call_contract_syscall"}), {}, frozenset({selector("safeTransferFrom")}), complete=True)
    assert nr_predicates(f)["nr_no_token_transfer"] == "false"
    f2 = ClassFacts(frozenset({"call_contract_syscall"}), {}, frozenset(), complete=True)
    assert nr_predicates(f2)["nr_no_token_transfer"] == "unknown"


@pytest.mark.parametrize("addr,ok", [("0x1", True), ("0x" + "0" * 63 + "1", True), ("0x" + "f" * 64, False),
                                     ("0x", False), ("1234", False), ("0x" + "1" * 65, False)])
def test_address_validation(addr: str, ok: bool) -> None:
    assert (normalize_address(addr) is not None) == ok


def test_extract_components_from_substorage() -> None:
    """extract_components reads #[substorage(v0)] fields from all storage structs (07 10)."""
    from soken_review.adapters.starknet.source import extract_components, parse

    src = (
        "#[storage]\nstruct Storage {\n"
        "    #[substorage(v0)]\n    ownable: OwnableComponent::Storage,\n"
        "    #[substorage(v0)]\n    pub erc20: ERC20::Storage,\n"
        "    plain: u256,\n"
        "}\n"
    )
    cf = parse("src/lib.cairo", src)
    comps = extract_components([cf])
    assert comps == [
        {"path": "OwnableComponent", "storage_name": "ownable"},
        {"path": "ERC20", "storage_name": "erc20"},
    ]


def test_extract_components_deduplicates_across_files() -> None:
    from soken_review.adapters.starknet.source import extract_components, parse

    src = "#[storage]\nstruct Storage {\n    #[substorage(v0)]\n    comp: super::Comp::Storage,\n}\n"
    cf1 = parse("a.cairo", src)
    cf2 = parse("b.cairo", src)
    comps = extract_components([cf1, cf2])
    assert comps == [{"path": "super::Comp", "storage_name": "comp"}]


def test_extract_components_empty_when_no_substorage() -> None:
    from soken_review.adapters.starknet.source import extract_components, parse

    cf = parse("src/lib.cairo", "#[storage]\nstruct Storage { plain: u256, }\n")
    assert extract_components([cf]) == []


def test_chain_extras_components_from_static_map() -> None:
    """chain_extras forwards components[] from static_map into the output dict (07 10)."""
    from soken_review.adapters.starknet.map import chain_extras

    static_map = {
        "functions": [],
        "components": [{"path": "OwnableComponent", "storage_name": "ownable"}],
    }
    extras = chain_extras(None, None, static_map, None)
    assert extras["components"] == [{"path": "OwnableComponent", "storage_name": "ownable"}]


def test_chain_extras_components_empty_when_absent() -> None:
    from soken_review.adapters.starknet.map import chain_extras

    extras = chain_extras(None, None, {"functions": []}, None)
    assert extras["components"] == []


def test_rpc_class_body_must_hash_to_reported_hash(udc: dict) -> None:
    from soken_review.adapters.starknet.fetch import verified_state

    ok = verified_state("0x1", 1, "https://rpc.example/x", None, UDC_HASH, copy.deepcopy(udc))
    assert ok["class_verified"] and ok["class"] is not None and ok["cairo_version"] == "2.11.4"
    tampered = copy.deepcopy(udc)
    tampered["sierra_program"][20] = hex(int(tampered["sierra_program"][20], 16) ^ 1)
    bad = verified_state("0x1", 1, "https://rpc.example/x", None, UDC_HASH, tampered)
    assert not bad["class_verified"] and bad["class"] is None and bad["selectors"] is None
    assert bad["class_error"] == "class_body_hash_mismatch" and bad["cairo_version"] is None
