"""Architecture diagram and roles rows from map.v1 (08 2.2): real maps from the fixtures, schema, kit fit."""

from __future__ import annotations

import copy
import gzip
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from soken_review.mapping.build import build_map
from soken_review.mapping.step import family_categories
from soken_review.report import architecture as arch
from soken_review.report.architecture import architecture_block, no_map_block, role_rows
from soken_review.report.kit.build import build, check_strings, diagram, kit_texts, schema, validate

from .fixtures import report

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "map"
CATS = list(family_categories("evm"))
OWNER = "0x1111111111111111111111111111111111111111"
ADMIN = "0x2222222222222222222222222222222222222222"
IMPL = "0x3333333333333333333333333333333333333333"
ADDRESS = "0xc2181d975c05c8c724b334bcED0764c0b86B1D53"


def _fact(key: str, value: str, unit_id: str) -> dict:
    return {"key": key, "value": value, "unit": None, "unit_id": unit_id, "source": "eth_call at block 1", "tags": []}


@pytest.fixture(scope="module")
def vault() -> dict:
    out = json.loads((FIX / "vault_solc_output.json").read_text())
    return build_map({"src/Vault.sol": (FIX / "Vault.sol").read_text()}, out, CATS).doc


@pytest.fixture(scope="module")
def guardrules() -> dict:
    out = json.loads((FIX / "guardrules_solc_output.json").read_text())
    return build_map({"src/GuardRules.sol": (FIX / "GuardRules.sol").read_text()}, out, CATS).doc


@pytest.fixture(scope="module")
def masterchef() -> dict:
    d = FIX / "masterchef_crlf"
    crlf = (d / "MasterChef.crlf.sol").read_bytes().decode("utf-8")
    with gzip.open(d / "solc_output.sources.json.gz", "rt", encoding="utf-8") as fh:
        out = json.load(fh)
    return build_map({"MasterChef.sol": crlf.replace("\r\n", "\n")}, out, CATS,
                     compiled_texts={"MasterChef.sol": crlf}).doc


@pytest.fixture(scope="module")
def maps(vault, guardrules, masterchef) -> dict[str, tuple[dict, list, dict]]:
    """name -> (map, facts, job) for the three real maps; Vault and MasterChef are deployed."""
    return {
        "vault": (vault, [_fact("onchain.owner", OWNER, "src/Vault.sol:Vault")], {"address": ADDRESS}),
        "guardrules": (guardrules, [], {}),
        "masterchef": (masterchef, [_fact("onchain.owner", OWNER, "MasterChef.sol:MasterChef")], {"address": ADDRESS}),
    }


def _errors(defn: str, obj) -> list[str]:
    s = schema()["$defs"]
    return [e.message for e in Draft202012Validator({"$defs": s, **s[defn]}).iter_errors(obj)]


def _node(block: dict, nid: str) -> dict:
    return next(n for n in block["nodes"] if n["id"] == nid)


def _edge(block: dict, a: str, b: str) -> dict | None:
    return next((e for e in block["edges"] if e["a"] == a and e["b"] == b), None)


# ── every produced block: schema, kit fit, caps, determinism ────────────────


def test_every_block_validates_and_fits_the_kit_diagram(maps):
    for name, (doc, facts, job) in maps.items():
        block = architecture_block(doc, facts, job, None)
        assert _errors("architecture", block) == [], name
        assert len(block["nodes"]) <= arch.MAX_NODES and len(block["edges"]) <= arch.MAX_EDGES
        assert block["rows"] <= arch.MAX_ROWS and block["cols"] == 4
        assert [n["id"] for n in block["nodes"]] != ["no_map"], name
        diagram(block)  # raises diagram_fit on any node outside the grid or label too long
        for row in role_rows(doc, facts, job):
            assert _errors("role_row", row) == [], (name, row)


def test_repeated_builds_are_identical(maps):
    for doc, facts, job in maps.values():
        a, b = architecture_block(doc, facts, job, None), architecture_block(copy.deepcopy(doc), list(facts), dict(job), None)
        assert a == b
        assert role_rows(doc, facts, job) == role_rows(copy.deepcopy(doc), list(facts), dict(job))


def test_every_edge_joins_two_present_nodes_and_no_edge_crosses_a_box(maps):
    for doc, facts, job in maps.values():
        block = architecture_block(doc, facts, job, None)
        box = arch._boxes(block["nodes"], block["row_height"])
        for e in block["edges"]:
            assert e["a"] in box and e["b"] in box
            seg = arch._segment(box, e["a"], e["b"])
            assert not any(arch._crosses(seg, box[o]) for o in box if o not in (e["a"], e["b"])), e


# ── Vault: one unit, two roles, low-level calls, owner fact ────────────────


def test_vault_nodes_edges_and_roles(vault):
    facts = [_fact("onchain.owner", OWNER, "src/Vault.sol:Vault")]
    block = architecture_block(vault, facts, {"address": ADDRESS}, None)
    ids = {n["id"] for n in block["nodes"]}
    assert ids == {"a_public", "a_inline_sender_check", "a_onlyowner", "u_vault", "x_any_address"}
    assert _node(block, "u_vault") == {"id": "u_vault", "label": "Vault", "kind": "scope", "sub": "deployed, 4 entries",
                                       "col": 1.5, "row": 1}
    assert _node(block, "x_any_address")["kind"] == "ext" and _node(block, "x_any_address")["sub"] == "call, transfer"
    assert _node(block, "a_onlyowner")["kind"] == "actor"
    assert _edge(block, "a_onlyowner", "u_vault")["label"] == "setFee"
    assert _edge(block, "a_inline_sender_check", "u_vault")["label"] == "sweep"
    assert _edge(block, "a_public", "u_vault") is not None and "label" not in _edge(block, "a_public", "u_vault")
    assert _edge(block, "u_vault", "x_any_address")["label"] == "2 calls"
    assert block["rows"] == 3 and block["row_height"] == arch.ROW_HEIGHT

    rows = role_rows(vault, facts, {"address": ADDRESS})
    assert rows == [
        {"role": "msg.sender check", "holder": "Unknown", "type": "Unknown", "gated_functions": ["Vault.sweep"],
         "risk_note": "Can move funds held by the contract"},
        {"role": "onlyOwner", "holder": {"addr": OWNER}, "type": "Unknown", "gated_functions": ["Vault.setFee"],
         "risk_note": "Can change fees or rates"},
    ]


def test_vault_renounced_owner_and_no_facts(vault):
    zero = [_fact("onchain.owner", "0x" + "0" * 40, "src/Vault.sol:Vault")]
    assert role_rows(vault, zero, {"address": ADDRESS})[1]["holder"] == "Renounced"
    rows = role_rows(vault, [], {})
    assert [r["holder"] for r in rows] == ["Unknown", "Unknown"]
    block = architecture_block(vault, [], {}, None)
    assert _node(block, "u_vault")["sub"] == "4 entries"


def test_vault_deployed_unit_from_deployment_json(vault):
    block = architecture_block(vault, [], {}, {"dep": {"contract": "src/Vault.sol:Vault"}})
    assert _node(block, "u_vault")["sub"] == "deployed, 4 entries"


def test_eip1967_proxy_and_admin_from_facts(vault):
    facts = [_fact("onchain.eip1967.implementation", IMPL, "src/Vault.sol:Vault"),
             _fact("onchain.eip1967.admin", ADMIN, "src/Vault.sol:Vault"),
             _fact("onchain.owner", OWNER, "src/Vault.sol:Vault")]
    block = architecture_block(vault, facts, {"address": ADDRESS}, None)
    assert _errors("architecture", block) == []
    diagram(block)
    proxy, admin = _node(block, "x_proxy"), _node(block, "a_proxy_admin")
    assert proxy["kind"] == "ext" and proxy["sub"] == "0xc218...1D53" and proxy["row"] == 0
    assert admin["kind"] == "actor" and admin["sub"] == "0x2222...2222"
    assert _edge(block, "x_proxy", "u_vault")["label"] == "delegatecall"
    assert _edge(block, "a_proxy_admin", "x_proxy") is not None
    rows = role_rows(vault, facts, {"address": ADDRESS})
    assert rows[0] == {"role": "Proxy admin", "holder": {"addr": ADMIN}, "type": "Unknown", "gated_functions": [],
                       "risk_note": "Can replace the contract code"}   # the upgrade authority leads the table
    assert rows[2]["holder"] == {"addr": OWNER}


# ── GuardRules: four units, one inline role, no deployment ─────────────────


def test_guardrules_four_units_one_row_no_externals(guardrules):
    block = architecture_block(guardrules, [], {}, None)
    units = [n for n in block["nodes"] if n["kind"] == "scope"]
    assert [n["label"] for n in units] == ["CallerRules", "LockRules", "PauseRules", "InitRules"]
    assert all(n["row"] == 1 for n in units) and [n["col"] for n in units] == [0, 1, 2, 3]
    assert not [n for n in block["nodes"] if n["kind"] == "ext"]
    assert _edge(block, "a_inline_sender_check", "u_callerrules")["label"] == "5 functions"
    assert len([e for e in block["edges"] if e["a"] == "a_public"]) == 4
    rows = role_rows(guardrules, [], {})
    assert len(rows) == 1 and rows[0]["gated_functions"][0] == "CallerRules.okAllowList"
    assert rows[0]["risk_note"] == "Gates the listed functions"  # no write, call or category signal


# ── MasterChef: eight units, inheritance, libraries, external tokens, overflow ──


def test_masterchef_layout_caps_and_summary_node(masterchef):
    facts = [_fact("onchain.owner", OWNER, "MasterChef.sol:MasterChef")]
    block = architecture_block(masterchef, facts, {"address": ADDRESS}, None)
    assert block["rows"] == 4
    mc, sushi = _node(block, "u_masterchef"), _node(block, "u_sushitoken")
    assert mc["sub"] == "deployed, 13 entries" and mc["row"] == 1 and sushi["row"] == 1
    assert _node(block, "u_erc20")["row"] == _node(block, "u_ownable")["row"] == 3     # bases below
    assert _node(block, "u_address")["sub"] == "library"
    assert _node(block, "u_more_s") == {"id": "u_more_s", "label": "Other units", "kind": "scope", "sub": "+3 more",
                                        "col": 2.0, "row": 3}
    ext = {n["id"]: n for n in block["nodes"] if n["kind"] == "ext"}
    assert set(ext) == {"x_ierc20", "x_imigratorchef", "x_any_address"} and all(n["row"] == 2 for n in ext.values())
    assert ext["x_ierc20"]["sub"] == "allowance, balanceOf"
    assert _edge(block, "u_masterchef", "x_ierc20")["label"] == "balanceOf"
    assert _edge(block, "u_masterchef", "x_imigratorchef")["label"] == "migrate"
    assert _edge(block, "u_masterchef", "u_ownable")["label"] == "inherits"
    # inherited functions count on the contracts that inherit them, not on the base
    assert _edge(block, "a_onlyowner", "u_masterchef")["label"] == "5 functions"
    assert _edge(block, "a_onlyowner", "u_sushitoken")["label"] == "3 functions"
    assert _edge(block, "a_onlyowner", "u_ownable") is None
    assert _edge(block, "a_inline_sender_check", "u_masterchef")["label"] == "dev"


def test_masterchef_roles_split_by_unit_with_owner_on_the_deployed_group(masterchef):
    facts = [_fact("onchain.owner", OWNER, "MasterChef.sol:MasterChef")]
    rows = role_rows(masterchef, facts, {"address": ADDRESS})
    assert [r["role"] for r in rows] == ["msg.sender check", "onlyOwner (MasterChef)", "onlyOwner (SushiToken)"]
    mc = rows[1]
    assert mc["holder"] == {"addr": OWNER}
    assert mc["gated_functions"] == ["MasterChef.add", "MasterChef.set", "MasterChef.setMigrator",
                                     "Ownable.renounceOwnership", "Ownable.transferOwnership"]
    assert mc["risk_note"] == ("Can transfer or renounce the role; Can change reward settings; "
                               "Can set a migration target")
    assert rows[2] == {"role": "onlyOwner (SushiToken)", "holder": "Unknown", "type": "Unknown",
                       "gated_functions": ["SushiToken.mint"], "risk_note": "Can mint tokens"}
    assert rows[0]["risk_note"] == "Can change addresses the contract calls or pays"   # dev(): writes devaddr


# ── empty map, label cut, overloads ─────────────────────────────────────────


def test_no_semantic_layer_keeps_the_no_map_stub(vault):
    lexical = {k: v for k, v in vault.items() if k != "semantic"}
    assert architecture_block(lexical, [], {}, None) == no_map_block()
    assert architecture_block(None, [], {}, None) == no_map_block()
    assert role_rows(lexical, [], {}) == [] and role_rows(None, None, None) == []
    assert no_map_block()["nodes"][0]["id"] == "no_map"


def test_long_names_are_cut_to_the_kit_fit_rule(vault):
    doc = copy.deepcopy(vault)
    long = "AVeryLongContractNameThatDoesNotFitTheCell"
    doc["semantic"]["units"][0]["name"] = long
    for f in doc["semantic"]["functions"]:
        f["span"] = f["span"].replace("Vault.", long + ".")
    for r in doc["semantic"]["roles"]:
        r["gated_functions"] = [s.replace("Vault.", long + ".") for s in r["gated_functions"]]
    doc["semantic"]["roles"][1]["name"] = "onlyTheOwnerOrOperatorOfThisVaultContract"
    block = architecture_block(doc, [], {}, None)
    diagram(block)
    unit = next(n for n in block["nodes"] if n["kind"] == "scope")
    assert unit["label"] == "AVeryLongContractName..." and len(unit["label"]) == arch.LABEL_MAX
    assert len(unit["id"]) <= 24


def test_overloaded_gated_functions_keep_their_parameter_list(vault):
    doc = copy.deepcopy(vault)
    doc["semantic"]["roles"][1]["gated_functions"] = ["Vault.setFee(uint256)", "Vault.setFee(uint256,bool)"]
    assert role_rows(doc, [], {})[1]["gated_functions"] == ["Vault.setFee(uint256)", "Vault.setFee(uint256,bool)"]


# ── through the kit: a full report with the real blocks builds and prints the roles table ──


def test_fixture_report_with_real_blocks_builds(tmp_path, masterchef):
    facts = [_fact("onchain.owner", OWNER, "MasterChef.sol:MasterChef")]
    r = report(2)
    r["architecture"] = architecture_block(masterchef, facts, {"address": ADDRESS}, None)
    r["roles"]["rows"] = role_rows(masterchef, facts, {"address": ADDRESS})
    validate(r)
    check_strings(r)   # risk notes and subs pass the model and server text gates
    html = build(r, tmp_path, mode="print").html_path.read_text(encoding="utf-8")
    assert kit_texts()["no_map_line"] not in html
    assert "Privileged roles" in html and "onlyOwner (MasterChef)" in html
    assert "Can set a migration target" in html and "deployed, 13 entries" in html
