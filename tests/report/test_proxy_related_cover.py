"""The report of a proxy job names the proxy and the implementation, and lists related contracts
(matrix run 2026-10-31: Venus got two PDFs for one address, Magnum three jobs for one system)."""

from __future__ import annotations

from soken_review.report.assemble import _build_verification_blocks, provenance
from soken_review.report.kit.build import build, validate

from .fixtures import report
from .test_tier_ac_provenance import _cands, _chain_state, _deployment, _job

IMPL = "0x43506849d7c04f9138d1a2050bbf3a0c054402dd"
ADMIN = "0x807a96288a1a408dbc13de2b1d087d10356395d2"
PF = "0x7366388273111e035bbc555cd0f44a5bb3067c32"


def _proxy_cs() -> dict:
    cs = _chain_state()
    cs["proxy"] = {"pattern_name": "eip1967_transparent", "proxy": cs["address"].lower(), "implementation": IMPL,
                   "admin": ADMIN, "proxy_bytecode": "0x6080"}
    return cs


RELATED = [
    {"name": "proxy", "address": "0xc2181d975c05c8c724b334bced0764c0b86b1d53", "status": "pinned", "role": "proxy"},
    {"name": "PriceFeed", "address": PF, "status": "pinned", "path": "_related/PriceFeed"},
    {"name": "Gone", "address": "0x" + "12" * 20, "status": "no_code", "note": "x"},
]


def test_provenance_names_implementation_admin_and_related():
    prov = provenance(_job("A"), _cands(), _proxy_cs(), _deployment(), related=RELATED)
    assert prov["address"] == "0xC2181D975c05c8C724b334BcED0764C0b86B1D53"
    assert prov["implementation"] == IMPL and prov["proxy_pattern"] == "eip1967_transparent"
    assert prov["upgradeable"] is True and prov["upgrade_authority"] == {"addr": ADMIN}
    # the proxy line is the cover's Proxy/Implementation pair, not a related row
    assert prov["related"] == [{"name": "PriceFeed", "address": PF, "status": "pinned"},
                               {"name": "Gone", "address": "0x" + "12" * 20, "status": "no_code"}]


def test_plain_contract_provenance_unchanged():
    prov = provenance(_job("A"), _cands(), _chain_state(), _deployment())
    assert "implementation" not in prov and "related" not in prov
    assert prov["upgrade_authority"] == "NotChecked"


def test_verification_table_shows_proxy_and_implementation():
    rows = _build_verification_blocks(_deployment(), _proxy_cs(), _job("A"))[0]["table"]["rows"]
    labels = [r[0] for r in rows]
    assert labels[:4] == ["Proxy address", "Proxy pattern", "Implementation", "Proxy admin"]
    assert rows[2][1] == {"addr": IMPL}
    assert "Implementation code hash" in labels and "On-chain code hash" not in labels


def test_cover_prints_proxy_implementation_and_related(tmp_path):
    r = report(tier="B", label_key="tier_b_third_party")
    r["meta"]["provenance"].update({"address": "0xC2181D975c05c8C724b334BcED0764C0b86B1D53",
                                    "implementation": IMPL, "proxy_pattern": "eip1967_transparent",
                                    "related": [{"name": "PriceFeed", "address": PF, "status": "pinned"},
                                                {"name": "Gone", "address": "0x" + "12" * 20, "status": "no_code"}]})
    validate(r)
    res = build(r, tmp_path)
    html = res.html_path.read_text()
    assert "Implementation" in html and IMPL in html
    assert "Related contracts" in html and "PriceFeed" in html
    assert "reviewed in this job" in html and "no contract code, not reviewed" in html
