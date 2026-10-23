"""Context facts (spec section 5): one fixture per kind, expected keys, values and sources."""

from __future__ import annotations

from pathlib import Path

import pytest

from soken_review.context import facts as cf
from soken_review.context.store import HEADER_LINES, ContextStore
from soken_review.mapping.facts import load_facts, write_facts

from .conftest import JOB_ID, doc

JOB = {"job_id": JOB_ID, "chain": "evm", "chain_id": 1, "address": "0xc2edad668740f1aa35e4d8f227fb8e17dca888cd"}


def _by_key(facts: list[dict]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for f in facts:
        out.setdefault(f["key"], []).append(f)
    return out


def _line_of(store: ContextStore, path: str, needle: str) -> int:
    for i, line in enumerate(store.read_all(path), start=1):
        if needle in line:
            return i
    raise AssertionError(needle)


@pytest.fixture
def store(tmp_path: Path, fixtures: Path) -> ContextStore:
    s = ContextStore.load(tmp_path, JOB_ID)
    s.add([
        doc("whitepaper", "https://sample.example/wp.md", (fixtures / "whitepaper.md").read_text(), title="Whitepaper"),
        doc("terms", "https://sample.example/terms", (fixtures / "terms.md").read_text(), title="Terms"),
        doc("privacy", "https://sample.example/privacy", (fixtures / "privacy.md").read_text(), title="Privacy"),
        doc("app", "https://app.sample.example/", "Sample App\n\nYou need to enable JavaScript.", title="Sample App",
            bundle_hits={"addresses": {"evm": ["0xc2edad668740f1aa35e4d8f227fb8e17dca888cd",
                                               "0x3ee18b2214aff97000d974cf647e7c347e8fa585"]},
                         "chain_ids": [1, 56], "bundles": [{"url": "https://app.sample.example/static/main.js",
                                                            "bytes": 10, "status": "ok"}]}),
        doc("docs", "https://docs.sample.example/", "", status="failed", error="timeout"),
    ])
    return s


def test_every_fact_is_tagged_and_sourced(store: ContextStore) -> None:
    facts = cf.context_facts(store, JOB)
    assert facts, "no facts"
    for f in facts:
        assert f["key"].startswith("context.")
        assert f["tags"] == ["context"], f
        path, _, line = f["source"].rpartition(":")
        assert path.startswith("context/") and line.isdigit() and int(line) >= 1, f
        assert store.get_entry(path) is not None
        assert int(line) <= store.line_count(path)
    assert facts == sorted(facts, key=lambda f: (f["key"], f["source"].rpartition(":")[0], int(f["source"].rpartition(":")[2])))
    assert not any(f["key"].startswith("context.docs.") for f in facts)   # the failed document yields nothing


def test_whitepaper_supply_fees_admin_audit_chains(store: ContextStore) -> None:
    by = _by_key(cf.context_facts(store, JOB))
    wp = "context/whitepaper-1.md"
    ts = by["context.whitepaper.total_supply"]
    assert len(ts) == 1 and ts[0]["value"] == "1000000000" and ts[0]["unit"] == "tokens"
    assert ts[0]["source"] == f"{wp}:{_line_of(store, wp, 'total supply of 1,000,000,000')}"
    assert by["context.whitepaper.max_supply"][0]["value"] == "1000000000"      # "1 billion"
    assert by["context.whitepaper.decimals"][0]["value"] == "18"
    fees = [(f["value"], f["unit"]) for f in by["context.whitepaper.fee_pct"]]
    assert fees == [("2", "percent"), ("30", "bps"), ("0.25", "percent")]      # one record per figure and line
    labels = [f["label"] for f in by["context.whitepaper.fee_pct"]]
    assert labels[0].startswith("A transfer tax of 2% applies") and all(len(lb) <= 120 for lb in labels)
    admin = {f["value"]: f for f in by["context.whitepaper.admin_claims"]}
    assert set(admin) == {"renounced", "multisig", "timelock", "upgradeable", "immutable", "mint", "pausable"}
    assert admin["renounced"]["source"] == f"{wp}:{_line_of(store, wp, 'has been renounced')}"
    assert admin["multisig"]["phrase"].lower() == "multisig"
    audits = {f["value"] for f in by["context.whitepaper.audit_claims"]}
    assert {"Hacken", "PeckShield"} <= audits
    chains = {f["value"]: f for f in by["context.whitepaper.chains"]}
    assert chains["Ethereum Mainnet"]["chain_id"] == 1
    assert any(f.get("chain_id") == 56 for f in chains.values())
    assert "Solana" in chains and chains["Solana"]["chain"] == "solana"
    addrs = {(f["shape"], f["value"]) for f in by["context.whitepaper.addresses"]}
    assert ("evm", "0xc2edad668740f1aa35e4d8f227fb8e17dca888cd") in addrs
    assert ("solana", "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU") in addrs
    mention = by["context.whitepaper.mentions_reviewed_address"]
    assert len(mention) == 1 and mention[0]["value"] == "true"
    assert mention[0]["source"] == f"{wp}:{_line_of(store, wp, '0xc2edad668740f1aa35e4d8f227fb8e17dca888cd')}"


def test_terms_jurisdictions_and_kyc(store: ContextStore) -> None:
    by = _by_key(cf.context_facts(store, JOB))
    jur = {f["value"] for f in by["context.terms.restricted_jurisdictions"]}
    assert {"United States", "Canada", "China", "Iran", "North Korea", "Syria", "Cuba", "Crimea"} <= jur
    assert "British Virgin Islands" not in jur
    kyc = by["context.terms.kyc"]
    assert len(kyc) == 1 and kyc[0]["value"] == "true" and kyc[0]["phrase"].lower() in ("kyc", "identity verification")
    assert "context.terms.total_supply" not in by


def test_privacy_data_collected_and_contact(store: ContextStore) -> None:
    by = _by_key(cf.context_facts(store, JOB))
    data = {f["value"] for f in by["context.privacy.data_collected"]}
    assert {"wallet_address", "ip_address", "device", "cookies", "transaction_data", "Google Analytics", "Mixpanel"} <= data
    assert by["context.privacy.contact"][0]["value"] == "privacy@sample-protocol.example"


def test_app_bundle_hits_become_facts_on_the_title_line(store: ContextStore) -> None:
    by = _by_key(cf.context_facts(store, JOB))
    app = {f["value"]: f for f in by["context.app.addresses"]}
    assert app["0x3ee18b2214aff97000d974cf647e7c347e8fa585"]["via"] == "bundle"
    assert app["0x3ee18b2214aff97000d974cf647e7c347e8fa585"]["source"] == "context/app-1.md:1"
    assert by["context.app.mentions_reviewed_address"][0]["value"] == "true"
    assert {f["chain_id"] for f in by["context.app.chains"]} == {1, 56}


def test_mentions_false_and_no_deployment(store: ContextStore) -> None:
    other = dict(JOB, address="0x" + "9" * 40)
    by = _by_key(cf.context_facts(store, other))
    assert by["context.whitepaper.mentions_reviewed_address"][0]["value"] == "false"
    assert by["context.whitepaper.mentions_reviewed_address"][0]["source"] == f"context/whitepaper-1.md:{1}"
    by = _by_key(cf.context_facts(store, {"job_id": JOB_ID, "chain": "evm"}))
    assert not any(k.endswith("mentions_reviewed_address") for k in by)


def test_number_parsing() -> None:
    assert cf.parse_number("1,000,000,000 tokens") == 1_000_000_000
    assert cf.parse_number("1 billion SMP") == 1_000_000_000
    assert cf.parse_number("100M") == 100_000_000
    assert cf.parse_number("10^9") == 1_000_000_000
    assert cf.parse_number("2.5 million") == 2_500_000
    assert cf.parse_number("21000000") == 21_000_000
    assert cf.parse_number("18") == 18
    assert cf.parse_number("none") is None
    assert cf.parse_number("12 apples") is None          # an unknown unit word is not a count


def test_pdf_whitepaper_text_yields_supply(tmp_path: Path) -> None:
    store = ContextStore.load(tmp_path, JOB_ID)
    store.add([doc("whitepaper", "https://w.example/wp.pdf", "Total supply: 21,000,000 tokens.\n\nPage two: fee of 1% on transfers.",
                   content_type="application/pdf")])
    by = _by_key(cf.context_facts(store, {}))
    assert by["context.whitepaper.total_supply"][0]["value"] == "21000000"
    assert by["context.whitepaper.total_supply"][0]["source"] == f"context/whitepaper-1.md:{HEADER_LINES + 1}"
    assert by["context.whitepaper.fee_pct"][0]["value"] == "1"


def test_context_facts_file_merges_into_load_facts_and_never_into_facts_json(tmp_path: Path) -> None:
    code = [{"key": "source.files", "value": "1", "unit": None, "unit_id": None, "source": "pin manifest", "tags": []}]
    ctx = [cf.fact("context.docs.kyc", "true", source="context/docs-1.md:3")]
    write_facts(tmp_path, JOB_ID, code + ctx)               # a context fact handed to write_facts is dropped
    assert load_facts(tmp_path, JOB_ID) == code
    cf.write_context_facts(tmp_path, JOB_ID, ctx)
    merged = load_facts(tmp_path, JOB_ID)
    assert merged == code + ctx
    assert cf.load_context_facts(tmp_path, JOB_ID) == ctx
    write_facts(tmp_path, JOB_ID, merged)                   # a re-write of the merged list keeps the split
    assert load_facts(tmp_path, JOB_ID) == code + ctx
    assert cf.load_context_facts(tmp_path / "none", JOB_ID) == []
