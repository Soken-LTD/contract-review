"""Tier A and C provenance assembly and verification blocks (08 3.1, plan K3 part 08)."""

from __future__ import annotations

import hashlib

from soken_review.report.assemble import provenance
from soken_review.report.kit.build import check_strings, kit_texts, validate

from .fixtures import report

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

_BYTECODE = "0x6080604052" + "ab" * 100  # fake but parseable on-chain runtime


def _chain_state(block: int = 158_237_689) -> dict:
    return {
        "chain_id": 10,
        "address": "0xC2181D975c05c8C724b334BcED0764C0b86B1D53",
        "bytecode": _BYTECODE,
        "block": block,
    }


def _deployment(
    match: str = "metadata_only",
    reason: str | None = None,
    detail: str | None = None,
    linked_libraries: dict | None = None,
) -> dict:
    return {
        "tier": "A" if match != "differs" else "C",
        "dep": {
            "match": match,
            "reason": reason,
            "contract": "GovernanceToken.sol:GovernanceToken",
            "comparison": {
                "outcome": match,
                "local_len": 16528,
                "onchain_len": 16528,
                "immutable_ranges": [],
                "link_ranges": [],
                "auxdata_ranges": [],
                "auxdata_source": "x2",
                "unmasked_x2": [],
                "linked_libraries": linked_libraries or {},
                "masked_bytes": {"immutables": 224, "links": 0, "auxdata": 53},
                "differing": [],
                "differing_bytes": 0,
                "detail": detail,
            },
            "notes": [],
        },
        "candidate": {
            "provider": "sourcify",
            "sha256": "6f56dd" + "00" * 29,
            "compiler": "0.8.12+commit.f00d7308",
            "version_pinned_by": "sourcify",
            "untrusted_inputs": False,
        },
        "block": 158_237_689,
    }


def _deployment_c(reason: str = "differs") -> dict:
    d = _deployment(match="differs")
    d["tier"] = "C"
    d["dep"]["reason"] = reason
    d["dep"]["comparison"]["differing_bytes"] = 42
    return d


def _job(tier: str, today_str: str = "2026-10-15") -> dict:
    return {
        "tier": tier,
        "source_pin": "b4cc916ccf88bed8f28f6c15752c424fe8ef881983807d4240895a129f9adf49",
        "address": "0xC2181D975c05c8C724b334BcED0764C0b86B1D53",
        "chain_id": 10,
        "resolved_commit": None,
        "source_args": {},
        "ownership_proven": False,
        "requester_role": "third_party_public_code",
    }


def _cands() -> list:
    return [{"provider": "sourcify", "entry_contract": "GovernanceToken.sol:GovernanceToken",
              "explorer_verified": True, "sourcify_match": "match"}]


def _expected_code_hash() -> str:
    raw = bytes.fromhex(_BYTECODE.removeprefix("0x"))
    return "sha256:" + hashlib.sha256(raw).hexdigest()


# ---------------------------------------------------------------------------
# Unit tests for provenance()
# ---------------------------------------------------------------------------

class TestProvenanceTierA:
    def test_required_fields_present(self):
        prov = provenance(_job("A"), _cands(), _chain_state(), _deployment())
        assert prov["tier"] == "A"
        assert prov["label_key"] == "tier_a"
        assert prov["source_hash"] == _job("A")["source_pin"]
        assert prov["address"] == "0xC2181D975c05c8C724b334BcED0764C0b86B1D53"
        assert "code_hash" in prov
        assert "as_of" in prov
        # No on-chain evidence about an upgrade path is read for EVM today, so no claim is made:
        # the cover prints the kit text "Not checked in this review" instead of "Renounced".
        assert prov["upgrade_authority"] == "NotChecked"
        assert "upgradeable" not in prov

    def test_code_hash_is_sha256_of_bytecode(self):
        prov = provenance(_job("A"), _cands(), _chain_state(), _deployment())
        assert prov["code_hash"] == _expected_code_hash()

    def test_as_of_block_and_date(self):
        prov = provenance(_job("A"), _cands(), _chain_state(block=123456), _deployment())
        assert prov["as_of"]["block_or_slot"] == 158_237_689  # from deployment.json["block"]
        assert prov["as_of"]["date"]  # non-empty date string

    def test_label_contains_block_number(self):
        prov = provenance(_job("A"), _cands(), _chain_state(), _deployment())
        assert "158237689" in prov["label"] or "158,237,689" in prov["label"]

    def test_label_contains_unit_block(self):
        prov = provenance(_job("A"), _cands(), _chain_state(), _deployment())
        assert "block" in prov["label"].lower()

    def test_no_assembly_error_raised(self):
        # Must not raise any more
        prov = provenance(_job("A"), _cands(), _chain_state(), _deployment())
        assert prov is not None


class TestProvenanceTierC:
    def test_required_fields_present(self):
        prov = provenance(_job("C"), _cands(), _chain_state(), _deployment_c())
        assert prov["tier"] == "C"
        assert prov["label_key"] == "tier_c"
        assert prov["source_hash"] == _job("C")["source_pin"]
        assert prov["address"] == "0xC2181D975c05c8C724b334BcED0764C0b86B1D53"

    def test_tier_c_label_from_kit(self):
        t = kit_texts()
        prov = provenance(_job("C"), _cands(), _chain_state(), _deployment_c())
        assert prov["label"] == t["tier_labels"]["tier_c"]

    def test_code_hash_set_when_bytecode_present(self):
        prov = provenance(_job("C"), _cands(), _chain_state(), _deployment_c())
        assert "code_hash" in prov
        assert prov["code_hash"] == _expected_code_hash()


class TestProvenanceTierBUnchanged:
    def test_tier_b_still_works_without_deployment(self):
        job = _job("B")
        job["address"] = "0xC2181D975c05c8C724b334BcED0764C0b86B1D53"
        prov = provenance(job, _cands(), _chain_state())
        assert prov["tier"] == "B"

    def test_tier_b_with_deployment_passed_still_b(self):
        job = _job("B")
        job["address"] = "0xC2181D975c05c8C724b334BcED0764C0b86B1D53"
        prov = provenance(job, _cands(), _chain_state(), _deployment())
        assert prov["tier"] == "B"


# ---------------------------------------------------------------------------
# Unit tests for _build_verification_blocks()
# ---------------------------------------------------------------------------

class TestVerificationBlocks:
    def _blocks(self, dep: dict, cs: dict | None = None) -> list:
        from soken_review.report.assemble import _build_verification_blocks
        cs = cs or _chain_state()
        job = _job("A")
        return _build_verification_blocks(dep, cs, job)

    def test_returns_list(self):
        blocks = self._blocks(_deployment())
        assert isinstance(blocks, list)
        assert 1 <= len(blocks) <= 6

    def test_first_block_is_deployment_table(self):
        blocks = self._blocks(_deployment())
        first = blocks[0]
        assert "table" in first
        # Should have address and block info
        rows_flat = [str(v) for row in first["table"]["rows"] for v in row if isinstance(v, str)]
        assert any("158237689" in s for s in rows_flat) or \
               any(isinstance(v, int) and v == 158_237_689 for row in first["table"]["rows"] for v in row)

    def test_address_cell_uses_addr_form(self):
        blocks = self._blocks(_deployment())
        # Flatten all cells from all rows
        all_cells = [cell for blk in blocks if "table" in blk
                     for row in blk["table"]["rows"] for cell in row]
        addr_cells = [c for c in all_cells if isinstance(c, dict) and "addr" in c]
        assert addr_cells, "Expected at least one {addr:...} cell"

    def test_second_block_is_comparison_table(self):
        blocks = self._blocks(_deployment())
        assert len(blocks) >= 2
        assert "table" in blocks[1]

    def test_comparison_table_has_outcome(self):
        blocks = self._blocks(_deployment())
        cmp_tbl = blocks[1]["table"]
        all_cells = [str(c) for row in cmp_tbl["rows"] for c in row if isinstance(c, str)]
        assert any("metadata_only" in c or "outcome" in c.lower() for c in all_cells)

    def test_linked_libraries_table_included_when_present(self):
        dep = _deployment(linked_libraries={"MyLib": "0xABCD" + "00" * 18})
        blocks = self._blocks(dep)
        all_heads = [h for blk in blocks if "table" in blk for h in blk["table"]["head"]]
        # Should have a libraries table
        assert any("lib" in h.lower() for h in all_heads)

    def test_no_library_table_when_empty(self):
        blocks = self._blocks(_deployment(linked_libraries={}))
        all_heads = [h for blk in blocks if "table" in blk for h in blk["table"]["head"]]
        assert not any("lib" in h.lower() for h in all_heads)

    def test_paragraph_for_reason(self):
        dep = _deployment_c(reason="runtime_differs")   # a dep_match reason code, the only text a paragraph may carry
        cs = _chain_state()
        job = _job("C")
        from soken_review.report.assemble import _build_verification_blocks
        blocks = _build_verification_blocks(dep, cs, job)
        p_blocks = [b for b in blocks if "p" in b]
        assert p_blocks, "Expected at least one paragraph block for tier C reason"

    def test_max_six_blocks(self):
        dep = _deployment(linked_libraries={"A": "0x" + "aa" * 20, "B": "0x" + "bb" * 20})
        blocks = self._blocks(dep)
        assert len(blocks) <= 6

    def test_cells_are_valid_server_cell_types(self):
        """Every cell must be str, int, or a known dict form."""
        blocks = self._blocks(_deployment())
        for blk in blocks:
            if "p" in blk:
                assert isinstance(blk["p"], str)
            elif "table" in blk:
                for row in blk["table"]["rows"]:
                    for cell in row:
                        assert isinstance(cell, (str, int)) or (isinstance(cell, dict) and ("addr" in cell or "src" in cell)), \
                            f"Unexpected cell type: {cell!r}"


# ---------------------------------------------------------------------------
# Integration: tier A and C report fixtures pass schema validation
# ---------------------------------------------------------------------------

def _tier_a_report() -> dict:
    """A report fixture with tier A provenance and verification."""
    r = report(tier="A", label_key="tier_a")
    # verification must be present for tier A
    r["verification"] = [
        {"table": {"head": ["Field", "Value"], "rows": [
            ["Address", {"addr": "0xC2181D975c05c8C724b334BcED0764C0b86B1D53"}],
            ["Chain / network", "Optimism (10)"],
            ["Block", 158_237_689],
            ["On-chain code hash", _expected_code_hash()],
            ["Entry contract", "GovernanceToken"],
        ]}},
        {"table": {"head": ["Field", "Value"], "rows": [
            ["Outcome", "metadata_only"],
            ["Local length", 16528],
            ["On-chain length", 16528],
            ["Masked bytes (immutables)", 224],
            ["Masked bytes (links)", 0],
            ["Masked bytes (auxdata)", 53],
            ["Differing bytes", 0],
        ]}},
    ]
    return r


def _tier_c_report() -> dict:
    """A report fixture with tier C provenance and verification."""
    t = kit_texts()
    r = report(tier="C", label_key="tier_c")
    r["meta"]["provenance"].update({
        "tier": "C",
        "label": t["tier_labels"]["tier_c"],
        "label_key": "tier_c",
        "address": "0xC2181D975c05c8C724b334BcED0764C0b86B1D53",
        "code_hash": _expected_code_hash(),
    })
    # verification must be present for tier C too
    r["verification"] = [
        {"table": {"head": ["Field", "Value"], "rows": [
            ["Address", {"addr": "0xC2181D975c05c8C724b334BcED0764C0b86B1D53"}],
            ["Chain / network", "Optimism (10)"],
            ["Block", 12345],
            ["On-chain code hash", _expected_code_hash()],
            ["Entry contract", "MyContract"],
        ]}},
        {"table": {"head": ["Field", "Value"], "rows": [
            ["Outcome", "differs"],
            ["Local length", 1000],
            ["On-chain length", 1050],
            ["Differing bytes", 42],
        ]}},
        {"p": "The source code compiled to a different runtime than the deployed bytecode."},
    ]
    return r


class TestSchemaValidation:
    def test_tier_a_report_passes_schema(self):
        r = _tier_a_report()
        validate(r)  # raises BuildError on failure

    def test_tier_c_report_passes_schema(self):
        r = _tier_c_report()
        validate(r)  # raises BuildError on failure

    def test_tier_b_without_verification_passes_schema(self):
        r = report(tier="B", label_key="tier_b_not_checked")
        assert "verification" not in r
        validate(r)

    def test_tier_a_with_string_gate(self):
        r = _tier_a_report()
        check_strings(r)  # must not raise

    def test_tier_c_with_string_gate(self):
        r = _tier_c_report()
        check_strings(r)  # must not raise


class TestKitBuildTierAC:
    def test_tier_a_builds_html_with_verification_section(self, tmp_path):
        r = _tier_a_report()
        from soken_review.report.kit.build import build as kit_build
        result = kit_build(r, tmp_path / "tier_a")
        html = result.html_path.read_text(encoding="utf-8")
        assert "Deployment verification" in html or "verification" in html.lower()
        # The address should appear (rendered via addr_html or escaped)
        assert "C2181D975" in html

    def test_tier_c_builds_html_with_tier_c_banner(self, tmp_path):
        r = _tier_c_report()
        from soken_review.report.kit.build import build as kit_build
        result = kit_build(r, tmp_path / "tier_c")
        html = result.html_path.read_text(encoding="utf-8")
        # Tier C warning should be present
        t = kit_texts()
        assert t["tier_c_warning"].split("{")[0] in html

    def test_tier_b_html_has_no_verification_section(self, tmp_path):
        r = report(tier="B", label_key="tier_b_not_checked")
        from soken_review.report.kit.build import build as kit_build
        result = kit_build(r, tmp_path / "tier_b")
        html = result.html_path.read_text(encoding="utf-8")
        # Should not have a verification section (no verification key in report)
        assert "Deployment verification" not in html


def test_cover_prints_not_checked_when_no_upgrade_evidence(tmp_path):
    """A tier A cover without upgrade_authority shows the kit text, never a default claim."""
    from soken_review.report.kit.build import build
    from tests.report.fixtures import report as fixture_report

    r = fixture_report(tier="A", label_key="tier_a")
    prov = r["meta"]["provenance"]
    prov["upgrade_authority"] = "NotChecked"
    prov.pop("upgradeable", None)
    html = build(r, tmp_path / "print", mode="print").html_path.read_text(encoding="utf-8")
    assert kit_texts()["upgrade_authority_not_checked"] in html
    assert "Renounced" not in html


def test_verification_cells_keep_source_text_out_of_server_class():
    """Contract and library names are src cells; only enum codes appear as server strings."""
    from soken_review.report.assemble import _build_verification_blocks
    dep = {"tier": "A", "block": 7, "dep": {"match": "metadata_only", "reason": "weird text; drop me", "contract": "src/Evil.sol:Totally<b>Safe</b>",
           "comparison": {"outcome": "metadata_only", "local_len": 10, "onchain_len": 10, "auxdata_source": "x2",
                          "linked_libraries": {"Lib<script>": "0x" + "ab" * 20}, "detail": "stderr junk", "masked_bytes": {}}}}
    blocks = _build_verification_blocks(dep, {"address": "0x" + "cd" * 20, "block": 7, "bytecode": "0x60"}, {"chain_id": 1})
    cells = [c for b in blocks if "table" in b for row in b["table"]["rows"] for c in row]
    assert {"src": "Totally<b>Safe</b>"} in cells and {"src": "Lib<script>"} in cells
    assert "Totally<b>Safe</b>" not in cells and "Lib<script>" not in cells
    assert not [b for b in blocks if "p" in b]                      # free-text reason never a paragraph


def test_coverage_section_starts_on_a_new_page(tmp_path):
    """Found on the 2026-10-15 x86 render of 13 tier A reports: with the verification tables the
    coverage section began near the bottom of a page and paged.js spilled its areas table into
    overflow columns (layout_overflow, section 3.6 pages wide). A page break before it is the
    deterministic fix (verified in a browser: no overflow, no near-empty page)."""
    from soken_review.report.kit.build import build
    from tests.report.fixtures import report as fixture_report

    r = fixture_report(tier="A", label_key="tier_a")
    r["meta"]["provenance"]["upgrade_authority"] = "NotChecked"
    r["meta"]["provenance"].pop("upgradeable", None)
    html = build(r, tmp_path / "print", mode="print").html_path.read_text(encoding="utf-8")
    i = html.find("Review coverage")
    assert i > 0 and html.rfind("<section", 0, i) == html.rfind('<section class="brk">', 0, i)
