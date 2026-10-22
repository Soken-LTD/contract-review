"""Semantic layer line attribution when the compiler saw different bytes than the pin (04 2.1, 5.1).

The build step compiles the fetched Standard JSON input byte for byte (CRLF kept, so the rebuild
can be `exact`), while the pin and the lexical layer hold the LF-normalised text. solc `src`
offsets are byte offsets into the compiled text, so every function after a CR drifts down by the
number of CRs before it. On the SushiSwap MasterChef Sourcify pin that attached
`MasterChef.updatePool(uint256)` to the `withdraw` span and dropped `safeSushiTransfer` entirely
(2026-10-22 incident). The semantic layer must resolve lines against the compiled text.
"""

from __future__ import annotations

import gzip
import json
import re
import shutil
from pathlib import Path

from soken_review.mapping.build import build_map
from soken_review.mapping.step import family_categories, run_map_step
from soken_review.pinning.store import PinnedSource

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "map"
CATS = list(family_categories("evm"))

VAULT_LF = (FIX / "Vault.sol").read_text()
VAULT_CRLF = (FIX / "Vault.crlf.sol").read_bytes().decode("utf-8")
VAULT_CRLF_OUTPUT = json.loads((FIX / "vault_crlf_solc_output.json").read_text())

MC_DIR = FIX / "masterchef_crlf"
MC_CRLF = (MC_DIR / "MasterChef.crlf.sol").read_bytes().decode("utf-8")
MC_LF = MC_CRLF.replace("\r\n", "\n")
with gzip.open(MC_DIR / "solc_output.sources.json.gz", "rt", encoding="utf-8") as _fh:
    MC_OUTPUT = json.load(_fh)


def _fn_spans(doc: dict) -> dict[str, tuple[int, int]]:
    """semantic span id -> (start, end) of the lexical span it was attached to."""
    by_id = {sp["id"]: (sp["start"], sp["end"]) for sp in doc["spans"]}
    return {f["span"]: by_id[f["span"]] for f in doc["semantic"]["functions"]}


def _declared_line(text: str, name: str, contract: str | None = None) -> int:
    """1-based line of `function <name>`, searched inside `contract <contract>` when given."""
    base = 0
    if contract:
        c = re.search(r"\bcontract\s+" + re.escape(contract) + r"\b", text)
        assert c, contract
        base = c.start()
    m = re.compile(r"function\s+" + re.escape(name) + r"\b").search(text, base)
    assert m, name
    return text[: m.start()].count("\n") + 1


def test_vault_crlf_compiled_text_keeps_every_function_on_its_own_line():
    assert VAULT_CRLF.replace("\r\n", "\n") == VAULT_LF
    art = build_map({"src/Vault.sol": VAULT_LF}, VAULT_CRLF_OUTPUT, CATS,
                    compiled_texts={"src/Vault.sol": VAULT_CRLF})
    spans = _fn_spans(art.doc)
    for name in ("setFee", "deposit", "withdraw", "sweep", "_chargeFee", "_checkOwner"):
        hit = [sid for sid in spans if re.fullmatch(r"\w+\." + name + r"\(.*\)", sid)]
        assert hit, f"{name} missing from the semantic layer: {sorted(spans)}"
        assert spans[hit[0]][0] == _declared_line(VAULT_LF, name), (name, spans[hit[0]])


def test_vault_crlf_without_compiled_text_matches_lf_build():
    """When the compiled text is the pinned text (files/repo LF sources) nothing changes."""
    lf_output = json.loads((FIX / "vault_solc_output.json").read_text())
    base = build_map({"src/Vault.sol": VAULT_LF}, lf_output, CATS)
    same = build_map({"src/Vault.sol": VAULT_LF}, lf_output, CATS, compiled_texts={"src/Vault.sol": VAULT_LF})
    assert _fn_spans(base.doc) == _fn_spans(same.doc)


def test_masterchef_sourcify_pin_semantic_functions_match_declarations():
    """Real pin: every MasterChef function has a record and sits on its declared line."""
    art = build_map({"MasterChef.sol": MC_LF}, MC_OUTPUT, CATS, compiled_texts={"MasterChef.sol": MC_CRLF})
    assert art.status == "full"
    spans = _fn_spans(art.doc)
    mc = {sid: se for sid, se in spans.items() if sid.startswith("MasterChef.")}
    # Lines verified by hand on the pinned LF text; the pre-fix map had updatePool at 1578 (that is
    # withdraw), poolLength at 1497 (that is migrate) and no record for safeSushiTransfer.
    expected = {"poolLength": 1462, "add": 1468, "set": 1483, "setMigrator": 1492, "migrate": 1497,
                "getMultiplier": 1509, "pendingSushi": 1522, "massUpdatePools": 1536, "updatePool": 1544,
                "deposit": 1563, "withdraw": 1578, "emergencyWithdraw": 1592, "safeSushiTransfer": 1602,
                "dev": 1612}
    for name, line in expected.items():
        hit = [sid for sid in mc if sid.startswith(f"MasterChef.{name}(")]
        assert hit, f"MasterChef.{name} missing: {sorted(mc)}"
        start = mc[hit[0]][0]
        assert start == line == _declared_line(MC_LF, name, "MasterChef"), (name, start, line)
    # the lexical span the semantic id was attached to must be the same function
    lex_names = {sp["id"]: sp["name"] for sp in art.doc["spans"]}
    for sid in mc:
        assert lex_names[sid] == sid.split(".", 1)[1].split("(", 1)[0], (sid, lex_names[sid])


def test_masterchef_safe_sushi_transfer_is_reachable_from_withdraw():
    """The internal callee record exists, so `entry_function` scope and L1 reachability resolve."""
    art = build_map({"MasterChef.sol": MC_LF}, MC_OUTPUT, CATS, compiled_texts={"MasterChef.sol": MC_CRLF})
    fns = {f["span"]: f for f in art.doc["semantic"]["functions"]}
    withdraw = fns["MasterChef.withdraw(uint256,uint256)"]
    assert any(c["kind"] == "internal" and c["target"] == "safeSushiTransfer"
               for c in withdraw["calls"]), withdraw["calls"]
    assert fns["MasterChef.safeSushiTransfer(address,uint256)"]["visibility"] == "internal"


def test_run_map_step_reads_compiled_text_from_std_input(tmp_path: Path):
    """Supervisor shape: `std_input_0.json` = {"std_json_input": <std json>, ...} next to the solc copy."""
    PinnedSource.from_files({"src/Vault.sol": VAULT_CRLF.encode("utf-8")}).persist(tmp_path, "job_crlf")
    out = tmp_path / "out"
    out.mkdir()
    shutil.copy(FIX / "vault_crlf_solc_output.json", out / "solc_output.json")
    (out / "std_input_0.json").write_text(json.dumps({
        "std_json_input": {"language": "Solidity", "sources": {"src/Vault.sol": {"content": VAULT_CRLF}}},
        "constructor_args_hex": None,
    }))
    summary = run_map_step(tmp_path, "job_crlf", solc_output_path=out / "solc_output.json",
                           std_input_path=out / "std_input_0.json", build_ok=True)
    assert summary["semantic"] is True
    doc = json.loads((tmp_path / "job_crlf" / "map" / "map.json").read_text())
    spans = _fn_spans(doc)
    assert spans["Vault.withdraw(uint256)"][0] == _declared_line(VAULT_LF, "withdraw")
    assert "Vault._chargeFee(uint256)" in spans


def test_run_map_step_reads_compiled_text_from_host_build_copy(tmp_path: Path):
    """Build-adapter shape: `<work>.host/build/input.json` is the plain Standard JSON input."""
    PinnedSource.from_files({"src/Vault.sol": VAULT_CRLF.encode("utf-8")}).persist(tmp_path, "job_host")
    out = tmp_path / "out"
    out.mkdir()
    shutil.copy(FIX / "vault_crlf_solc_output.json", out / "solc_output.json")
    (out / "input.json").write_text(json.dumps(
        {"language": "Solidity", "sources": {"src/Vault.sol": {"content": VAULT_CRLF}}}))
    run_map_step(tmp_path, "job_host", solc_output_path=out / "solc_output.json",
                 std_input_path=out / "input.json", build_ok=True)
    doc = json.loads((tmp_path / "job_host" / "map" / "map.json").read_text())
    assert _fn_spans(doc)["Vault.withdraw(uint256)"][0] == _declared_line(VAULT_LF, "withdraw")
