"""TON multisig v2: masterchain library references, FunC point builds, gateway throttling.

Matrix r5 2026-10-31: EQBabkaz2T0_ZoRDzaMqZheJIDeRCJgwxMlsQ1GigwsjQlP- (multisig v2, verified on
verifier.ton.org as FunC 0.4.4) ended in insufficient_source / SOURCE_NOT_OWNER_LINKED /
untrusted_inputs. Causes, each covered here with recorded fixtures (no network):

1. `auto/order_code.func` builds a library reference cell in an asm body (the order contract code
   is a masterchain library); the trust scan refused the Fift builder. Now trusted when the
   library hash was read from the chain (getLibraries body hashes to it).
2. `MAX_ORDER_SEQNO` is 2**256 - 1, over the integer digit cap. A mask carries no data.
3. The registry manifest names `funcVersion`, which the fetch ignored, and the verifier compiled
   the files in `commandLine` order; only the `0.4.4-newops.1` build assembles the stdlib.
4. files.orbs.network throttles with 429 and Retry-After 900, pinata refuses some text files.

Fixtures in tests/fixtures/ton/multisig_v2: the verifier bundle (src/), its IPFS manifest, the
deployed code BoC (toncenter, 2026-10-31), the rebuild BoC of the locked ton-build image with
func 0.4.4-newops.1, and the getLibraries answer for the order code library.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from soken_review.adapters.base import BuildResult, Candidate, Compiler
from soken_review.adapters.ton import build as build_mod
from soken_review.adapters.ton import fetch as fetch_mod
from soken_review.adapters.ton.cell import root_info
from soken_review.adapters.ton.provenance import Attempt, Dep, deployment_doc, resolve_provenance
from soken_review.adapters.ton.trust_scan import library_ref_hash, library_refs, scan_files

FIX = Path(__file__).parent.parent.parent / "fixtures" / "ton" / "multisig_v2"
DEPLOYED_HASH = "d3d14da9a627f0ec3533341829762af92b9540b21bf03665fac09c2b46eabbac"
ORDER_LIB = "6305a8061c856c2ccf05dcb0df5815c71475870567cab5f049e340bcf59251f3"
TARGETS = ["imports/stdlib.fc", "op-codes.func", "multisig.func", "errors.func", "messages.func",
           "auto/order_code.func", "order_helpers.func", "types.func"]


def _files() -> dict[str, str]:
    return {p.relative_to(FIX / "src").as_posix(): p.read_text() for p in (FIX / "src").rglob("*") if p.is_file()}


def _cand(**settings) -> Candidate:
    files = _files()
    return Candidate(provider="ton_verifier", files=files, sha256="x", language="func",
                     compiler=Compiler(version="0.4.4", version_pinned_by="ton_verifier"),
                     settings=settings, std_json_input=None, entry_contract=None)


# ── 1, 2: trust scan ──────────────────────────────────────────────────────


def test_library_ref_body_recognised():
    body = f"<b 2 8 u, 0x{ORDER_LIB} 256 u, b>spec PUSHREF"
    assert library_ref_hash(body) == ORDER_LIB
    assert library_ref_hash("  <b 2 8 u,   0x" + ORDER_LIB.upper() + " 256 u, b>spec   PUSHREF ") == ORDER_LIB
    # anything else is not the idiom: another tag, another width, an extra word
    assert library_ref_hash(f"<b 1 8 u, 0x{ORDER_LIB} 256 u, b>spec PUSHREF") is None
    assert library_ref_hash(f"<b 2 8 u, 0x{ORDER_LIB} 256 u, b> PUSHREF") is None
    assert library_ref_hash(f"<b 2 8 u, 0x{ORDER_LIB} 256 u, b>spec PUSHREF DROP") is None


def test_bundle_lists_its_library():
    assert library_refs(_files()) == [ORDER_LIB]


def test_bundle_untrusted_until_the_library_is_resolved():
    reasons = scan_files(_files())
    assert any("library reference" in r and "not resolved" in r for r in reasons)
    assert scan_files(_files(), resolved_libraries=[ORDER_LIB]) == []
    # a resolved hash that is not the one in the source does not help
    assert scan_files(_files(), resolved_libraries=["00" * 32]) != []


def test_mask_constant_is_not_data_but_other_big_integers_are():
    ok = {"a.fc": "const int M = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;\n"
                  "const int P = 0x10000000000000000000;\n"}
    assert scan_files(ok) == []
    bad = {"a.fc": "const int D = 0x1234567890abcdef1234567890;\n"}
    assert any("digit cap" in r for r in scan_files(bad))


def test_forged_boc_literal_stays_untrusted():
    # the e2e_ton_provenance N2 control: a BoC literal of a library cell is not the builder idiom
    forged = {"x.fc": 'cell forged() asm "B{b5ee9c72010101010023000842028f452d7a4dfd74066b682365177259ed05734435be76'
                      'b5fd4bd5d8af2b7c3d68} B>boc PUSHREF";\n'}
    assert scan_files(forged, resolved_libraries=[ORDER_LIB]) != []


# ── exotic child cell hashing: rebuild equals deployment ─────────────────


def test_rebuild_and_deployed_code_hash_equal():
    deployed = root_info((FIX / "deployed_code.boc").read_bytes())
    rebuilt = root_info((FIX / "rebuilt_0.4.4-newops.1.boc").read_bytes())
    assert deployed.hash == rebuilt.hash == DEPLOYED_HASH
    assert not deployed.is_library_ref


def test_resolve_provenance_tier_a_with_trusted_candidate():
    cand = _cand()
    out = resolve_provenance(Dep(address="0:5a6e", status="active", hash=DEPLOYED_HASH), [cand],
                             lambda i, c: Attempt(i, c.provider, "ok", {"multisig.func": DEPLOYED_HASH}))
    assert (out.reason, out.tier, out.match) == ("MATCH_REBUILD", "A", "exact")


def test_deployment_doc_carries_library_refs():
    prov = {"reason": "MATCH_REBUILD", "tier": "A", "address": "0:5a6e", "dep_hash": DEPLOYED_HASH,
            "build_hash": DEPLOYED_HASH, "library_refs": [{"hash": ORDER_LIB, "status": "ok",
                                                           "verified_source": "https://verifier.ton.org/x"}]}
    doc = deployment_doc(prov, None, "EQBabkaz2T0_ZoRDzaMqZheJIDeRCJgwxMlsQ1GigwsjQlP-")
    assert doc["library_refs"] == [{"hash": ORDER_LIB, "status": "ok", "verified_source": "https://verifier.ton.org/x"}]
    from soken_review.report.assemble import _build_verification_blocks

    blocks = _build_verification_blocks(doc, None, {"chain": "ton", "address": doc["address"]})
    rows = [r for b in blocks if "table" in b for r in b["table"]["rows"]]
    lib = [r for r in rows if r[0] == "Library reference"]
    assert lib and ORDER_LIB in lib[0][1] and "verified" in lib[0][1] and "—" not in lib[0][1]


# ── 1: library resolution from the chain ──────────────────────────────────


def _libraries_result() -> dict:
    return json.loads((FIX / "getLibraries.json").read_text())["result"]


@pytest.mark.asyncio
async def test_resolve_library_refs_reads_and_hashes_the_body():
    cand = _cand()
    with patch.object(fetch_mod, "_toncenter", AsyncMock(return_value=_libraries_result())), \
         patch.object(fetch_mod, "_registry_get_source_item_address", AsyncMock(return_value="EQsource")):
        rows = await fetch_mod.resolve_library_refs(MagicMock(), cand)
    assert rows[0]["hash"] == ORDER_LIB and rows[0]["status"] == "ok"
    assert rows[0]["verified_source"] == f"https://verifier.ton.org/{ORDER_LIB}"
    assert cand.settings["library_refs"] == rows
    assert scan_files(cand.files, resolved_libraries=[r["hash"] for r in rows if r["status"] == "ok"]) == []


@pytest.mark.asyncio
async def test_library_body_with_another_hash_is_not_found():
    forged = _libraries_result()
    forged["result"][0]["data"] = base64.b64encode((FIX / "deployed_code.boc").read_bytes()).decode()
    cand = _cand()
    with patch.object(fetch_mod, "_toncenter", AsyncMock(return_value=forged)):
        rows = await fetch_mod.resolve_library_refs(MagicMock(), cand)
    assert rows[0]["status"] == "not_found" and rows[0]["verified_source"] is None


@pytest.mark.asyncio
async def test_library_read_failure_is_unavailable():
    cand = _cand()
    with patch.object(fetch_mod, "_toncenter", AsyncMock(side_effect=fetch_mod.TonReadError("getLibraries: HTTP 503"))):
        rows = await fetch_mod.resolve_library_refs(MagicMock(), cand)
    assert rows[0]["status"] == "unavailable"


def test_build_scan_uses_the_resolved_libraries(tmp_path, monkeypatch):
    """build._run_build passes the candidate's resolved hashes to the trust scan."""
    monkeypatch.setattr(build_mod, "_DIRECT", False)
    monkeypatch.setattr(build_mod, "_BUILD_IMAGE", None)   # stop right after the scans
    cand = _cand(library_refs=[{"hash": ORDER_LIB, "status": "ok"}])
    build_mod.build(cand, work_dir=tmp_path / "a")
    assert cand.untrusted_inputs is False
    cand2 = _cand(library_refs=[{"hash": ORDER_LIB, "status": "unavailable"}])
    build_mod.build(cand2, work_dir=tmp_path / "b")
    assert cand2.untrusted_inputs is True


# ── 3: compiler version and file order from the manifest ─────────────────


def test_registry_func_targets_follow_the_command_line():
    manifest = json.loads((FIX / "manifest.json").read_text())
    assert fetch_mod._registry_func_targets(manifest, _files()) == TARGETS
    # a listed file that was not downloaded: no partial order, the build falls back to its entry
    partial = {k: v for k, v in _files().items() if k != "auto/order_code.func"}
    assert fetch_mod._registry_func_targets(manifest, partial) == []


@pytest.mark.asyncio
async def test_registry_candidate_takes_func_version_and_targets():
    manifest = json.loads((FIX / "manifest.json").read_text())
    manifest["_soken_cid_verified"] = True
    with patch.object(fetch_mod, "_registry_get_source_item_address", AsyncMock(return_value="EQitem")), \
         patch.object(fetch_mod, "_registry_get_ipfs_link", AsyncMock(return_value="ipfs://QmSS4JALZ2uvweCxTpZxdmfEegfLo3vukx9SHTWCkBkkaM")), \
         patch.object(fetch_mod, "_ipfs_fetch_manifest", AsyncMock(return_value=manifest)), \
         patch.object(fetch_mod, "_registry_download_files", AsyncMock(return_value=_files())):
        cand = await fetch_mod.fetch_source_from_registry(MagicMock(), DEPLOYED_HASH)
    assert cand is not None
    assert cand.compiler is not None and cand.compiler.version == "0.4.4"
    assert cand.settings["func_targets"] == TARGETS


def test_point_builds_order():
    assert build_mod.func_point_builds("0.4.4") == ["0.4.4-newops.1", "0.4.4-newops"]
    assert build_mod.func_point_builds("0.4.3") == []


def test_compile_error_retries_point_build(tmp_path, monkeypatch):
    seen: list[str] = []

    def fake_run(candidate, language, work_dir):
        seen.append(candidate.compiler.version)
        if candidate.compiler.version == "0.4.4-newops.1":
            return BuildResult(candidate=candidate, status="ok", work_dir=str(work_dir))
        return BuildResult(candidate=candidate, status="failed", reason="compile_error")

    monkeypatch.setattr(build_mod, "_run_build", fake_run)
    cand = _cand()
    res = build_mod.build(cand, work_dir=tmp_path / "attempt")
    assert seen == ["0.4.4", "0.4.4-newops.1"]
    assert res.status == "ok" and res.work_dir.endswith("attempt-0.4.4-newops.1")
    assert cand.compiler.version == "0.4.4-newops.1"


def test_other_failures_do_not_retry(tmp_path, monkeypatch):
    seen: list[str] = []

    def fake_run(candidate, language, work_dir):
        seen.append(candidate.compiler.version)
        return BuildResult(candidate=candidate, status="failed", reason="unsupported_toolchain")

    monkeypatch.setattr(build_mod, "_run_build", fake_run)
    build_mod.build(_cand(), work_dir=tmp_path / "attempt")
    assert seen == ["0.4.4"]


# ── 4: throttled gateways ────────────────────────────────────────────────


def _resp(status: int, content: bytes = b"", retry_after: str | None = None):
    r = MagicMock()
    r.status_code = status
    r.content = content
    r.headers = {"retry-after": retry_after} if retry_after is not None else {}
    return r


@pytest.mark.asyncio
async def test_ipfs_429_short_retry_after_retries_same_gateway():
    cid = "QmbFA7qr8uU2wveZB2xyoWBQkusAUBeFfNaDH2Ne8acLQ7"
    body = (FIX / "src" / "auto" / "order_code.func").read_bytes()
    answers = [_resp(429, b"slow down", "0"), _resp(200, body)]
    calls: list[str] = []

    async def get(url, **kw):
        calls.append(url)
        return answers.pop(0)

    client = MagicMock()
    client.get = get
    with patch.object(fetch_mod, "_limiter") as lim:
        lim.return_value.wait = AsyncMock()
        out = await fetch_mod._ipfs_fetch_bytes(client, cid, 1 << 20)
    assert out == body and len(calls) == 2 and calls[0] == calls[1]


@pytest.mark.asyncio
async def test_ipfs_long_retry_after_moves_to_next_gateway():
    cid = "QmbFA7qr8uU2wveZB2xyoWBQkusAUBeFfNaDH2Ne8acLQ7"
    body = (FIX / "src" / "auto" / "order_code.func").read_bytes()
    calls: list[str] = []

    async def get(url, **kw):
        calls.append(url)
        if "files.orbs.network" in url:
            return _resp(429, b"This IPFS gateway is switching", "900")
        if "pinata" in url:
            return _resp(403, b"HTML content cannot be served")
        if "ipfs.ton.live" in url:
            raise OSError("no such host")
        return _resp(200, body)

    client = MagicMock()
    client.get = get
    with patch.object(fetch_mod, "_limiter") as lim:
        lim.return_value.wait = AsyncMock()
        out = await fetch_mod._ipfs_fetch_bytes(client, cid, 1 << 20)
    assert out == body
    assert sum("files.orbs.network" in u for u in calls) == 1
    assert calls[-1].startswith("https://ipfs.filebase.io/ipfs/")
    assert fetch_mod._validate_download_url(calls[-1]) is not None
