"""Opcode activation probes (05 4.1, F18).

Offline: classification and registry rows. With `anvil` on PATH: the probe bytecodes run on a
local node per hardfork (paris, shanghai, prague, osaka), so each probe is shown to execute its
opcode and return the expected word. Live (-m live): Ethereum, Base and HyperEVM public RPCs.
"""

from __future__ import annotations

import asyncio
import shutil
import socket
import subprocess
import time

import pytest

from soken_review.adapters.evm.opcode_probe import CONTROL, PROBES, classify, probe_chain
from soken_review.adapters.evm.registry import get_chain, reload_registry
from soken_review.adapters.evm.rpc import RpcClient

_BY_NAME = {p.opcode: p for p in PROBES}


def test_probe_set_covers_post_shanghai_opcodes():
    assert set(_BY_NAME) == {"PUSH0", "TLOAD", "TSTORE", "MCOPY", "BLOBHASH", "BLOBBASEFEE", "CLZ"}
    for p in (*PROBES, CONTROL):
        assert len(p.expected) == 64
        bytes.fromhex(p.code)
        assert p.code.endswith("f3")  # every probe ends in RETURN


def test_probe_contains_its_opcode_byte():
    byte = {"PUSH0": "5f", "TLOAD": "5c", "TSTORE": "5d", "MCOPY": "5e", "BLOBHASH": "49", "BLOBBASEFEE": "4a", "CLZ": "1e"}
    for name, b in byte.items():
        assert b in [_BY_NAME[name].code[i : i + 2] for i in range(0, len(_BY_NAME[name].code), 2)]


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        ("invalid opcode: BLOBBASEFEE", "inactive"),                 # geth / bor
        ("EVM error: NotActivated", "inactive"),                    # reth / HyperEVM (F18)
        ("invalid opcode: opcode 0x1e not defined", "inactive"),    # geth, older
        ("BLOBBASEFEE is not supported on Arbitrum", "inactive"),   # nitro
        ("method eth_call with state override not supported", "error"),
        ("rate limit exceeded", "error"),
        ("execution reverted", "error"),
    ],
)
def test_classify_errors(error: str, expected: str):
    assert classify(_BY_NAME["BLOBBASEFEE"], None, error).split(":")[0] == expected


def test_not_supported_needs_this_opcode_name():
    assert classify(_BY_NAME["CLZ"], None, "BLOBBASEFEE is not supported on Arbitrum").startswith("error")


def test_classify_output():
    p = _BY_NAME["CLZ"]
    assert classify(p, "0x" + p.expected, None) == "active"
    # an RPC that ignores the override returns empty output: never "active"
    assert classify(p, "0x", None).startswith("error")
    assert classify(p, "0x" + "00" * 32, None).startswith("error")


class _Rpc:
    """Fake node: override ignored (returns 0x)."""

    async def block_number(self) -> int:
        return 7

    async def eth_call(self, **_kw) -> str:
        return "0x"


def test_override_ignored_means_not_measured():
    rec = asyncio.run(probe_chain(_Rpc()))
    assert rec["measured"] is False and rec["results"] == {} and rec["inactive"] == []


def test_registry_rows_measured():
    reload_registry()
    for cid, inactive in {1: [], 8453: [], 999: ["CLZ"], 42161: ["BLOBBASEFEE"], 137: ["BLOBHASH", "BLOBBASEFEE"]}.items():
        chain = get_chain(cid)
        assert chain is not None and chain.opcodes_measured, cid
        assert chain.inactive_opcodes == inactive, cid
        probe = chain.raw["opcode_probe"]
        assert probe["block"] and probe["rpc"].startswith("https://") and probe["checked_at"]
    assert get_chain(728126428).opcodes_measured  # TRON: getchainparameters (F41)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.mark.skipif(shutil.which("anvil") is None, reason="anvil (foundry) not installed")
@pytest.mark.parametrize(
    ("hardfork", "inactive"),
    [
        ("paris", ["PUSH0", "TSTORE", "TLOAD", "MCOPY", "BLOBHASH", "BLOBBASEFEE", "CLZ"]),
        ("shanghai", ["TSTORE", "TLOAD", "MCOPY", "BLOBHASH", "BLOBBASEFEE", "CLZ"]),
        ("prague", ["CLZ"]),
        ("osaka", []),
    ],
)
def test_probes_on_anvil_hardforks(hardfork: str, inactive: list[str]):
    port = _free_port()
    proc = subprocess.Popen(
        ["anvil", "--hardfork", hardfork, "--port", str(port), "--silent"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        url = f"http://127.0.0.1:{port}"
        for _ in range(50):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.1)
        rec = asyncio.run(probe_chain(RpcClient(url)))
    finally:
        proc.terminate()
        proc.wait(timeout=10)
    assert rec["measured"] is True, rec
    assert rec["inactive"] == inactive


@pytest.mark.live
@pytest.mark.parametrize(("chain_id", "inactive"), [(1, []), (8453, []), (999, ["CLZ"])])
def test_probes_live(chain_id: int, inactive: list[str]):
    chain = get_chain(chain_id)
    assert chain is not None
    last = None
    for row in chain.rpc:
        try:
            rec = asyncio.run(probe_chain(RpcClient(row.url)))
        except Exception as exc:  # noqa: BLE001
            last = exc
            continue
        if rec["measured"]:
            assert rec["inactive"] == inactive, (row.url, rec)
            return
        last = rec
    pytest.skip(f"no RPC for {chain_id} gave a complete measurement: {last}")
