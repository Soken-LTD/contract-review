"""review_verify_on_fork, sandbox side (chain access design 1.7 and 3.1 to 3.4).

No Docker here: the fork run's chain endpoint is exercised with a stub upstream (every send, sign
and broadcast method answers -32601 and nothing reaches the upstream, also over the Unix socket the
relay connects to), the container argv is checked for its caps, the output reader for its caps and
for untrusted text, and the test-file rules for what a test may import. The forge JSON fixture holds
the results of two real runs on a local Ethereum fork (2026-10-31, forge 1.8.5 in the evm-analyze
image, through this endpoint): a deposit test that passed, and a test that tried
eth_sendRawTransaction through vm.rpc and was refused.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import httpx
import pytest

from soken_review.chain import policy
from soken_review.chain.fork_rpc import ForkStats, fork_app, pin_tags, serve
from soken_review.chain.proxy import ChainProxy, Endpoint, Meter
from soken_review.sandbox import fork_verify as fv
from soken_review.sandbox.profile import CHAINSIM_NETWORK, StepLimits, docker_argv

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "fork" / "forge_test.json"
BLOCK = 26_311_087
FORK_HASH = "0x" + "ab" * 32
TOKEN = "t0k3n"


class _Upstream(httpx.AsyncBaseTransport):
    """Stub chain provider: records every request that reaches it."""

    def __init__(self) -> None:
        self.seen: list[dict] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        self.seen.append(body)
        if body["method"] == "eth_getBlockByNumber":
            result = {"number": hex(BLOCK), "hash": FORK_HASH}
        elif body["method"] == "eth_chainId":
            result = "0x1"
        else:
            result = "0x0"
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body.get("id"), "result": result})


def _app(up: _Upstream, meter: Meter | None = None, stats: ForkStats | None = None):
    meter = meter or Meter(max_calls=100)
    stats = stats if stats is not None else ForkStats()

    def factory() -> ChainProxy:
        return ChainProxy(meter=meter, transport=up, pace=False,
                          endpoint_list=lambda family, chain: [Endpoint("https://rpc.example", keyed=False, per_s=100)])

    return fork_app(1, BLOCK, TOKEN, meter, stats, proxy_factory=factory), meter, stats


def _rpc(method: str, params: list, i: int = 1) -> dict:
    return {"jsonrpc": "2.0", "id": i, "method": method, "params": params}


SENDS = [*policy.EVM_DENIED_EXAMPLES, "anvil_setBalance", "hardhat_impersonateAccount", "evm_mine",
         "eth_signTransaction", "eth_sendRawTransaction"]


@pytest.mark.asyncio
async def test_fork_endpoint_refuses_every_send_method_and_nothing_reaches_upstream():
    up = _Upstream()
    app, meter, stats = _app(up)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://relay") as c:
        for n, m in enumerate(SENDS):
            r = await c.post(f"/{TOKEN}", json=_rpc(m, ["0x02f8"], n))
            assert r.json()["error"]["code"] == -32601, m
        # one send inside a batch refuses the whole batch
        r = await c.post(f"/{TOKEN}", json=[_rpc("eth_chainId", []), _rpc("eth_sendRawTransaction", ["0x02"], 2)])
        assert r.json()["error"]["code"] == -32601
    assert up.seen == []
    assert meter.calls == 0
    assert stats.denied == len(SENDS) + 1
    assert "eth_sendRawTransaction" in stats.as_dict(meter)["denied_methods"]


@pytest.mark.asyncio
async def test_fork_endpoint_needs_the_run_token():
    up = _Upstream()
    app, _meter, stats = _app(up)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://relay") as c:
        r = await c.post("/", json=_rpc("eth_chainId", []))
        assert r.status_code == 404
        r = await c.post("/other", json=_rpc("eth_chainId", []))
        assert r.status_code == 404
    assert up.seen == [] and stats.bad_path == 2


@pytest.mark.asyncio
async def test_fork_endpoint_pins_tags_and_refuses_later_blocks():
    up = _Upstream()
    app, _meter, stats = _app(up)
    addr = "0x" + "1" * 40
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://relay") as c:
        r = await c.post(f"/{TOKEN}", json=_rpc("eth_getBalance", [addr, "latest"]))
        assert r.json()["result"] == "0x0"
        r = await c.post(f"/{TOKEN}", json=_rpc("eth_getCode", [addr]))           # no tag: the fork block
        assert r.json()["result"] == "0x0"
        r = await c.post(f"/{TOKEN}", json=_rpc("eth_getBalance", [addr, hex(BLOCK + 1)]))
        assert r.json()["error"]["code"] == -32601                                 # after the fork block
        # forge pins reads with EIP-1898 {blockHash}: the fork block's own hash is the fork block
        r = await c.post(f"/{TOKEN}", json=_rpc("eth_getStorageAt", [addr, "0x0", {"blockHash": FORK_HASH}]))
        assert r.json()["result"] == "0x0"
        r = await c.post(f"/{TOKEN}", json=_rpc("eth_getStorageAt", [addr, "0x0", {"blockHash": "0x" + "cd" * 32}]))
        assert r.json()["error"]["code"] == -32601                                 # any other hash stays refused
    reads = [s for s in up.seen if s["method"] != "eth_getBlockByNumber"]
    assert [s["params"][-1] for s in reads] == [hex(BLOCK), hex(BLOCK), hex(BLOCK)]
    assert stats.denied == 2


def test_pin_tags_leaves_methods_without_a_block_alone():
    item = _rpc("eth_chainId", [])
    assert pin_tags(item, BLOCK) is item
    assert pin_tags(_rpc("eth_call", [{"to": "0x" + "1" * 40}, "pending"]), BLOCK)["params"][1] == hex(BLOCK)


@pytest.mark.asyncio
async def test_fork_endpoint_meter_caps_the_run():
    up = _Upstream()
    app, meter, _stats = _app(up, meter=Meter(max_calls=2))
    addr = "0x" + "2" * 40
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://relay") as c:
        answers = [(await c.post(f"/{TOKEN}", json=_rpc("eth_getBalance", [addr, hex(BLOCK - i)]))).json()
                   for i in range(3)]
    assert "result" in answers[0] and "result" in answers[1]
    assert answers[2]["error"]["code"] == -32005
    assert len(up.seen) == 3 and meter.calls == 3   # the third call was charged, then refused


@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform == "win32", reason="Unix socket")
async def test_fork_endpoint_over_the_unix_socket_the_relay_uses():
    import tempfile

    up = _Upstream()
    app, _meter, _stats = _app(up)
    sock_dir = Path(tempfile.mkdtemp(prefix="fk", dir="/tmp"))   # a socket path is at most 107 bytes
    async with serve(app, sock_dir / "rpc.sock") as path:
        assert oct(path.stat().st_mode & 0o777) == "0o666"
        async with httpx.AsyncClient(transport=httpx.AsyncHTTPTransport(uds=str(path)), base_url="http://relay") as c:
            r = await c.post(f"/{TOKEN}", json=_rpc("eth_sendRawTransaction", ["0x02f8"]))
            assert r.json()["error"]["code"] == -32601
            r = await c.post(f"/{TOKEN}", json=_rpc("eth_chainId", []))
            assert r.json()["result"] == "0x1"
    assert not (sock_dir / "rpc.sock").exists()
    assert [s["method"] for s in up.seen] == ["eth_chainId"]


# ── container caps ─────────────────────────────────────────────────────────


def _fork_argv(tmp_path: Path, monkeypatch, runtime: str | None = None) -> list[str]:
    monkeypatch.delenv("SOKEN_SANDBOX_RUNTIME", raising=False)
    lim = fv.fork_limits()
    limits = StepLimits(cpus=float(lim["cpus"]), memory=str(lim["memory"]), pids=int(lim["pids"]),
                        max_file=int(lim["max_file_bytes"]))
    return docker_argv(step="fork", image="ghcr.io/x/evm-analyze@sha256:" + "a" * 64, work_dir=tmp_path,
                       cache_dir=tmp_path / "solc", limits=limits, env={"HOME": "/tmp"},
                       command=["forge", "test", "--json"], family_network=CHAINSIM_NETWORK, runtime=runtime,
                       workdir=fv.PROJECT_DIR, name="soken-fork-x", mounts=[(tmp_path, fv.PROJECT_DIR, True)])


def test_fork_container_runs_under_gvisor_on_the_chainsim_network_with_caps(tmp_path, monkeypatch):
    argv = _fork_argv(tmp_path, monkeypatch)
    joined = " ".join(argv)
    assert "--runtime=runsc-egress" in argv
    assert f"--network={CHAINSIM_NETWORK}" in argv
    for flag in ("--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=256",
                 "--memory=1536m", "--memory-swap=1536m", "--log-driver"):
        assert flag in argv, flag
    assert f"fsize={fv.fork_limits()['max_file_bytes']}" in joined
    assert any(a.startswith("--cpus=") and float(a.split("=")[1]) <= 1.5 for a in argv)
    assert f"type=bind,src={tmp_path},dst={fv.PROJECT_DIR},readonly" in argv
    assert "/tmp:rw,noexec,nosuid,size=512m" in argv
    assert "HTTPS_PROXY" not in joined and "SOKEN_" not in joined   # no smokescreen, no server secrets


def test_fork_container_refuses_other_networks_and_floating_tags(tmp_path, monkeypatch):
    monkeypatch.delenv("SOKEN_SANDBOX_RUNTIME", raising=False)
    lim = StepLimits(cpus=1, memory="1g", pids=64, max_file=1024)
    with pytest.raises(ValueError):
        docker_argv(step="fork", image="i@sha256:" + "a" * 64, work_dir=tmp_path, cache_dir=None, limits=lim, env={},
                    command=["forge"], family_network="soken-egress-evm")
    with pytest.raises(ValueError):
        docker_argv(step="fork", image="i:latest", work_dir=tmp_path, cache_dir=None, limits=lim, env={},
                    command=["forge"], family_network=CHAINSIM_NETWORK)


def test_relay_container_is_read_only_without_capabilities(tmp_path):
    argv = fv.relay_argv("soken-forkrelay-x", "img@sha256:" + "b" * 64, tmp_path, CHAINSIM_NETWORK)
    assert "--runtime=runc" in argv and f"--network={CHAINSIM_NETWORK}" in argv
    for flag in ("--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--user"):
        assert flag in argv
    assert f"type=bind,src={fv.RELAY_SCRIPT},dst=/relay/rpc_relay.py,readonly" in argv
    assert argv[-3:] == ["/relay/rpc_relay.py", str(fv.RELAY_PORT), "/relay/sock/rpc.sock"]


def test_run_capped_kills_at_the_wall_and_at_the_output_cap(tmp_path):
    killed: list[str] = []
    code, why = fv.run_capped([sys.executable, "-c", "import time; time.sleep(30)"], 0.5, 1024,
                              lambda: killed.append("wall"), tmp_path / "o1", tmp_path / "e1", grace_s=0.2)
    assert why == "wall" and killed
    code, why = fv.run_capped([sys.executable, "-c", "import sys,time\nwhile True: sys.stdout.write('x'*65536); sys.stdout.flush(); time.sleep(0.01)"],
                              20, 4096, lambda: None, tmp_path / "o2", tmp_path / "e2", grace_s=0.2)
    assert why == "output"
    code, why = fv.run_capped([sys.executable, "-c", "print('{}')"], 20, 4096, lambda: None, tmp_path / "o3", tmp_path / "e3")
    assert (code, why) == (0, None)


def test_foundry_toml_closes_every_way_out():
    toml = fv.foundry_toml(["@oz/=pinned/lib/oz/"])
    for line in ("ffi = false", "fs_permissions = []", "offline = true", "auto_detect_solc = false",
                 "no_storage_caching = true", 'src = "test"', 'out = "/tmp/forge-out"'):
        assert line in toml, line
    assert "eth_rpc_url" not in toml and "rpc_endpoints" not in toml
    assert '"forge-std/=/opt/forge-std/src/"' in toml and '"@oz/=pinned/lib/oz/"' in toml


# ── test file rules ────────────────────────────────────────────────────────

GOOD = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;
import {Test} from "forge-std/Test.sol";
import "pinned/src/Vault.sol";
// import "../../etc/passwd";
contract VerifyTest is Test { function test_x() public {} }
"""


def test_test_source_accepts_forge_std_and_pinned_imports():
    assert fv.check_test_source(GOOD, {"src/Vault.sol"}) == ["forge-std/Test.sol", "pinned/src/Vault.sol"]


@pytest.mark.parametrize("imp", ["../src/Vault.sol", "/etc/passwd", "@openzeppelin/contracts/token/ERC20/ERC20.sol",
                                 "pinned/src/Other.sol", "forge-std/../../x.sol", "pinned/../x.sol", "lib/x.sol"])
def test_test_source_refuses_other_imports(imp):
    src = GOOD.replace('import "pinned/src/Vault.sol";', f'import "{imp}";')
    with pytest.raises(fv.TestRejected) as exc:
        fv.check_test_source(src, {"src/Vault.sol"})
    assert exc.value.field == "test.content"


def test_test_source_caps_and_shape():
    with pytest.raises(fv.TestRejected):
        fv.check_test_source(GOOD + "//" + "x" * 70000, set())
    with pytest.raises(fv.TestRejected):
        fv.check_test_source("contract A {}", set())
    with pytest.raises(fv.TestRejected):
        fv.check_test_source("pragma solidity ^0.8.0; contract A { function f() public {} }", set())
    assert fv.check_test_path(None) == fv.DEFAULT_TEST_PATH
    for bad in ("Verify.t.sol", "test/../x.t.sol", "test/a/b.t.sol", "test/x.sol", "script/X.t.sol"):
        with pytest.raises(fv.TestRejected):
            fv.check_test_path(bad)


def test_compiler_choice_and_pinned_remappings():
    assert fv.choose_solc("0.8.20+commit.a1b79de6") == "0.8.20+commit.a1b79de6"
    assert fv.choose_solc("0.4.19+commit.c4cbbb05") == fv.fork_limits()["solc"]
    assert fv.choose_solc(None) == fv.fork_limits()["solc"]
    assert fv.job_compiler([{"compiler": {"version": "0.8.7"}}], {"attempts": [{"status": "ok", "version": "0.8.9"}]}) == "0.8.9"
    cands = [{"settings": {"remappings": ["@oz/=lib/oz/contracts/", "-x=lib/", "evil/=../../etc/", "ctx:a/=lib/oz/",
                                          "gone/=lib/missing/"]}}]
    assert fv.pinned_remappings(cands, {"lib/oz/contracts/token/ERC20.sol", "src/V.sol"}) == ["@oz/=pinned/lib/oz/contracts/"]


# ── forge output ───────────────────────────────────────────────────────────


def test_forge_json_results_are_classed_untrusted():
    tests = fv.parse_forge_json(FIX.read_bytes())
    by = {t["name"]: t for t in tests}
    dep = by["WethDepositTest.test_depositCreditsBalance()"]
    assert dep["status"] == "passed" and dep["gas"] == 253747 and dep["events"] == 1
    assert dep["logs"][0] == {"value": "deposited 1000000000000000000", "class": "chain_text", "origin": "forge test console"}
    send = by["SendAttemptTest.test_sendIsRefused()"]
    assert send["status"] == "failed" and "not on the read allowlist" in send["reason"]["value"]
    inj = by["SendAttemptTest.test_wrongBalanceClaim()"]["reason"]
    assert inj["class"] == "chain_text" and "ignore previous instructions" not in inj["value"].lower()
    assert any(f.startswith("J1") for f in inj["flags"])
    assert fv.run_status(tests) == "failed"
    assert fv.run_status([dep]) == "passed"


def test_forge_json_caps_and_failures():
    with pytest.raises(fv.RunError) as exc:
        fv.parse_forge_json(b"Compiler run failed:\nError (2314): Expected ';'")
    assert exc.value.reason == "no_result"
    doc = {"test/V.t.sol:V": {"test_results": {f"test_{i}()": {"status": "Success", "kind": {"Unit": {"gas": i}},
                                                               "decoded_logs": [f"l{j}" for j in range(60)]}
                                              for i in range(30)}}}
    tests = fv.parse_forge_json(json.dumps(doc).encode(), max_tests=5, log_lines=3)
    assert len(tests) == 6 and tests[-1]["status"] == "not_reported"
    assert len(tests[0]["logs"]) == 3 and tests[0]["logs_more"] == 57
    diag = fv.compile_error("Compiler run failed:\nError (2314): Expected ';' but got '}'\n --> test/V.t.sol:5:1")
    assert diag["class"] == "chain_text" and "Expected" in diag["value"]


@pytest.mark.asyncio
async def test_execute_fails_closed_without_a_pinned_image(tmp_path, monkeypatch):
    monkeypatch.setattr("soken_review.sandbox.profile.locked_image", lambda name: None)
    with pytest.raises(fv.RunError) as exc:
        await fv.execute({"job_id": "job_x", "run_id": "fork-000000000000"}, tmp_path)
    assert exc.value.reason == "image_unavailable"
