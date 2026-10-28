"""Reliability probe of the free chain sources (CEO 2026-10-28: zero budget, free sources only).

Per chain and candidate endpoint: availability and latency over N calls, rate-limit answers,
the widest eth_getLogs block range served, how far back historical state is served, and whether
`anvil --fork-url` starts on it and answers calls. TRON (TronGrid keyless), Solana (public
mainnet) and TON (toncenter v2/v3 keyless) get the equivalent checks.

    uv run python scripts/chain_free_probe.py --calls 50 --out soken-output/probe.json
    uv run python scripts/chain_free_probe.py --chains 56,1 --write-pool   # refresh chain/data/free_rpc.json depths

Read-only: every request is a read method of the chain proxy allowlist (`chain.policy`); nothing
is signed or sent. Repeatable: the output JSON carries the date and the raw measurements, and
`--markdown` renders the report the design cites.
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import os
import shutil
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from soken_review.chain import policy

# Candidate free endpoints per EVM chain: chains.json rows plus the public pools named by the CEO
# brief (publicnode, drpc, ankr public, blastapi public, official chain RPCs, 1rpc, others).
EVM_CANDIDATES: dict[int, list[str]] = {
    1: ["https://ethereum-rpc.publicnode.com", "https://eth.drpc.org", "https://rpc.ankr.com/eth",
        "https://eth-mainnet.public.blastapi.io", "https://1rpc.io/eth", "https://rpc.mevblocker.io",
        "https://eth.llamarpc.com", "https://eth.blockrazor.xyz", "https://rpc.flashbots.net"],
    56: ["https://bsc-dataseed.binance.org", "https://bsc-dataseed1.defibit.io", "https://bsc-dataseed1.ninicoin.io",
         "https://bsc-dataseed2.bnbchain.org", "https://bsc-rpc.publicnode.com", "https://bsc.drpc.org",
         "https://rpc.ankr.com/bsc", "https://bsc-mainnet.public.blastapi.io", "https://1rpc.io/bnb",
         "https://bsc.blockrazor.xyz", "https://bsc.llamarpc.com"],
    42161: ["https://arb1.arbitrum.io/rpc", "https://arbitrum-one-rpc.publicnode.com", "https://arbitrum.drpc.org",
            "https://rpc.ankr.com/arbitrum", "https://arbitrum-one.public.blastapi.io", "https://1rpc.io/arb",
            "https://arbitrum.llamarpc.com"],
    8453: ["https://mainnet.base.org", "https://base-rpc.publicnode.com", "https://base.drpc.org",
           "https://rpc.ankr.com/base", "https://base-mainnet.public.blastapi.io", "https://1rpc.io/base",
           "https://base.llamarpc.com"],
    137: ["https://polygon-rpc.com", "https://polygon-bor-rpc.publicnode.com", "https://polygon.drpc.org",
          "https://rpc.ankr.com/polygon", "https://polygon-mainnet.public.blastapi.io", "https://1rpc.io/matic",
          "https://polygon.llamarpc.com"],
}
CHAIN_NAMES = {1: "Ethereum", 56: "BNB Chain", 42161: "Arbitrum One", 8453: "Base", 137: "Polygon"}
# eth_getLogs range cap: filter on Multicall3, which emits no logs, so the answer is small and only
# the endpoint's range rule decides (a busy token would measure response size, not the range cap).
LOG_ADDRESS = dict.fromkeys((1, 56, 42161, 8453, 137), "0xcA11bde05977b3631167028862bE2a173976CA11")
DEPTHS = (128, 1_000, 10_000, 100_000, 1_000_000, 10_000_000)
LOG_RANGES = (100, 1_000, 2_000, 5_000, 10_000, 50_000)
UA = {"content-type": "application/json", "User-Agent": "contract-review-probe/1"}


def _post(url: str, body: Any, timeout: float = 12.0, headers: dict[str, str] | None = None) -> tuple[int, Any, float]:
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers={**UA, **(headers or {})})
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read(32 * 1024 * 1024)
            dt = time.monotonic() - t0
            try:
                return r.status, json.loads(raw), dt
            except ValueError:
                return 598, None, dt
    except urllib.error.HTTPError as e:
        return e.code, None, time.monotonic() - t0
    except (urllib.error.URLError, TimeoutError, ConnectionError, OSError):
        return 0, None, time.monotonic() - t0


def _get(url: str, timeout: float = 12.0, headers: dict[str, str] | None = None) -> tuple[int, Any, float]:
    req = urllib.request.Request(url, headers={**UA, **(headers or {})})
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read(4 * 1024 * 1024)
            return r.status, json.loads(raw), time.monotonic() - t0
    except urllib.error.HTTPError as e:
        return e.code, None, time.monotonic() - t0
    except (urllib.error.URLError, TimeoutError, ConnectionError, OSError, ValueError):
        return 0, None, time.monotonic() - t0


def rpc(url: str, method: str, params: list[Any], timeout: float = 12.0) -> tuple[int, Any, float]:
    policy.check_evm(method, params)   # the probe obeys the proxy allowlist too
    return _post(url, {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, timeout)


def _lat(xs: list[float]) -> dict[str, float | None]:
    if not xs:
        return {"p50_ms": None, "p95_ms": None}
    xs = sorted(xs)
    return {"p50_ms": round(statistics.median(xs) * 1000), "p95_ms": round(xs[min(len(xs) - 1, int(len(xs) * 0.95))] * 1000)}


def probe_evm_endpoint(cid: int, url: str, calls: int, pause: float) -> dict[str, Any]:
    out: dict[str, Any] = {"url": url, "chain_id": cid}
    ok, rate, lat, errs = 0, 0, [], {}
    head = None
    for _ in range(calls):
        st, data, dt = rpc(url, "eth_blockNumber", [])
        if st == 200 and isinstance(data, dict) and "result" in data:
            ok += 1
            lat.append(dt)
            head = int(data["result"], 16)
        else:
            msg = str((data or {}).get("error", {}).get("message", "") if isinstance(data, dict) else "")[:60]
            if st == 429 or any(w in msg.lower() for w in ("rate", "limit", "too many")):
                rate += 1
            errs[str(st) + (":" + msg if msg else "")] = errs.get(str(st) + (":" + msg if msg else ""), 0) + 1
        time.sleep(pause)
    out.update(availability=round(ok / calls, 3), rate_limited=rate, errors=dict(list(errs.items())[:5]), head=head, **_lat(lat))
    if head is None:
        out.update(depth_ok=None, archive=False, logs_max_range=0)
        return out
    deepest = 0
    depth_rows = {}
    for d in DEPTHS:
        if d >= head:
            break
        st, data, _ = rpc(url, "eth_getBalance", ["0x" + "0" * 40, hex(head - d)])
        good = st == 200 and isinstance(data, dict) and "result" in data
        depth_rows[str(d)] = "ok" if good else (str((data or {}).get("error", {}).get("message", st))[:50]
                                               if isinstance(data, dict) else f"http {st}")
        if good:
            deepest = d
        time.sleep(pause)
    out["depth"] = depth_rows
    out["depth_ok"] = deepest
    out["archive"] = deepest >= 1_000_000
    best = 0
    for r in LOG_RANGES:
        lo = head - 10 - r
        st, data, _ = rpc(url, "eth_getLogs", [{"address": LOG_ADDRESS[cid], "fromBlock": hex(lo), "toBlock": hex(lo + r - 1)}], timeout=20)
        if st == 200 and isinstance(data, dict) and isinstance(data.get("result"), list):
            best = r
        else:
            out.setdefault("logs_refusal", str((data or {}).get("error", {}).get("message", st))[:80] if isinstance(data, dict) else f"http {st}")
            break
        time.sleep(pause)
    out["logs_max_range"] = best
    return out


def probe_fork(url: str, port: int, block: int | None) -> dict[str, Any]:
    anvil = shutil.which("anvil")
    if not anvil:
        return {"fork": "anvil not installed"}
    # anvil 1.5 flags (--retries, --quiet); checked with `anvil --help` on the probe host
    args = [anvil, "--fork-url", url, "--port", str(port), "--no-mining", "--quiet", "--retries", "2", "--timeout", "15000"]
    if block:
        args += ["--fork-block-number", str(block)]
    proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    res: dict[str, Any] = {"fork": "failed"}
    try:
        local = f"http://127.0.0.1:{port}"
        t0 = time.monotonic()
        while time.monotonic() - t0 < 25:
            if proc.poll() is not None:
                res["fork_error"] = (proc.stderr.read() or b"").decode(errors="replace")[-160:] if proc.stderr else ""
                return res
            st, data, _ = _post(local, {"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "params": []}, 3)
            if st == 200 and isinstance(data, dict) and "result" in data:
                break
            time.sleep(0.5)
        else:
            return {"fork": "did not start in 25 s"}
        start_s = round(time.monotonic() - t0, 1)
        served = 0
        for _ in range(5):   # cold state reads go through to the forked endpoint
            st, data, _ = _post(local, {"jsonrpc": "2.0", "id": 1, "method": "eth_getBalance",
                                        "params": ["0x" + os.urandom(20).hex(), "latest"]}, 20)
            served += st == 200 and isinstance(data, dict) and "result" in data
        res = {"fork": "ok" if served == 5 else "partial", "fork_start_s": start_s, "fork_reads_ok": f"{served}/5"}
    finally:
        proc.terminate()
        try:
            proc.wait(5)
        except subprocess.TimeoutExpired:
            proc.kill()
    return res


def probe_tron(calls: int, pause: float) -> dict[str, Any]:
    base = "https://api.trongrid.io"
    ok, rate, lat = 0, 0, []
    for _ in range(calls):
        policy.check_tron("/wallet/getnowblock", "POST", {})
        st, data, dt = _post(base + "/wallet/getnowblock", {})
        if st == 200 and isinstance(data, dict) and data.get("block_header"):
            ok += 1
            lat.append(dt)
        elif st == 429:
            rate += 1
        time.sleep(pause)
    crs = "TRegosVaS1o3DHG85nnW8xYzczPm3xL76K"
    tc_ok = 0
    for _ in range(10):
        st, data, _ = _post(base + "/wallet/triggerconstantcontract", {"owner_address": crs, "contract_address": crs,
                                                                     "function_selector": "totalSupply()", "parameter": "", "visible": True})
        tc_ok += st == 200 and isinstance(data, dict) and bool(data.get("constant_result"))
    st, ev, _ = _get(f"{base}/v1/contracts/{crs}/events?limit=200")
    return {"endpoint": base, "availability": round(ok / calls, 3), "rate_limited": rate, **_lat(lat),
            "trigger_constant_ok": f"{tc_ok}/10 (back to back)", "archive": False,
            "history_events_page": len((ev or {}).get("data") or []) if st == 200 else f"http {st}",
            "note": "triggerconstantcontract is latest state only on every TRON node"}


def probe_solana(calls: int, pause: float) -> dict[str, Any]:
    url = "https://api.mainnet-beta.solana.com"
    ok, rate, lat = 0, 0, []
    for _ in range(calls):
        st, data, dt = _post(url, {"jsonrpc": "2.0", "id": 1, "method": "getSlot", "params": []})
        if st == 200 and isinstance(data, dict) and "result" in data:
            ok += 1
            lat.append(dt)
        elif st == 429:
            rate += 1
        time.sleep(pause)
    st, sig, _ = _post(url, {"jsonrpc": "2.0", "id": 1, "method": "getSignaturesForAddress",
                             "params": ["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", {"limit": 1000}]}, timeout=30)
    return {"endpoint": url, "availability": round(ok / calls, 3), "rate_limited": rate, **_lat(lat),
            "archive": False, "signatures_page": len((sig or {}).get("result") or []) if st == 200 else f"http {st}",
            "note": "Solana JSON-RPC has no account state at a past slot on any node; history is signatures plus transactions"}


def probe_ton(calls: int, pause: float) -> dict[str, Any]:
    v2 = "https://toncenter.com/api/v2"
    ok, rate, lat = 0, 0, []
    head = None
    for _ in range(calls):
        st, data, dt = _get(v2 + "/getMasterchainInfo")
        if st == 200 and isinstance(data, dict) and data.get("ok"):
            ok += 1
            lat.append(dt)
            head = data["result"]["last"]["seqno"]
        elif st == 429:
            rate += 1
        time.sleep(pause)
    usdt = "EQCxE6mUtQJKFnGfaROTKOt1lZbDiiX1kCixRv7Nw2Id_sDs"
    depth = {}
    deepest = 0
    if head:
        for d in (1_000, 100_000, 1_000_000, 10_000_000):
            time.sleep(1.2)
            st, data, _ = _post(v2 + "/runGetMethodStd", {"address": usdt, "method": "get_jetton_data", "stack": [], "seqno": head - d})
            good = st == 200 and isinstance(data, dict) and data.get("ok")
            depth[str(d)] = "ok" if good else (str((data or {}).get("error"))[:60] if isinstance(data, dict) else f"http {st}")
            deepest = d if good else deepest
    time.sleep(1.2)
    st, tx, _ = _get(f"https://toncenter.com/api/v3/transactions?account={usdt}&limit=100")
    return {"endpoint": v2, "availability": round(ok / calls, 3), "rate_limited": rate, **_lat(lat), "depth": depth,
            "depth_ok": deepest, "archive": deepest >= 1_000_000,
            "v3_transactions_page": len((tx or {}).get("transactions") or []) if st == 200 else f"http {st}"}


def verdict(rows: list[dict[str, Any]], key: str) -> str:
    good = [r for r in rows if (r.get("availability") or 0) >= 0.95]
    if key == "state":
        return "reliable" if len(good) >= 2 else "partial" if good else "not available on free"
    if key == "archive":
        arch = [r for r in good if r.get("archive")]
        return "reliable" if len(arch) >= 2 else "partial" if arch or any(r.get("depth_ok", 0) >= 1000 for r in good) \
            else "not available on free"
    if key == "logs":
        best = max([r.get("logs_max_range", 0) for r in good] or [0])
        return "reliable" if best >= 5000 and sum(r.get("logs_max_range", 0) >= 1000 for r in good) >= 2 else \
            "partial" if best >= 100 else "not available on free"
    if key == "fork":
        oks = [r for r in rows if r.get("fork") == "ok"]
        return "reliable" if len(oks) >= 2 else "partial" if oks or any(r.get("fork") == "partial" for r in rows) \
            else "not available on free"
    return "?"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--chains", default="1,56,42161,8453,137,tron,solana,ton")
    ap.add_argument("--calls", type=int, default=50)
    ap.add_argument("--pause", type=float, default=0.1)
    ap.add_argument("--no-fork", action="store_true")
    ap.add_argument("--out", default=str(REPO / ".sbx" / "chain-free-probe.json"))
    ap.add_argument("--write-pool", action="store_true", help="write measured depths into chain/data/free_rpc.json")
    ap.add_argument("--markdown", help="render an existing probe JSON (--out) as a Markdown report to this path")
    args = ap.parse_args()
    if args.markdown:
        Path(args.markdown).write_text(markdown(json.loads(Path(args.out).read_text(encoding="utf-8"))), encoding="utf-8")
        return
    wanted = [c.strip() for c in args.chains.split(",") if c.strip()]
    result: dict[str, Any] = {"date": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"), "calls": args.calls, "chains": {}}
    evm = [int(c) for c in wanted if c.isdigit()]
    jobs = [(cid, url) for cid in evm for url in EVM_CANDIDATES[cid]]
    with cf.ThreadPoolExecutor(max_workers=12) as ex:
        rows = list(ex.map(lambda a: probe_evm_endpoint(a[0], a[1], args.calls, args.pause), jobs))
    port = 18545
    for r in rows:
        if not args.no_fork and r.get("availability", 0) >= 0.5 and r.get("head"):
            r.update(probe_fork(r["url"], port, r["head"] - 5))
            port += 1
    for cid in evm:
        crows = [r for r in rows if r["chain_id"] == cid]
        result["chains"][str(cid)] = {"name": CHAIN_NAMES[cid], "endpoints": crows,
                                      "verdict": {k: verdict(crows, k) for k in ("state", "archive", "logs", "fork")}}
    if "tron" in wanted:
        t = probe_tron(args.calls, max(args.pause, 0.5))
        result["chains"]["tron"] = {"name": "TRON", "endpoints": [t], "verdict": {
            "state": "reliable" if t["availability"] >= 0.95 else "partial", "archive": "not available on free",
            "logs": "partial" if isinstance(t["history_events_page"], int) else "not available on free",
            "fork": "not available on free"}}
    if "solana" in wanted:
        s = probe_solana(args.calls, max(args.pause, 0.2))
        result["chains"]["solana"] = {"name": "Solana", "endpoints": [s], "verdict": {
            "state": "reliable" if s["availability"] >= 0.95 else "partial", "archive": "not available on free",
            "logs": "partial" if isinstance(s["signatures_page"], int) else "not available on free",
            "fork": "not available on free (account clone into a local validator is a later phase)"}}
    if "ton" in wanted:
        o = probe_ton(args.calls, max(args.pause, 1.1))
        result["chains"]["ton"] = {"name": "TON", "endpoints": [o], "verdict": {
            "state": "reliable" if o["availability"] >= 0.95 else "partial",
            "archive": "reliable" if o["archive"] else "partial" if o["depth_ok"] else "not available on free",
            "logs": "partial" if isinstance(o["v3_transactions_page"], int) else "not available on free",
            "fork": "not available on free (sandbox with fetched state is a later phase)"}}
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(result, indent=1) + "\n", encoding="utf-8")
    if args.write_pool:
        write_pool(result)
    for cid, c in result["chains"].items():
        print(cid, c["name"], c["verdict"])


def _depth_text(r: dict[str, Any]) -> str:
    d = r.get("depth_ok")
    return "n/a" if d is None else "head only" if d < 1000 else f"{d:,} blocks"


def markdown(result: dict[str, Any]) -> str:
    lines = [(f"Probe run {result['date']}, {result['calls']} availability calls per endpoint "
              "(scripts/chain_free_probe.py; raw JSON beside this file)."), ""]
    for cid, c in result["chains"].items():
        v = c["verdict"]
        lines += [f"### {c['name']}", "",
                  (f"Verdict: state **{v['state']}**, historical state **{v['archive']}**, logs or history "
                   f"**{v['logs']}**, fork **{v['fork']}**."), ""]
        if cid.isdigit():
            lines += ["| Endpoint | Availability | Rate limited | p50 / p95 ms | State served back | eth_getLogs max range | anvil fork |",
                      "|---|---|---|---|---|---|---|"]
            for r in c["endpoints"]:
                lat = f"{r.get('p50_ms')} / {r.get('p95_ms')}" if r.get("p50_ms") else "n/a"
                logs = f"{r.get('logs_max_range', 0):,}" if r.get("logs_max_range") else (
                    "refused: " + str(r.get("logs_refusal") or "")[:40] if r.get("head") else "n/a")
                fork = r.get("fork") or "n/a"
                if r.get("fork_start_s") is not None:
                    fork += f" ({r['fork_start_s']} s, {r.get('fork_reads_ok')} reads)"
                lines.append(f"| {r['url']} | {r.get('availability', 0):.0%} | {r.get('rate_limited', 0)} | {lat} | "
                             f"{_depth_text(r)} | {logs} | {fork} |")
        else:
            r = c["endpoints"][0]
            extra = {k: v for k, v in r.items() if k not in ("endpoint", "availability", "rate_limited", "p50_ms", "p95_ms", "note")}
            lines += [f"Endpoint {r['endpoint']}: availability {r['availability']:.0%}, rate limited {r['rate_limited']}, "
                      f"p50 / p95 {r.get('p50_ms')} / {r.get('p95_ms')} ms. Other checks: "
                      + ", ".join(f"{k} {v}" for k, v in extra.items()) + "."]
            if r.get("note"):
                lines.append(r["note"] + ".")
        lines.append("")
    return "\n".join(lines) + "\n"


def depth_label(r: dict[str, Any]) -> str:
    d = r.get("depth_ok") or 0
    return "archive" if d >= 1_000_000 else "recent" if d >= 1_000 else "head"


def write_pool(result: dict[str, Any]) -> None:
    """Pool rows ordered by measured depth then availability; endpoints under 80% availability are left out."""
    p = REPO / "src" / "soken_review" / "chain" / "data" / "free_rpc.json"
    doc = json.loads(p.read_text(encoding="utf-8"))
    rank = {"archive": 0, "recent": 1, "head": 2}
    for cid, c in result["chains"].items():
        if not cid.isdigit():
            continue
        rows = [r for r in c["endpoints"] if (r.get("availability") or 0) >= 0.8]
        rows.sort(key=lambda r: (rank[depth_label(r)], -(r.get("availability") or 0), r.get("p50_ms") or 9999))
        doc["chains"][cid] = [{"url": r["url"], "depth": depth_label(r), "logs_max_range": r.get("logs_max_range", 0)}
                              for r in rows]
        doc.setdefault("down", {})[cid] = sorted(r["url"] for r in c["endpoints"] if (r.get("availability") or 0) < 0.8)
    doc["checked_at"] = result["date"][:10]
    doc.pop("registry_depth", None)
    p.write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
