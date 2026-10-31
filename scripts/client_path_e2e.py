#!/usr/bin/env python3
"""Client-path regression suite: the real stack (Postgres, HTTP server, worker, locked sandbox images)
driven through the MCP tools over HTTP for fixture jobs on every released family.

    uv run python scripts/client_path_e2e.py up                      # Postgres (tmpfs), egress, server, worker
    uv run python scripts/client_path_e2e.py run --targets evm,ton   # drive the targets, print the table
    uv run python scripts/client_path_e2e.py down
    uv run python scripts/client_path_e2e.py all --targets evm,evm-proxy,evm-repo,solana,solana-repo,ton,ton-repo,tron

Targets (scripts/client_path_driver.py TARGETS): evm (WETH9 on mainnet: full reviewer flow with a
Medium finding, challenge, every section, the stale-client JSON-string invariant_walks, PDF), evm-proxy
(EigenLayer stETH strategy, EIP-1967: one job on a proxy reviews the implementation, reads state at the
proxy, one PDF), evm-repo
(Apyee v2.0.0, Hardhat with npm deps), solana (agent-loans programs/locker repo), ton (Forton tier A), ton-repo (HipoFinance FunC repo, family
detected from the tree, third party, no deployment), solana-repo (Pump Science Anchor workspace, repo only),
tron (CRS token). Images come from images.lock.json by digest (`SOKEN_IMAGE_*` overrides for a local
build); Postgres runs in Docker on tmpfs unless SOKEN_DATABASE_URL points at one.

Exit 1 when any target fails; a target that stops on a confirmed upstream outage is reported as
`skipped: upstream` and does not fail the run. State lives in <root>/stack.json (default .sbx/cpe).
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import signal
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
sys.path.insert(0, str(REPO / "src"))

from client_path_driver import TARGETS, TargetResult, run_target

PG_IMAGE = "postgres:16"
PG_NAME = "soken-pg-cpe"
PG_PORT = 5439
DEFAULT_TARGETS = "evm,evm-proxy,evm-repo,solana,solana-repo,ton,ton-repo,tron"
# egress family per target (sandbox/egress.py): only repo fetch and deps containers have a network
EGRESS = {"evm-repo": "evm", "solana": "solana", "ton-repo": "evm", "solana-repo": "solana"}


def _root(args: argparse.Namespace) -> Path:
    root = Path(args.root).resolve()
    for sub in ("pins", "work", "reports", "render-tmp", "solc", "logs", "out"):
        (root / sub).mkdir(parents=True, exist_ok=True)
    return root


def _state_path(root: Path) -> Path:
    return root / "stack.json"


def _free_port(preferred: int) -> int:
    with socket.socket() as s:
        try:
            s.bind(("127.0.0.1", preferred))
            return preferred
        except OSError:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]


def _docker(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=check)


def start_postgres(port: int) -> str:
    """Postgres 16 on tmpfs: nothing to clean up, and no disk pressure on a tight Docker VM."""
    _docker("rm", "-f", PG_NAME, check=False)
    _docker("run", "-d", "--name", PG_NAME, "-e", "POSTGRES_USER=soken", "-e", "POSTGRES_PASSWORD=soken",
            "-e", "POSTGRES_DB=soken", "-p", f"127.0.0.1:{port}:5432", "--tmpfs", "/var/lib/postgresql/data",
            "--shm-size", "256m", PG_IMAGE)
    for _ in range(60):
        if _docker("exec", PG_NAME, "pg_isready", "-U", "soken", check=False).returncode == 0:
            time.sleep(1)
            return f"postgresql://soken:soken@127.0.0.1:{port}/soken"
        time.sleep(1)
    raise SystemExit("postgres did not become ready in 60 s")


def egress_up(family: str, env: dict[str, str]) -> None:
    name = f"soken-smokescreen-{family}"
    running = _docker("inspect", "-f", "{{.State.Running}}", name, check=False)
    if running.returncode == 0 and running.stdout.strip() == "true":
        print(f"egress {family}: {name} already running", flush=True)
        return
    from soken_review.sandbox.profile import locked_image

    image = locked_image("smokescreen")
    if image is None:
        raise SystemExit("smokescreen image not pinned and SOKEN_IMAGE_SMOKESCREEN unset")
    subprocess.run([sys.executable, "-m", "soken_review.sandbox.egress", "up", family, "--image", image,
                    "--config-root", str(Path(env["SOKEN_PIN_ROOT"]).parent / "egress")], check=True, env=env)
    print(f"egress {family}: up ({image})", flush=True)


def stack_env(root: Path, dsn: str, port: int, *, render_direct: bool = False) -> dict[str, str]:
    env = dict(os.environ)
    env.update({
        "SOKEN_DATABASE_URL": dsn,
        "SOKEN_PIN_ROOT": str(root / "pins"),
        "SOKEN_REPORT_STORE": str(root / "reports"),
        "SOKEN_RENDER_ROOT": str(root / "render-tmp"),
        "SOKEN_SOLC_CACHE_DIR": str(root / "solc"),
        "SOKEN_SANDBOX_RUNTIME": env.get("SOKEN_SANDBOX_RUNTIME", "runc"),
        "SOKEN_SANDBOX_DEV_PERMS": "1",
        "SOKEN_REPORT_SITE": f"http://127.0.0.1:{port}",
        "SOKEN_ALLOWED_HOSTS": f"127.0.0.1:{port},localhost:{port},127.0.0.1:*,localhost:*",
        "SOKEN_AUTOPUBLISH": "off",
        "SOKEN_DISABLED_FAMILIES": env.get("SOKEN_DISABLED_FAMILIES", "starknet,sui"),
        "SOKEN_WORKER_HOST": "client-path-e2e",
        "PYTHONUNBUFFERED": "1",
    })
    # A per-run report signing key (the API refuses to start without one); never a committed value.
    env.setdefault("SOKEN_REPORT_KEY_V1", secrets.token_hex(32))
    if render_direct:
        # Dev only (report/render.py DIRECT): the kit on the host with the host Chrome, for a Docker VM
        # that cannot run the amd64 soken-render image (chrome_start under emulation). CI uses the image.
        env["SOKEN_RENDER_DIRECT"] = "1"
        env.setdefault("CHROME_BIN", _host_chrome())
    return env


def _host_chrome() -> str:
    for cand in ("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "/usr/bin/google-chrome",
                 "/usr/bin/chromium", "/usr/bin/chromium-browser"):
        if Path(cand).exists():
            return cand
    raise SystemExit("--render-direct needs CHROME_BIN or a host Chrome")


def _wait_health(port: int, timeout_s: float = 120.0) -> None:
    import httpx

    deadline = time.monotonic() + timeout_s
    last = ""
    while time.monotonic() < deadline:
        try:
            r = httpx.get(f"http://127.0.0.1:{port}/healthz", timeout=5)
            last = f"{r.status_code} {r.text[:200]}"
            if r.status_code == 200:
                print(f"healthz: {last}", flush=True)
                return
        except httpx.HTTPError as exc:
            last = str(exc)
        time.sleep(2)
    raise SystemExit(f"stack not healthy after {timeout_s:.0f}s: {last}")


def cmd_up(args: argparse.Namespace) -> None:
    root = _root(args)
    port = _free_port(args.port)
    dsn = os.environ.get("SOKEN_DATABASE_URL") or start_postgres(PG_PORT if args.pg_port is None else args.pg_port)
    env = stack_env(root, dsn, port, render_direct=args.render_direct)
    import asyncio

    from soken_review.db.migrate import run_migrations

    applied = asyncio.run(run_migrations(dsn))
    print(f"migrations applied: {applied or 'none (up to date)'}", flush=True)
    families = sorted({EGRESS[t] for t in args.targets.split(",") if t in EGRESS})
    for fam in families:
        egress_up(fam, env)
    logs = root / "logs"
    server_log = (logs / "server.log").open("ab")
    worker_log = (logs / "worker.log").open("ab")
    server = subprocess.Popen([sys.executable, "-m", "uvicorn", "soken_review.tools.context_pg:create_app",
                               "--factory", "--host", "127.0.0.1", "--port", str(port), "--log-level", "info"],
                              env=env, stdout=server_log, stderr=subprocess.STDOUT, cwd=str(REPO))
    worker = subprocess.Popen([sys.executable, "-m", "soken_review.worker"], env=env, stdout=worker_log,
                              stderr=subprocess.STDOUT, cwd=str(REPO))
    state = {"port": port, "dsn": dsn, "server_pid": server.pid, "worker_pid": worker.pid,
             "store_root": str(root / "reports"), "report_key": env["SOKEN_REPORT_KEY_V1"],
             "pg_container": None if os.environ.get("SOKEN_DATABASE_URL") else PG_NAME}
    _state_path(root).write_text(json.dumps(state, indent=1))
    try:
        _wait_health(port)
    except SystemExit:
        print((logs / "server.log").read_text()[-3000:], file=sys.stderr)
        print((logs / "worker.log").read_text()[-3000:], file=sys.stderr)
        cmd_down(args)
        raise
    print(f"stack up: http://127.0.0.1:{port}/mcp  worker pid {worker.pid}  root {root}", flush=True)


def cmd_down(args: argparse.Namespace) -> None:
    root = _root(args)
    path = _state_path(root)
    if not path.exists():
        print("no stack state; nothing to stop")
        return
    state = json.loads(path.read_text())
    for key in ("worker_pid", "server_pid"):
        pid = state.get(key)
        if pid:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
    time.sleep(2)
    for key in ("worker_pid", "server_pid"):
        pid = state.get(key)
        if pid:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    if state.get("pg_container"):
        _docker("rm", "-f", state["pg_container"], check=False)
    path.unlink()
    print("stack down", flush=True)


def _print_table(results: list[TargetResult]) -> None:
    print("\n" + "=" * 100)
    print(f"{'target':10} {'status':18} {'pages':>5} {'calls':>5} {'secs':>6}  job / error")
    print("-" * 100)
    for r in results:
        tail = r.error or r.job_id or ""
        print(f"{r.name:10} {r.status:18} {r.pages or ''!s:>5} {r.calls:>5} {r.seconds:>6.0f}  {tail[:70]}")
    print("-" * 100)
    for r in results:
        for c in r.checks:
            mark = "ok  " if c.ok else "FAIL"
            mark = "GAP " if (not c.ok and c.gap) else mark
            print(f"  [{mark}] {r.name}: {c.name}  {c.detail}")
        if r.error:
            print(f"  [ERR ] {r.name}: {r.error}")
    print("=" * 100, flush=True)


def cmd_run(args: argparse.Namespace) -> int:
    root = _root(args)
    state = json.loads(_state_path(root).read_text())
    base = f"http://127.0.0.1:{state['port']}"
    store_root = Path(state["store_root"])
    out = Path(args.out).resolve() if args.out else root / "out"
    names = [t.strip() for t in args.targets.split(",") if t.strip()]
    unknown = [n for n in names if n not in TARGETS]
    if unknown:
        raise SystemExit(f"unknown targets {unknown}; known: {sorted(TARGETS)}")
    t0 = time.monotonic()
    with ThreadPoolExecutor(max_workers=max(1, args.parallel)) as pool:
        results = list(pool.map(lambda n: run_target(TARGETS[n], base, store_root, out / n), names))
    _print_table(results)
    summary = {"runtime_s": round(time.monotonic() - t0), "results": [
        {"name": r.name, "status": r.status, "job_id": r.job_id, "pages": r.pages, "calls": r.calls,
         "seconds": round(r.seconds), "error": r.error, "failed_checks": [c.name for c in r.failed],
         "known_gaps": [c.name for c in r.gaps]} for r in results]}
    (out / "summary.json").write_text(json.dumps(summary, indent=1))
    print(f"runtime {summary['runtime_s']} s; summary {out / 'summary.json'}", flush=True)
    failed = [r for r in results if r.status == "fail"]
    skipped = [r for r in results if r.status.startswith("skipped")]
    if skipped:
        print("skipped (upstream): " + ", ".join(f"{r.name}: {r.error}" for r in skipped))
    return 1 if failed else 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("cmd", choices=["up", "run", "down", "all"])
    p.add_argument("--root", default=str(REPO / ".sbx" / "cpe"), help="state root (pins, reports, logs)")
    p.add_argument("--port", type=int, default=8765, help="HTTP port (a free one is picked when taken)")
    p.add_argument("--pg-port", type=int, default=None)
    p.add_argument("--targets", default=DEFAULT_TARGETS)
    p.add_argument("--parallel", type=int, default=5)
    p.add_argument("--out", default=None, help="output dir for PDFs, report.json copies, call logs")
    p.add_argument("--render-direct", action="store_true",
                   help="dev only: render with the host Chrome (SOKEN_RENDER_DIRECT=1) instead of the soken-render image")
    args = p.parse_args()
    if args.cmd == "up":
        cmd_up(args)
        return 0
    if args.cmd == "down":
        cmd_down(args)
        return 0
    if args.cmd == "run":
        return cmd_run(args)
    cmd_up(args)
    try:
        return cmd_run(args)
    finally:
        cmd_down(args)


if __name__ == "__main__":
    sys.exit(main())
