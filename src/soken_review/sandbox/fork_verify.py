"""review_verify_on_fork: run a reviewer's Foundry test against a local fork (chain access design 1.7,
P4 on EVM; 3.1 to 3.4 for the sandbox).

The test is hostile until proven otherwise. What it gets:

- one Solidity file under `test/`, importing only `forge-std/...` (the image's pinned copy) and
  `pinned/<path>` (the job's pinned source tree, read-only); `check_test_source` refuses anything
  else before a row is written;
- a project directory written by the supervisor and mounted read-only: `foundry.toml` (ffi off, no
  file system permissions, offline, no RPC storage cache, build output on the container's tmpfs),
  the test, and the pinned tree; no `.env`, no repo `foundry.toml`;
- `forge test --json` in the evm-analyze image (digest-pinned) under gVisor (`runsc-egress`), on the
  internal `soken-chainsim` network whose only peer is the run's relay. The relay forwards to the
  run's chain endpoint (`chain/fork_rpc.py`) on a Unix socket in the supervisor, behind the proxy
  policy: no send, sign or broadcast method is ever forwarded, and no block after the fork block is
  readable. The fork itself is forge's in-memory copy; nothing leaves it;
- CPU, memory, pids, file size, wall clock and output caps from `limits.yaml` `fork_verify`, sized for
  a 2 vCPU / 3.9 GiB host; the worker claims one `verify_fork` step at a time (job_repo.claim_step).

What comes back is data: per test status, gas and the assertion message and console lines as
untrusted text (`chain.untrusted.untrusted_text`), never as instructions. A failure of any kind is a
run result (`error`, `timeout`), never a job failure: review and finalize do not depend on a run.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import secrets
import shutil
import subprocess
import time
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from ..chain.untrusted import untrusted_text

logger = logging.getLogger(__name__)

_LIMITS = Path(__file__).resolve().parents[3] / "contract" / "ops" / "limits.yaml"
RELAY_SCRIPT = Path(__file__).resolve().parent / "rpc_relay.py"
COLLECT_SCRIPT = Path(__file__).resolve().parent / "fork_collect.py"
COLLECT_PATH = "/work/tools/fork_collect.py"
RELAY_PORT = 8545
FORGE_STD_ROOT = "/opt/forge-std"
PROJECT_DIR = "/work/project"
TEST_PATH_RE = re.compile(r"^test/[A-Za-z][A-Za-z0-9_]{0,63}\.t\.sol$")
DEFAULT_TEST_PATH = "test/Verify.t.sol"
_IMPORT_RE = re.compile(r"""\bimport\s+(?:[^;"']*?\bfrom\s+)?["']([^"']{1,300})["']\s*(?:as\s+\w+\s*)?;""")
_FORGE_STD_IMPORT = re.compile(r"^forge-std/[A-Za-z0-9_/]{1,120}\.sol$")
_COMMENT_RE = re.compile(r"//[^\n]*|/\*.*?\*/", re.DOTALL)
_VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)")
_REMAP_RE = re.compile(r"^([A-Za-z0-9@_.\-/]{1,120}/)=([A-Za-z0-9@_.\-/]{0,200})$")
_PIN_SAFE = re.compile(r"^[A-Za-z0-9@_.\-+/ ]{1,300}$")
MAX_PIN_FILES = 4000
MAX_PIN_BYTES = 64 * 1024 * 1024


@lru_cache(maxsize=1)
def fork_limits() -> dict[str, Any]:
    return dict(yaml.safe_load(_LIMITS.read_text(encoding="utf-8")).get("fork_verify") or {})


class TestRejected(ValueError):
    """The test file breaks a rule; nothing was queued. Fields map onto E_INVALID_ARGUMENT."""

    def __init__(self, field: str, rule: str, value: str, example: str) -> None:
        super().__init__(f"{field}: {rule}")
        self.field = field
        self.rule = rule
        self.value = value[:80]
        self.example = example


# ── test validation (tool side, before any row exists) ─────────────────────


def check_test_path(path: str | None) -> str:
    p = path or DEFAULT_TEST_PATH
    if not TEST_PATH_RE.match(p):
        raise TestRejected("test.path", "test/<Name>.t.sol, letters, digits and _ only", p, DEFAULT_TEST_PATH)
    return p


def test_imports(content: str) -> list[str]:
    """Import paths of a Solidity source, comments stripped."""
    return _IMPORT_RE.findall(_COMMENT_RE.sub(" ", content))


def check_test_source(content: str, pin_paths: set[str], *, max_bytes: int | None = None) -> list[str]:
    """Return the imports of an acceptable test file, else raise TestRejected.

    Allowed imports: `forge-std/<file>.sol` and `pinned/<path>` for a Solidity file of the job's pin
    (as review_read_code lists it). Relative, absolute and remapped imports are refused, so the test
    can reach the reviewed code and forge-std and nothing else on disk."""
    cap = int(max_bytes or fork_limits().get("test_bytes", 65536))
    raw = content.encode("utf-8", "surrogatepass")
    if len(raw) > cap:
        raise TestRejected("test.content", f"at most {cap} bytes", f"{len(raw)} bytes", "one test contract")
    if "\x00" in content:
        raise TestRejected("test.content", "text without NUL bytes", "NUL", "a Solidity source")
    if not re.search(r"\bpragma\s+solidity\b", content):
        raise TestRejected("test.content", "a Solidity source with a pragma", content[:80], "pragma solidity ^0.8.13;")
    if not re.search(r"\bfunction\s+(test|invariant)\w*\s*\(", content):
        raise TestRejected("test.content", "at least one test function (name starts with test)",
                           content[:80], "function test_depositCredits() public")
    imports = test_imports(content)
    for imp in imports:
        if _FORGE_STD_IMPORT.match(imp) and ".." not in imp:
            continue
        if imp.startswith("pinned/") and imp.removeprefix("pinned/") in pin_paths and imp.endswith(".sol"):
            continue
        raise TestRejected("test.content", "imports only forge-std/<file>.sol or pinned/<path of a pinned .sol file>",
                           imp, 'import {Test} from "forge-std/Test.sol"; import "pinned/src/Vault.sol";')
    return imports


def test_sha256(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8", "surrogatepass")).hexdigest()


# ── compiler and project layout (supervisor side) ──────────────────────────


def _vtuple(v: str) -> tuple[int, int, int] | None:
    m = _VERSION_RE.match(v or "")
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None


def job_compiler(cands: list[dict[str, Any]], build: dict[str, Any] | None) -> str | None:
    """The job's solc (`0.8.20` or `0.8.20+commit.x`), from the build attempts or the candidate."""
    for att in reversed((build or {}).get("attempts") or []):
        if isinstance(att, dict) and att.get("status") == "ok" and att.get("version"):
            return str(att["version"])
    for c in cands or []:
        v = ((c or {}).get("compiler") or {}).get("version")
        if v:
            return str(v)
    return None


def choose_solc(job_version: str | None) -> str:
    """The job's compiler when forge-std compiles with it (>= its pragma floor), else the default:
    a test that imports pinned code compiles it with the same compiler the job was built with."""
    lim = fork_limits()
    floor = _vtuple(str(lim.get("forge_std_floor", "0.8.13"))) or (0, 8, 13)
    jv = _vtuple(job_version or "")
    if jv is not None and jv >= floor and jv < (0, 9, 0):
        return str(job_version)
    return str(lim.get("solc", "0.8.28"))


def pinned_remappings(cands: list[dict[str, Any]], pin_paths: set[str]) -> list[str]:
    """The job's own remappings, re-rooted under `pinned/`, for imports inside the pinned tree. A
    remapping whose target is not a directory of the pin is dropped."""
    dirs = {p.rsplit("/", 1)[0] + "/" for p in pin_paths if "/" in p}
    prefixes = {d[: i + 1] for d in dirs for i in range(len(d)) if d[i] == "/"}
    out: list[str] = []
    for c in cands[:1] if cands else []:
        for r in ((c or {}).get("settings") or {}).get("remappings") or []:
            if not isinstance(r, str) or ":" in r:
                continue
            m = _REMAP_RE.match(r.strip())
            if not m or m.group(1).startswith("-") or ".." in m.group(2).split("/"):
                continue
            target = m.group(2).lstrip("./")
            if target and not target.endswith("/"):
                target += "/"
            if target and target not in prefixes:
                continue
            out.append(f"{m.group(1)}=pinned/{target}")
    return out[:64]


def foundry_toml(remappings: list[str], *, gas_limit: int = 1_000_000_000) -> str:
    """Server-written config. Every key that could reach outside the project is fixed here."""
    remaps = [f"forge-std/={FORGE_STD_ROOT}/src/", *remappings]
    lines = [
        "[profile.default]",
        'src = "test"', 'test = "test"', 'script = "test"', "libs = []",
        'out = "/tmp/forge-out"', 'cache_path = "/tmp/forge-cache"', 'broadcast = "/tmp/forge-broadcast"',
        "remappings = [" + ", ".join(json.dumps(r) for r in remaps) + "]",
        f"allow_paths = [{json.dumps(FORGE_STD_ROOT)}]",
        "ffi = false", "fs_permissions = []", "offline = true", "auto_detect_solc = false",
        "no_storage_caching = true", "always_use_create_2_factory = false",
        f"gas_limit = {int(gas_limit)}", "memory_limit = 134217728",
        "[profile.default.fuzz]", "runs = 32",
        "[profile.default.invariant]", "runs = 8", "depth = 16",
    ]
    return "\n".join(lines) + "\n"


def write_project(project: Path, test_path: str, content: str, pin: Any, remappings: list[str]) -> int:
    """Write the run's project tree on the host (mounted read-only). Returns the pinned file count."""
    if project.exists():
        shutil.rmtree(project)
    (project / "test").mkdir(parents=True)
    (project / "foundry.toml").write_text(foundry_toml(remappings), encoding="utf-8")
    (project / test_path).write_text(content, encoding="utf-8")
    root = project / "pinned"
    root.mkdir()
    n = size = 0
    for path in sorted(pin.entries):
        if not path.endswith(".sol") or not _PIN_SAFE.match(path) or path.startswith("/") \
                or ".." in path.split("/"):
            continue
        text = pin.read_text(path)
        size += len(text)
        n += 1
        if n > MAX_PIN_FILES or size > MAX_PIN_BYTES:
            raise RunError("pin_too_large", f"{n} files, {size} bytes")
        dest = root / path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(text, encoding="utf-8")
    for d in [project, *[p for p in project.rglob("*") if p.is_dir()]]:
        d.chmod(0o755)
    for f in [p for p in project.rglob("*") if p.is_file()]:
        f.chmod(0o644)
    return n


class RunError(Exception):
    """A run that could not produce a test result; `reason` is a short machine word."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}"[:200])
        self.reason = reason
        self.detail = detail[:400]


# ── forge output ───────────────────────────────────────────────────────────


def forge_doc(raw: bytes) -> dict[str, Any]:
    """The JSON document `forge test --json` printed (the whole output, else its last JSON line)."""
    text = raw.decode("utf-8", "replace").strip()
    for line in [text, *reversed(text.splitlines())]:
        try:
            doc = json.loads(line)
        except ValueError:
            continue
        if isinstance(doc, dict):
            return doc
    raise RunError("no_result", "forge printed no JSON result")


_CALL_KINDS = frozenset({"CALL", "STATICCALL", "DELEGATECALL"})
_HEX = re.compile(r"^(0x)?[0-9a-fA-F]*$")


def trace_calls(doc: dict[str, Any]) -> tuple[set[str], dict[str, str]]:
    """From the forge call traces (-vvvv): the addresses entered by CALL, STATICCALL or DELEGATECALL,
    and the runtime code of every contract the run created (CREATE, CREATE2 output), by address. The
    traces are the EVM's own record; no name or RPC method is inferred."""
    called: set[str] = set()
    created: dict[str, str] = {}
    for body in doc.values():
        for r in ((body or {}).get("test_results") or {}).values() if isinstance(body, dict) else []:
            for entry in (r or {}).get("traces") or []:
                arena = entry[1] if isinstance(entry, list) and len(entry) == 2 else None
                for node in (arena or {}).get("arena") or [] if isinstance(arena, dict) else []:
                    t = (node or {}).get("trace") or {}
                    addr = str(t.get("address") or "").lower()
                    if not re.fullmatch(r"0x[0-9a-f]{40}", addr):
                        continue
                    kind = str(t.get("kind") or "")
                    if kind in _CALL_KINDS:
                        called.add(addr)
                    elif kind in ("CREATE", "CREATE2") and t.get("success"):
                        out = str(t.get("output") or "")
                        if _HEX.match(out):
                            created[addr] = out.removeprefix("0x").lower()
    return called, created


def _masked(code_hex: str, ranges: list[tuple[int, int]]) -> bytes:
    try:
        b = bytearray(bytes.fromhex(code_hex))
    except ValueError:
        return b""
    for start, length in ranges:
        if 0 <= start and start + length <= len(b):
            b[start:start + length] = bytes(length)
    return bytes(b)


def validate_artifacts(items: Any) -> list[dict[str, Any]]:
    """The artifacts the in-container collector (fork_collect.py) printed, re-checked: at most 16, hex
    code, total 32 MiB, bounded immutable ranges. Anything malformed is dropped."""
    arts: list[dict[str, Any]] = []
    total = 0
    for a in items if isinstance(items, list) else []:
        if not isinstance(a, dict) or len(arts) >= 16:
            continue
        code = str(a.get("code") or "").removeprefix("0x").lower()
        path, name = a.get("path"), a.get("contract")
        if not code or not _HEX.match(code) or not isinstance(path, str) or not isinstance(name, str):
            continue
        total += len(code)
        if total > 32 * 1024 * 1024:
            break
        ranges = [(int(r[0]), int(r[1])) for r in (a.get("ranges") or [])[:256]
                  if isinstance(r, list) and len(r) == 2 and all(isinstance(x, int) and 0 <= x < 1 << 25 for x in r)]
        arts.append({"path": path[:300], "contract": name[:80], "code": code, "ranges": ranges})
    return arts


def unwrap(stdout: bytes) -> tuple[bytes, list[dict[str, Any]], bool]:
    """(forge --json stdout, validated artifacts, output cap hit) from the collector's object."""
    try:
        doc = json.loads(stdout.decode("utf-8", "replace"))
    except ValueError:
        return stdout, [], False
    if not isinstance(doc, dict) or "forge" not in doc:
        return stdout, [], False
    return str(doc.get("forge") or "").encode(), validate_artifacts(doc.get("artifacts")), bool(doc.get("output_cap"))


def called_pinned(called: set[str], created: dict[str, str], artifacts: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Pinned contracts the run called: an address entered by a call whose created runtime code equals
    the artifact compiled from the pinned source (immutable ranges masked on both sides)."""
    out: list[dict[str, str]] = []
    for addr in sorted(called & set(created)):
        for art in artifacts:
            if len(created[addr]) == len(art["code"]) and \
                    _masked(created[addr], art["ranges"]) == _masked(art["code"], art["ranges"]):
                out.append({"path": art["path"], "contract": art["contract"], "address": addr})
    return out[:50]


def parse_forge_json(raw: bytes, *, max_tests: int | None = None, log_lines: int | None = None) -> list[dict[str, Any]]:
    """Per test results of `forge test --json`. Reasons and console lines are untrusted text."""
    lim = fork_limits()
    max_tests = int(max_tests or lim.get("max_tests", 20))
    log_lines = int(log_lines or lim.get("log_lines", 40))
    doc = forge_doc(raw)
    tests: list[dict[str, Any]] = []
    for suite, body in sorted(doc.items()):
        if not isinstance(body, dict):
            continue
        contract = str(suite).rsplit(":", 1)[-1][:80]
        for fn, r in sorted((body.get("test_results") or {}).items()):
            if not isinstance(r, dict):
                continue
            status = {"Success": "passed", "Failure": "failed", "Skipped": "skipped"}.get(str(r.get("status")), "failed")
            kind = r.get("kind") or {}
            gas = None
            if isinstance(kind, dict):
                if isinstance(kind.get("Unit"), dict):
                    gas = kind["Unit"].get("gas")
                elif isinstance(kind.get("Fuzz"), dict):
                    gas = kind["Fuzz"].get("mean_gas")
            item: dict[str, Any] = {"name": f"{contract}.{str(fn)[:120]}", "status": status,
                                    "gas": int(gas) if isinstance(gas, int) and not isinstance(gas, bool) else None}
            if r.get("reason"):
                item["reason"] = untrusted_text(r["reason"], "forge test assertion", cap=256)
            logs = [x for x in (r.get("decoded_logs") or []) if isinstance(x, str)]
            if logs:
                item["logs"] = [untrusted_text(x, "forge test console", cap=200) for x in logs[:log_lines]]
                if len(logs) > log_lines:
                    item["logs_more"] = len(logs) - log_lines
            item["events"] = len(r.get("logs") or [])
            tests.append(item)
    if not tests:
        raise RunError("no_tests", "no test function ran")
    tests.sort(key=lambda t: t["name"])
    if len(tests) > max_tests:
        tests = tests[:max_tests] + [{"name": f"{len(tests) - max_tests} more", "status": "not_reported"}]
    return tests


def run_status(tests: list[dict[str, Any]]) -> str:
    ran = [t for t in tests if t["status"] in ("passed", "failed")]
    if not ran:
        return "error"
    return "passed" if all(t["status"] == "passed" for t in ran) else "failed"


def compile_error(stderr: str) -> dict[str, Any]:
    """The tail of forge's diagnostics, as untrusted text (it quotes the reviewer's source)."""
    lines = [ln for ln in stderr.splitlines() if ln.strip()]
    pick = [ln for ln in lines if "Error" in ln or "error" in ln][:6] or lines[-6:]
    return untrusted_text(" | ".join(pick), "forge diagnostics", cap=600)


# ── container plumbing ─────────────────────────────────────────────────────


def _docker(*args: str, timeout: float = 60) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=False, timeout=timeout)


def ensure_network(name: str) -> None:
    """The internal chainsim network (no route out); created once, idempotent."""
    if _docker("network", "inspect", name).returncode == 0:
        return
    res = _docker("network", "create", "--internal", name)
    if res.returncode != 0 and "already exists" not in res.stderr:
        raise RunError("sandbox_unavailable", f"network {name}: {res.stderr.strip()[:160]}")


def relay_argv(name: str, image: str, sock_dir: Path, network: str) -> list[str]:
    """The relay container: our stdlib script, runc (it must open the host-side Unix socket, which
    gVisor does not pass through), read-only, no capabilities, the sandbox uid, the internal network."""
    return ["docker", "run", "-d", "--rm", "--name", name, "--runtime=runc", f"--network={network}",
            "--user", "10001:10001", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
            "--pids-limit=32", "--memory=96m", "--memory-swap=96m", "--cpus=0.25", "--log-driver", "none",
            "--mount", f"type=bind,src={RELAY_SCRIPT},dst=/relay/rpc_relay.py,readonly",
            "--mount", f"type=bind,src={sock_dir.resolve()},dst=/relay/sock",
            "--entrypoint", "python3", image, "-I", "/relay/rpc_relay.py", str(RELAY_PORT), "/relay/sock/rpc.sock"]


def container_ip(name: str, network: str) -> str | None:
    res = _docker("inspect", "--format", "{{(index .NetworkSettings.Networks \"" + network + "\").IPAddress}}", name)
    ip = res.stdout.strip()
    return ip if res.returncode == 0 and re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip) else None


def run_capped(argv: list[str], wall_s: float, stdout_cap: int, kill: Any, out_path: Path,
               err_path: Path, grace_s: float = 10.0) -> tuple[int | None, str | None]:
    """Run argv with stdout and stderr in host files; at the wall or when the output passes its cap,
    `kill()` (docker rm -f of the named container), then the process group after `grace_s`."""
    import signal

    with open(out_path, "wb") as out_fh, open(err_path, "wb") as err_fh:
        proc = subprocess.Popen(argv, stdout=out_fh, stderr=err_fh, start_new_session=True)
        deadline = time.monotonic() + wall_s
        killed_by = None
        try:
            while proc.poll() is None:
                if time.monotonic() > deadline:
                    killed_by = "wall"
                elif out_path.stat().st_size > stdout_cap or err_path.stat().st_size > stdout_cap:
                    killed_by = "output"
                if killed_by:
                    break
                time.sleep(0.25)
        finally:
            if proc.poll() is None:
                kill()
                try:
                    proc.wait(timeout=grace_s)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except OSError:
                        proc.kill()
                    proc.wait()
    return proc.returncode, killed_by


def _read_capped(path: Path, cap: int) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read(cap + 1)
    except OSError:
        return b""


def sock_root(pin_root: Path) -> Path:
    """Short host directory for run sockets (a Unix socket path is at most 107 bytes). Never /tmp: a
    worker with a private /tmp would bind a path the Docker daemon cannot see."""
    env = os.environ.get("SOKEN_FORK_SOCK_DIR")
    return Path(env) if env else pin_root.parent / "fork-sock"


async def execute(run: dict[str, Any], pin_root: Path, *, image: str | None = None, runtime: str | None = None,
                  proxy_factory: Any = None) -> dict[str, Any]:
    """Run one fork test. Returns the result document (status, tests, rpc, wall_s, ...). Raises RunError
    for a run that produced no test result."""
    from ..adapters.evm.compiler import SolcCache
    from ..chain.fork_rpc import ForkStats, fork_app, serve
    from ..chain.proxy import Meter
    from ..pinning.store import PinnedSource
    from .profile import CHAINSIM_NETWORK, StepLimits, docker_argv, locked_image, locked_tools

    lim = fork_limits()
    image = image or locked_image("evm-analyze")
    if image is None:
        raise RunError("image_unavailable", "evm-analyze is not pinned in images.lock.json")
    if not shutil.which("docker"):
        raise RunError("sandbox_unavailable", "docker is not installed on this worker")
    job_id, run_id = run["job_id"], run["run_id"]
    work = pin_root.parent / "work" / job_id / "fork" / run_id
    project = work / "project"
    pin = PinnedSource.load(pin_root, job_id)
    pin_paths = set(pin.entries)
    cands = _load_json(pin_root.parent / "work" / job_id / "candidates.json", [])
    build = _load_json(pin_root.parent / "work" / job_id / "build_result.json", None)
    solc_version = choose_solc(job_compiler(cands if isinstance(cands, list) else [], build))
    loop = asyncio.get_running_loop()
    cache = SolcCache()
    try:
        solc_bin = await loop.run_in_executor(None, cache.binary, solc_version)
    except Exception as exc:  # noqa: BLE001  # CompilerCacheError or a download fault: no compiler, no run
        raise RunError("compiler_unavailable", f"solc {solc_version}: {type(exc).__name__}") from None
    n_pinned = write_project(project, run["test_path"], run["test_source"],
                             pin, pinned_remappings(cands if isinstance(cands, list) else [], pin_paths))
    await loop.run_in_executor(None, ensure_network, CHAINSIM_NETWORK)

    sock_dir = sock_root(pin_root) / secrets.token_hex(4)
    sock_dir.mkdir(parents=True, exist_ok=False)
    sock_dir.chmod(0o755)
    token = secrets.token_hex(16)
    meter = Meter(max_calls=int(lim.get("rpc_calls", 3000)), max_bytes=int(lim.get("rpc_bytes", 100 * 1024 * 1024)))
    stats = ForkStats()
    app = fork_app(int(run["chain_id"]), int(run["block"]), token, meter, stats,
                   proxy_factory=(lambda: proxy_factory(meter)) if proxy_factory else None)
    relay = f"soken-forkrelay-{secrets.token_hex(6)}"
    forge = f"soken-fork-{secrets.token_hex(6)}"
    limits = StepLimits(cpus=float(lim.get("cpus", 1.5)), memory=str(lim.get("memory", "1536m")),
                        pids=int(lim.get("pids", 256)), max_file=int(lim.get("max_file_bytes", 128 * 1024 * 1024)))
    wall = float(lim.get("wall_s", 180))
    t0 = time.monotonic()
    out_path, err_path = work / "forge.stdout", work / "forge.stderr"
    try:
        async with serve(app, sock_dir / "rpc.sock"):
            res = await loop.run_in_executor(None, lambda: _docker(*relay_argv(relay, image, sock_dir, CHAINSIM_NETWORK)[1:]))
            if res.returncode != 0:
                raise RunError("sandbox_unavailable", f"relay: {res.stderr.strip()[:160]}")
            ip = None
            for _ in range(40):
                ip = await loop.run_in_executor(None, container_ip, relay, CHAINSIM_NETWORK)
                if ip:
                    break
                await asyncio.sleep(0.25)
            if ip is None:
                raise RunError("sandbox_unavailable", "relay has no address on the chainsim network")
            await asyncio.sleep(0.5)   # the relay binds in well under a second; forge retries the fork anyway
            url = f"http://{ip}:{RELAY_PORT}/{token}"
            command = ["forge", "test", "--json", "-vvvv", "--fork-url", url, "--fork-block-number", str(int(run["block"])),
                       "--fork-retries", "2", "--fork-retry-backoff", "1000", "--no-storage-caching",
                       "--use", f"/cache/{solc_bin.parent.name}/{solc_bin.name}", "--no-auto-detect",
                       "--offline", "--match-path", run["test_path"]]
            command = ["python3", "-I", COLLECT_PATH, "--out", "/tmp/forge-out",
                       "--cited", json.dumps(sorted(run.get("cited") or [])[:20]), "--", *command]
            argv = docker_argv(step="fork", image=image, work_dir=project, cache_dir=cache._root, limits=limits,
                               env={"HOME": "/tmp", "NO_COLOR": "1"}, command=command,
                               family_network=CHAINSIM_NETWORK, runtime=runtime or os.environ.get("SOKEN_SANDBOX_RUNTIME"),
                               workdir=PROJECT_DIR, name=forge,
                               mounts=[(project.resolve(), PROJECT_DIR, True), (COLLECT_SCRIPT, COLLECT_PATH, True)])

            def kill() -> None:
                _docker("rm", "-f", forge, timeout=30)

            code, killed_by = await loop.run_in_executor(
                None, run_capped, argv, wall, int(lim.get("stdout_bytes", 1024 * 1024)), kill, out_path, err_path)
    finally:
        await loop.run_in_executor(None, lambda: _docker("rm", "-f", relay, timeout=30))
        shutil.rmtree(sock_dir, ignore_errors=True)
    wall_s = round(time.monotonic() - t0, 1)
    cap = int(lim.get("stdout_bytes", 1024 * 1024))
    stdout = _read_capped(out_path, cap)
    stderr = _read_capped(err_path, cap).decode("utf-8", "replace")
    stdout, artifacts, collector_cap = unwrap(stdout)
    shutil.rmtree(work, ignore_errors=True)
    base: dict[str, Any] = {"wall_s": wall_s, "rpc": stats.as_dict(meter), "exit_code": code,
                            "engine": {"tool": "forge", "version": locked_tools("evm-analyze").get("forge"),
                                       "forge_std": locked_tools("evm-analyze").get("forge-std"),
                                       "image": image.rsplit("@", 1)[-1][:80], "solc": solc_version},
                            "pinned_files": n_pinned}
    if killed_by == "wall":
        return {**base, "status": "timeout", "reason": f"wall clock {int(wall)} s"}
    if killed_by == "output" or collector_cap:
        return {**base, "status": "error", "reason": "output_cap"}
    try:
        tests = parse_forge_json(stdout)
    except RunError as exc:
        reason = exc.reason
        if reason == "no_result" and _compile_failed(stderr):
            reason = "compile"
        elif reason == "no_result" and _fork_error(stderr):
            reason = "chain_unavailable"
        return {**base, "status": "error", "reason": reason, "diagnostics": compile_error(stderr)}
    called, created = trace_calls(forge_doc(stdout))
    calls = {"addresses": sorted(called)[:200], "pinned": called_pinned(called, created, artifacts)}
    return {**base, "status": run_status(tests), "tests": tests, "calls": calls}


def _fork_error(stderr: str) -> bool:
    low = stderr.lower()
    return "fork" in low or "rpc" in low or "backend" in low


def _compile_failed(stderr: str) -> bool:
    low = stderr.lower()
    return "compil" in low or "parsererror" in low or "typeerror" in low or "declarationerror" in low


def _load_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


# ── worker step ────────────────────────────────────────────────────────────


REAP_MARGIN_S = 120


async def reap_dead_runs(conn: Any, job_id: str | None = None) -> list[str]:
    """Mark as `error` (reason step_lost) every queued or running run whose step is no longer live: no
    step, a step that ended or was cancelled, a running step whose lease expired, or a run running for
    longer than the wall cap plus a margin. A dead run never blocks finalize."""
    wall = int(fork_limits().get("wall_s", 180)) + REAP_MARGIN_S
    async with conn.cursor() as cur:
        await cur.execute(
            """update fork_runs fr set status = 'error', finished_at = now(),
                   result = coalesce(fr.result, '{}'::jsonb) || '{"status": "error", "reason": "step_lost"}'::jsonb
               where fr.status in ('queued', 'running') and (%(job)s::text is null or fr.job_id = %(job)s)
                 and (fr.step_id is null
                      or not exists (select 1 from job_steps s where s.id = fr.step_id
                                     and (s.status = 'queued'
                                          or (s.status = 'running' and (s.lease_until is null or s.lease_until > now()))))
                      or (fr.status = 'running' and fr.started_at < now() - make_interval(secs => %(wall)s)))
               returning fr.run_id""",
            {"job": job_id, "wall": wall})
        return [r[0] for r in await cur.fetchall()]


async def fail_runs_of_step(pool: Any, step_id: int, reason: str = "step_failed") -> None:
    """The supervisor's failure path of a verify_fork step: its bound run ends `error`."""
    async with pool.connection() as conn:
        await conn.execute(
            """update fork_runs set status = 'error', finished_at = now(),
                   result = coalesce(result, '{}'::jsonb) || jsonb_build_object('status', 'error', 'reason', %s::text)
               where step_id = %s and status in ('queued', 'running')""", (reason, step_id))


async def run_step(pool: Any, pin_root: Path, step: dict[str, Any]) -> None:
    """The `verify_fork` step: run the job's run row bound to this step, store its result. Never
    raises for a run failure; the step ends `done` with the run's status in its provenance."""
    from ..db.job_repo import JobRepo

    async with pool.connection() as conn, conn.cursor() as cur:
        await cur.execute(
            """update fork_runs set status = 'running', started_at = now()
                   where step_id = %s and status = 'queued'
                   returning run_id, job_id, chain_id, network, block, test_path, test_source, expect,
                             draft_key, draft_revision""",
            (step["id"],))
        row = await cur.fetchone()
    if row is None:
        async with pool.connection() as conn:
            await JobRepo(conn).complete_step(step["id"], "done", provenance={"fork_run": None})
        return
    keys = ("run_id", "job_id", "chain_id", "network", "block", "test_path", "test_source", "expect",
            "draft_key", "draft_revision")
    run = dict(zip(keys, row, strict=True))
    run["cited"] = []
    if run["draft_key"]:   # the collector keeps only the artifacts of the files this finding quotes
        async with pool.connection() as conn, conn.cursor() as cur:
            await cur.execute("""select distinct path from finding_quote_ranges
                                 where job_id = %s and draft_key = %s and revision = %s""",
                              (run["job_id"], run["draft_key"], run["draft_revision"]))
            run["cited"] = [r[0] for r in await cur.fetchall()]
    try:
        result = await execute(run, pin_root)
    except RunError as exc:
        result = {"status": "error", "reason": exc.reason, "detail": exc.detail}
    except Exception as exc:  # a supervisor fault is a run error, never a job failure
        logger.exception("fork run %s failed", run["run_id"])
        result = {"status": "error", "reason": "internal", "detail": type(exc).__name__}
    status = result.get("status") if result.get("status") in ("passed", "failed", "error", "timeout") else "error"
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "update fork_runs set status = %s, result = %s, finished_at = now() where run_id = %s",
                (status, json.dumps(result), run["run_id"]))
        await JobRepo(conn).complete_step(step["id"], "done", provenance={
            "fork_run": run["run_id"], "status": status, "reason": result.get("reason"),
            "wall_s": result.get("wall_s"), "rpc_calls": (result.get("rpc") or {}).get("upstream_calls")})
    logger.info("job %s: fork run %s %s (%s)", run["job_id"][-8:], run["run_id"], status, result.get("reason") or "")
