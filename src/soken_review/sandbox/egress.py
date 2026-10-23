"""Family egress proxies of 09 section 4.3 (P0-DEPS, UV9-3).

Only repo `fetch`, `deps` and the document `context` containers have a network:
`soken-egress-<family>`, created `--internal` (no route out). The one way out is a smokescreen on
that network under the alias `smokescreen`, also attached to `soken-egress-<family>-out`. Its ACL
holds only a `default:` rule (certificate-less clients, `allow_missing_role: true`, S9) with the
hosts of `contract/ops/limits.yaml` `egress.all` + `egress.<family>`; the `docs` family
(`{allow_public: true}`, context ingestion spec 3) renders `action: open` instead of a host list.
Smokescreen refuses private, loopback and link-local addresses (169.254.169.254 included) on its
own, for every family.

    python -m soken_review.sandbox.egress up <family> [--image REF]   # network + proxy
    python -m soken_review.sandbox.egress down <family>
    python -m soken_review.sandbox.egress render <family> <dir>       # config.yaml + acl.yaml
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

import yaml

FAMILIES = ("evm", "solana", "move", "starknet", "ton", "docs")
PROXY_ALIAS = "smokescreen"
PROXY_PORT = 4750
PROXY_UID = "65532:65532"
LIMITS = Path(__file__).resolve().parents[3] / "contract" / "ops" / "limits.yaml"
_HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def network_name(family: str) -> str:
    _check_family(family)
    return f"soken-egress-{family}"


def proxy_url(network: str | None = None) -> str:
    """Proxy URL for a step on `network`. By IP when the proxy container is found: gVisor's
    netstack does not reach Docker's embedded DNS (127.0.0.11), so a name may not resolve."""
    if network and network.startswith("soken-egress-"):
        family = network.removeprefix("soken-egress-")
        proc = subprocess.run(
            ["docker", "inspect", "--format",
             "{{(index .NetworkSettings.Networks \"" + network + "\").IPAddress}}",
             f"soken-smokescreen-{family}"],
            capture_output=True, text=True, check=False)
        ip = proc.stdout.strip()
        if proc.returncode == 0 and re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip):
            return f"http://{ip}:{PROXY_PORT}"
    return f"http://{PROXY_ALIAS}:{PROXY_PORT}"


def proxy_env(network: str | None = None) -> dict[str, str]:
    """Environment of a network step: every tool (git, cargo, npm, curl) goes through the proxy."""
    url = proxy_url(network)
    return {"HTTPS_PROXY": url, "HTTP_PROXY": url, "https_proxy": url, "http_proxy": url,
            "NO_PROXY": "", "no_proxy": ""}


def _check_family(family: str) -> None:
    if family not in FAMILIES:
        raise ValueError(f"unknown egress family {family!r}")


def allow_public(family: str, limits_path: Path = LIMITS) -> bool:
    """True for a family whose `egress.<family>` row is `{allow_public: true}` (the `docs` family of
    the context ingestion spec): its proxy reaches any public host and keeps no host list.
    Smokescreen's own deny list (private, loopback, link-local and metadata ranges) still applies."""
    _check_family(family)
    row = yaml.safe_load(limits_path.read_text())["egress"].get(family)
    if isinstance(row, dict):
        if set(row) != {"allow_public"} or row["allow_public"] is not True:
            raise ValueError(f"egress family {family!r}: a mapping row must be exactly {{allow_public: true}}")
        return True
    return False


def allowlist(family: str, limits_path: Path = LIMITS) -> list[str]:
    """Hosts of `egress.all` plus `egress.<family>`; refuses wildcards, IPs and odd names.
    An `allow_public` family has no host list: [] (the ACL is `open`, not `enforce`)."""
    _check_family(family)
    if allow_public(family, limits_path):
        return []
    egress = yaml.safe_load(limits_path.read_text())["egress"]
    hosts = [*(egress.get("all") or []), *(egress.get(family) or [])]
    for host in hosts:
        if not isinstance(host, str) or not _HOST_RE.match(host):
            raise ValueError(f"egress host {host!r} is not a plain host name")
    return sorted(set(hosts))


def render_acl(family: str, limits_path: Path = LIMITS) -> str:
    if allow_public(family, limits_path):
        # smokescreen `open`: every public destination; its built-in private-range denial stays.
        default = {"project": f"soken-{family}", "action": "open"}
    else:
        default = {"project": f"soken-{family}", "action": "enforce",
                   "allowed_domains": allowlist(family, limits_path)}
    acl = {"version": "v1", "services": [], "default": default}
    return yaml.safe_dump(acl, sort_keys=False)


def render_config() -> str:
    config = {
        "ip": "0.0.0.0",
        "port": PROXY_PORT,
        "allow_missing_role": True,
        "acl_file": "/etc/smokescreen/acl.yaml",
        "deny_addresses": ["169.254.169.254"],
        "connect_timeout": "10s",
    }
    return yaml.safe_dump(config, sort_keys=False)


def render(family: str, out_dir: Path, limits_path: Path = LIMITS) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "acl.yaml").write_text(render_acl(family, limits_path))
    (out_dir / "config.yaml").write_text(render_config())
    for f in out_dir.iterdir():
        f.chmod(0o644)
    out_dir.chmod(0o755)
    return out_dir


def _docker(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=check)


def up(family: str, image: str, config_root: Path) -> str:
    """Create the internal family network and start its smokescreen. Returns the container name."""
    net = network_name(family)
    out = f"{net}-out"
    name = f"soken-smokescreen-{family}"
    cfg = render(family, config_root / family)
    for network, internal in ((net, True), (out, False)):
        if _docker("network", "inspect", network, check=False).returncode != 0:
            _docker("network", "create", *(["--internal"] if internal else []), network)
    _docker("rm", "-f", name, check=False)
    _docker(
        "run", "-d", "--name", name, "--restart", "unless-stopped", "--network", out,
        "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--user", PROXY_UID,
        "--pids-limit=256", "--memory=256m",
        "--log-driver", "json-file", "--log-opt", "max-size=10m", "--log-opt", "max-file=2",  # 09 8
        "--mount", f"type=bind,src={cfg.resolve()},dst=/etc/smokescreen,readonly",
        image, "--config-file", "/etc/smokescreen/config.yaml",
    )
    _docker("network", "connect", "--alias", PROXY_ALIAS, net, name)
    return name


def down(family: str) -> None:
    net = network_name(family)
    _docker("rm", "-f", f"soken-smokescreen-{family}", check=False)
    for network in (net, f"{net}-out"):
        _docker("network", "rm", network, check=False)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="soken-egress")
    sub = p.add_subparsers(dest="cmd", required=True)
    u = sub.add_parser("up")
    u.add_argument("family")
    u.add_argument("--image", default=None)
    u.add_argument("--config-root", default=str(Path(__file__).resolve().parents[3] / ".sbx" / "egress"))
    d = sub.add_parser("down")
    d.add_argument("family")
    r = sub.add_parser("render")
    r.add_argument("family")
    r.add_argument("out_dir")
    args = p.parse_args(argv)
    if args.cmd == "render":
        render(args.family, Path(args.out_dir))
        return 0
    if args.cmd == "down":
        down(args.family)
        return 0
    from soken_review.sandbox.profile import locked_image

    image = args.image or locked_image("smokescreen")
    if not image:
        print("smokescreen image not pinned (images.lock.json) and no --image", file=sys.stderr)
        return 1
    print(up(args.family, image, Path(args.config_root)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
