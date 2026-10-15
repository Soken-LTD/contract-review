"""P0-UID (09 section 16, UV9-4): uid 10001, no network, read-only root and src, no caps."""

import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from soken_review.sandbox.profile import StepLimits, docker_argv

IMAGE = "alpine:3.20"
LIMITS = StepLimits(cpus=1, memory="256m", pids=64, max_file=8 * 1024 * 1024)

PROBE = r"""
id -u; id -g
grep CapEff /proc/self/status | awk '{print $2}'
grep NoNewPrivs /proc/self/status | awk '{print $2}'
awk 'NR>2{sub(":","",$1); print $1}' /proc/net/dev | tr '\n' ' '; echo
touch /rootfile 2>/dev/null && echo root_rw || echo root_ro
touch /work/src/x 2>/dev/null && echo src_rw || echo src_ro
touch /work/out/x 2>/dev/null && echo out_rw || echo out_ro
cp /bin/busybox /tmp/bb && (/tmp/bb true 2>/dev/null && echo tmp_exec || echo tmp_noexec)
dd if=/dev/zero of=/work/out/big bs=1M count=16 2>/dev/null && echo fsize_unlimited || echo fsize_capped
"""


def docker_ok() -> bool:
    if not shutil.which("docker"):
        return False
    return subprocess.run(["docker", "info"], capture_output=True, check=False).returncode == 0


def test_argv_offline_step_has_no_network():
    argv = docker_argv("build", "img@sha256:x", "/w", None, LIMITS, {}, ["true"])
    assert "--network=none" in argv and "--runtime=runsc-none" in argv
    assert "--read-only" in argv and "--cap-drop=ALL" in argv


def test_argv_network_step_needs_family_network():
    with pytest.raises(ValueError):
        docker_argv("fetch", "img", "/w", None, LIMITS, {}, ["true"])
    argv = docker_argv("deps", "img@sha256:x", "/w", None, LIMITS, {}, ["true"], family_network="egress-evm")
    assert "--network=egress-evm" in argv and "--runtime=runsc-egress" in argv


def test_argv_runsc_refuses_floating_tag():
    # 09 4.4: production runtime runs images by digest only.
    with pytest.raises(ValueError, match="digest"):
        docker_argv("build", "ghcr.io/soken-ltd/evm-analyze:0.1.0-dev", "/w", None, LIMITS, {}, ["true"])
    argv = docker_argv("build", "img:tag", "/w", None, LIMITS, {}, ["true"], runtime="runc")
    assert "img:tag" in argv          # dev runtime only


def test_argv_network_step_gets_proxy_env_and_netstack():
    argv = docker_argv("fetch", "img@sha256:x", "/w", None, LIMITS, {"HOME": "/tmp"}, ["true"],
                       family_network="egress-evm", runtime="runsc-none")
    assert "--runtime=runsc-egress" in argv
    assert "HTTPS_PROXY=http://smokescreen:4750" in argv and "HOME=/tmp" in argv
    offline = docker_argv("build", "img@sha256:x", "/w", None, LIMITS, {}, ["true"])
    assert not any(a.startswith("HTTPS_PROXY") for a in offline)


@pytest.mark.skipif(not docker_ok(), reason="docker not available")
def test_p0_uid():
    # Colima and Docker Desktop share only the home directory with the VM, not /tmp.
    root = Path(__file__).resolve().parents[1] / ".sbx"
    root.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=root) as tmp:
        run_probe(Path(tmp) / "work")


def run_probe(work):
    (work / "src").mkdir(parents=True)
    (work / "out").mkdir()
    (work / "out").chmod(0o777)
    (work / "src").chmod(0o555)
    import os

    # SOKEN_P0_UID_RUNTIME=runsc-none and an alpine image by digest prove the profile under gVisor (x86 CI).
    image = os.environ.get("SOKEN_P0_UID_IMAGE", IMAGE)
    runtime = os.environ.get("SOKEN_P0_UID_RUNTIME", "runc")
    if subprocess.run(["docker", "image", "inspect", image], capture_output=True, check=False).returncode != 0:
        subprocess.run(["docker", "pull", "-q", image], check=True, capture_output=True)
    argv = docker_argv("build", image, work, None, LIMITS, {}, ["sh", "-c", PROBE], runtime=runtime)
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=120, check=False)
    out = proc.stdout.split("\n")
    assert len(out) >= 10, proc.stderr
    uid, gid, capeff, nnp, nets, root, src, outw, tmp, fsize = out[:10]
    assert (uid, gid) == ("10001", "10001")
    assert int(capeff, 16) == 0
    assert nnp == "1"
    assert nets.split() == ["lo"]
    assert root == "root_ro" and src == "src_ro" and outw == "out_rw"
    assert tmp == "tmp_noexec"
    assert fsize == "fsize_capped"


def test_writable_dir_refuses_world_writable_without_flag(tmp_path, monkeypatch):
    """No 0o777 dir appears on a host unless the dev flag is set explicitly."""
    import os

    from soken_review.sandbox.profile import sandbox_writable_dir

    if os.geteuid() == 0:
        pytest.skip("root can chown")
    monkeypatch.delenv("SOKEN_SANDBOX_DEV_PERMS", raising=False)
    with pytest.raises(PermissionError):
        sandbox_writable_dir(tmp_path / "w")
