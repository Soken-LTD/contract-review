"""Vyper release cache with sha256 verification (05 6.1, 15; 09 4.4).

Same rules as the solc cache: only the exact recorded release (patch and commit), fetched by
the supervisor into the read-only compiler cache, sha256-checked against data/vyper_releases.json.
Pre-releases are refused; a release without a pinned sha256 is never run. Either way the build is
`not_checkable` with `compiler_binary_missing`, never `mismatch`.

Cache layout: <SOKEN_SOLC_CACHE_DIR>/vyper-linux-amd64/vyper-<long_version>, mounted at /cache.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
import urllib.request
from pathlib import Path

from soken_review.adapters.evm.compiler import CompilerCacheError

_RELEASES_FILE = Path(__file__).parent / "data" / "vyper_releases.json"
PLATFORM_DIR = "vyper-linux-amd64"
_PRERELEASE = re.compile(r"[A-Za-z]")  # any letter in the short version: b1, rc2, beta.17


def short_version(version: str) -> str:
    return version.split("+", 1)[0].removeprefix("v")


def is_prerelease(version: str) -> bool:
    return bool(_PRERELEASE.search(short_version(version)))


def _releases() -> list[dict]:
    return json.loads(_RELEASES_FILE.read_text())["releases"]


def find_release(version: str) -> dict | None:
    """The pinned release row for an exact recorded version ("0.2.4+commit.7949850" or "0.2.4").

    A recorded commit must equal the release's commit (prefix match: Sourcify and the release
    asset abbreviate commits to different lengths)."""
    short = short_version(version)
    commit = version.split("+commit.", 1)[1] if "+commit." in version else None
    for row in _releases():
        if row["version"] != short:
            continue
        rel_commit = row["long_version"].split("+commit.", 1)[1] if "+commit." in row["long_version"] else None
        if commit and rel_commit and not (commit.startswith(rel_commit) or rel_commit.startswith(commit)):
            return None
        return row
    return None


class VyperCache:
    def __init__(self, cache_dir: Path | None = None) -> None:
        if cache_dir is None:
            env = os.environ.get("SOKEN_SOLC_CACHE_DIR")
            cache_dir = Path(env) if env else Path.home() / ".cache" / "soken-solc"
        self._root = cache_dir
        self._dir = cache_dir / PLATFORM_DIR

    @property
    def root(self) -> Path:
        return self._root

    def binary(self, version: str) -> Path:
        if is_prerelease(version):
            raise CompilerCacheError("compiler_binary_missing")  # pre-releases refused (05 15)
        row = find_release(version)
        if row is None or not row.get("sha256"):
            raise CompilerCacheError("compiler_binary_missing")
        target = self._dir / f"vyper-{row['long_version']}"
        if target.exists():
            if _sha256(target.read_bytes()) != row["sha256"]:
                raise CompilerCacheError("compiler_binary_missing")  # tampered cache entry
            return target
        data = _http_get(row["url"])
        if _sha256(data) != row["sha256"]:
            raise CompilerCacheError("compiler_binary_missing")
        self._dir.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=self._dir, delete=False) as tmp:
            tmp.write(data)
            tmp_path = Path(tmp.name)
        tmp_path.chmod(tmp_path.stat().st_mode | stat.S_IXUSR | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
        tmp_path.rename(target)
        return target


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _http_get(url: str, timeout: int = 300) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "soken-review/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()
