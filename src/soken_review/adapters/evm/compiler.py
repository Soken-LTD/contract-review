"""solc release cache with sha256 verification (05 6.1, 09 4.4).

Downloads exact solc releases from binaries.soliditylang.org, verifying
sha256 from list.json.  Only the exact recorded release is used; if the
binary is unavailable the build returns status='failed', reason=
'not_checkable', reason_detail='compiler_binary_missing'.

Production path: supervisor mounts the cache read-only at /cache/solc.
Local dev on macOS arm64: set SOKEN_SOLC_PLATFORM=macosx-amd64 or use
a linux/arm64 container where platform defaults to linux-amd64.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import urllib.request
from pathlib import Path

_BASE_URL = "https://binaries.soliditylang.org"
_PLATFORMS = ("linux-amd64", "macosx-amd64")
_DEFAULT_PLATFORM = "linux-amd64"

# env override lets CI / local dev switch to macosx-amd64
PLATFORM = os.environ.get("SOKEN_SOLC_PLATFORM", _DEFAULT_PLATFORM)
if PLATFORM not in _PLATFORMS:
    raise ValueError(f"SOKEN_SOLC_PLATFORM must be one of {_PLATFORMS}, got {PLATFORM!r}")


class CompilerCacheError(Exception):
    """Raised when a compiler binary cannot be provisioned."""

    def __init__(self, reason_detail: str) -> None:
        super().__init__(reason_detail)
        self.reason_detail = reason_detail


class SolcCache:
    """Manages a local directory of solc binaries keyed by exact version string.

    Cache layout::

        <root>/
          <platform>/
            list.json          # fetched from binaries.soliditylang.org
            solc-<version>     # executable, verified against list.json sha256

    The supervisor mounts this directory as /cache/solc (read-only inside
    the sandbox).  Local callers set SOKEN_SOLC_CACHE_DIR or pass cache_dir.
    """

    def __init__(self, cache_dir: Path | None = None, platform: str = PLATFORM) -> None:
        if cache_dir is None:
            env = os.environ.get("SOKEN_SOLC_CACHE_DIR")
            cache_dir = Path(env) if env else Path.home() / ".cache" / "soken-solc"
        self._root = cache_dir
        self._platform = platform
        self._platform_dir = self._root / platform
        self._list: dict | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def binary(self, version: str) -> Path:
        """Return path to the solc binary for *version*, downloading if absent.

        Raises CompilerCacheError(reason_detail) when unavailable.
        """
        target = self._platform_dir / f"solc-{version}"
        if target.exists():
            return target
        # Exact recorded release only (05 6.1): match the long version ("0.8.37+commit.f401782d")
        # or a bare short version against list.json builds; refresh the list once on a miss.
        build = self._find_build(self._load_list(), version)
        if build is None:
            self._fetch_list()
            build = self._find_build(self._load_list(), version)
        if build is None or not build.get("sha256"):
            raise CompilerCacheError("compiler_binary_missing")
        entry, sha256 = build["path"], build["sha256"]
        url = f"{_BASE_URL}/{self._platform}/{entry}"
        self._download_and_verify(url, target, sha256, version)
        return target

    def path_in_cache(self, version: str) -> Path:
        """Return path even if the binary does not yet exist (for pre-check)."""
        return self._platform_dir / f"solc-{version}"

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _list_path(self) -> Path:
        return self._platform_dir / "list.json"

    def _load_list(self) -> dict:
        if self._list is not None:
            return self._list
        path = self._list_path()
        if not path.exists():
            self._fetch_list()
        with path.open() as fh:
            self._list = json.load(fh)
        return self._list

    def _fetch_list(self) -> None:
        self._platform_dir.mkdir(parents=True, exist_ok=True)
        url = f"{_BASE_URL}/{self._platform}/list.json"
        data = _http_get(url)
        tmp = self._list_path().with_suffix(".tmp")
        tmp.write_bytes(data)
        tmp.rename(self._list_path())
        self._list = None  # invalidate cache

    @staticmethod
    def _find_build(lst: dict, version: str) -> dict | None:
        for build in lst.get("builds", []):
            if version in (build.get("longVersion"), build.get("version")):
                return build
        return None

    def _sha256_for(self, lst: dict, filename: str) -> str | None:
        for build in lst.get("builds", []):
            if build.get("path") == filename:
                return build.get("sha256")
        return None

    def _download_and_verify(self, url: str, dest: Path, expected_sha256: str, version: str) -> None:
        dest.parent.mkdir(parents=True, exist_ok=True)
        data = _http_get(url)
        actual = "0x" + hashlib.sha256(data).hexdigest()
        if actual != expected_sha256:
            raise CompilerCacheError(
                "compiler_binary_missing"  # integrity failure → treat as missing
            )
        with tempfile.NamedTemporaryFile(dir=dest.parent, delete=False) as tmp:
            tmp.write(data)
            tmp_path = Path(tmp.name)
        # 0755, not 0711: NamedTemporaryFile is 0600, and gVisor (runsc) reads the ELF as the
        # sandbox user (uid 10001) to load it, so execute without read fails there (runc does not care).
        tmp_path.chmod(stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
        tmp_path.rename(dest)


def _http_get(url: str, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "soken-review/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


# Module-level default instance; override cache_dir via SOKEN_SOLC_CACHE_DIR
_default_cache: SolcCache | None = None


def get_cache(cache_dir: Path | None = None) -> SolcCache:
    """Return the module-level SolcCache, creating it on first call."""
    global _default_cache
    if cache_dir is not None:
        return SolcCache(cache_dir)
    if _default_cache is None:
        _default_cache = SolcCache()
    return _default_cache
