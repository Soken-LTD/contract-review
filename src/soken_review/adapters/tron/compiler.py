"""tron-solc release cache (05 section 6.3).

Security model (coordinator review 2026-10-09):
  - Strict tag regex ^tv_[0-9]+\\.[0-9]+\\.[0-9]+(_[A-Za-z0-9._]+)?$ — applied in
    _resolve_tag() AND binary() — malicious version strings return compiler_binary_missing.
  - Pinned sha256 per tag from data/tron_solc_releases.json (repo file, measured once from
    the official GitHub release, recorded with source URL and date).  A null or missing
    sha256 in the table -> compiler_binary_missing (fail closed; never download without a
    known-good hash).
  - tag_dir confined with resolve()+is_relative_to(self._root) to prevent path traversal.
  - sha256 is NOT fetched from the same server as the binary: we only fetch the binary and
    verify against the repo-pinned value.

Release tag format: tv_<version>  e.g. tv_0.8.31
Assets:
  tv_0.8.31 and later:     solc-static-linux  (+ arm variant)
  tv_0.8.18 to tv_0.8.30: solc-static-linux
  tv_0.8.11 and older (back to tv_0.5.4, 0.4.25 Odyssey): *linux*.zip (UV5-31)

Cache layout:
  <root>/
    tron/
      <tag>/
        solc-static-linux    (executable, sha256-verified against pinned table)
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
import os
import re
import stat
import tempfile
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Strict tag regex (security gate; path traversal prevention)
_TAG_RE = re.compile(r"^tv_[0-9]+\.[0-9]+\.[0-9]+(_[A-Za-z0-9._]+)?$")

_GITHUB_DOWNLOAD_BASE = "https://github.com/tronprotocol/solidity/releases/download/{tag}/{asset}"
_DATA_FILE = Path(__file__).parent / "data" / "tron_solc_releases.json"

_TIMEOUT = 120


class TronCompilerCacheError(Exception):
    """Raised when a tron-solc binary cannot be provisioned (6.3)."""

    def __init__(self, reason_detail: str) -> None:
        super().__init__(reason_detail)
        self.reason_detail = reason_detail


def _load_releases() -> dict[str, Any]:
    """Load the pinned release table from the repo data file."""
    if not _DATA_FILE.exists():
        return {}
    with _DATA_FILE.open() as fh:
        data = json.load(fh)
    return data.get("releases", {})


class TronSolcCache:
    """Manages a local directory of tron-solc binaries keyed by exact tag.

    Only downloads a binary when its sha256 is recorded in the repo-pinned table
    (data/tron_solc_releases.json).  Unknown or null-sha256 tags fail closed.

    Cache layout::

        <root>/
          tron/
            tv_0.8.31/
              solc-static-linux   (executable, sha256-verified against pinned table)
    """

    def __init__(self, cache_dir: Path | None = None) -> None:
        if cache_dir is None:
            env = os.environ.get("SOKEN_SOLC_CACHE_DIR")
            cache_dir = Path(env) if env else Path.home() / ".cache" / "soken-solc"
        self._root = (cache_dir / "tron").resolve()

    def binary(self, tag: str) -> Path:
        """Return path to the tron-solc binary for *tag*, downloading if absent.

        Strict validation:
          1. tag must match ^tv_[0-9]+\\.[0-9]+\\.[0-9]+(_[A-Za-z0-9._]+)?$
          2. tag must be in the repo-pinned table with a non-null sha256
          3. tag_dir confined with resolve()+is_relative_to(self._root)

        Raises TronCompilerCacheError(reason_detail) when unavailable.
        """
        # Gate 1: strict tag format (path traversal prevention)
        if not _TAG_RE.match(tag):
            logger.warning("tron_solc: rejected malformed tag %r", tag)
            raise TronCompilerCacheError("compiler_binary_missing")

        # Gate 2: tag in pinned table with known sha256
        releases = _load_releases()
        entry = releases.get(tag)
        if entry is None:
            # Semver-only fallback: "tv_0.5.10_Odyssey_v3.6.6" -> "tv_0.5.10"
            # Security: the fallback tag must also pass _TAG_RE (guaranteed by the regex match).
            m = re.match(r"^(tv_[0-9]+\.[0-9]+\.[0-9]+)_", tag)
            if m:
                semver_tag = m.group(1)
                if _TAG_RE.match(semver_tag):
                    entry = releases.get(semver_tag)
                    if entry is not None:
                        tag = semver_tag  # redirect cache path to canonical semver key
        if entry is None:
            raise TronCompilerCacheError("tron_compiler_unmapped")
        pinned_sha256: str | None = entry.get("sha256")
        if not pinned_sha256:
            # Not yet measured; fail closed (UV5-31 pending)
            raise TronCompilerCacheError("compiler_binary_missing")

        # Gate 3: path confinement
        tag_dir = (self._root / tag).resolve()
        if not tag_dir.is_relative_to(self._root):
            raise TronCompilerCacheError("compiler_binary_missing")

        asset_name = entry.get("asset", "solc-static-linux")
        binary_path = tag_dir / "solc-static-linux"

        # Cache hit: verify the stored binary's sha256.
        # For zip-based assets the pinned sha256 covers the zip download (supply-chain gate),
        # not the extracted binary.  Use binary_sha256 when present (always set for zip
        # entries); fall back to sha256 for non-zip assets where they are equal.
        binary_sha256: str | None = entry.get("binary_sha256") or pinned_sha256
        if binary_path.exists():
            actual = "0x" + hashlib.sha256(binary_path.read_bytes()).hexdigest()
            if actual == binary_sha256:
                return binary_path
            logger.warning("tron-solc %s sha256 mismatch; re-downloading", tag)
            binary_path.unlink()

        github_tag: str | None = entry.get("github_tag") or None
        self._download(tag, tag_dir, binary_path, asset_name, pinned_sha256, binary_sha256, github_tag=github_tag)
        return binary_path

    def path_in_cache(self, tag: str) -> Path:
        """Return path even if binary does not yet exist."""
        if not _TAG_RE.match(tag):
            raise TronCompilerCacheError("compiler_binary_missing")
        tag_dir = (self._root / tag).resolve()
        if not tag_dir.is_relative_to(self._root):
            raise TronCompilerCacheError("compiler_binary_missing")
        return tag_dir / "solc-static-linux"

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _download(
        self,
        tag: str,
        tag_dir: Path,
        binary_path: Path,
        asset_name: str,
        pinned_sha256: str,
        binary_sha256: str | None = None,
        github_tag: str | None = None,
    ) -> None:
        tag_dir.mkdir(parents=True, exist_ok=True)
        # github_tag may differ from the internal key (0.4.25 Odyssey has no tv_ prefix on GitHub).
        dl_tag = github_tag or tag
        download_url = _GITHUB_DOWNLOAD_BASE.format(tag=dl_tag, asset=asset_name)
        try:
            raw = _http_get(download_url)
        except Exception as exc:
            raise TronCompilerCacheError("compiler_binary_missing") from exc

        # Verify the raw download against repo-pinned sha256 (supply-chain gate).
        # For zip assets this pins the zip; for static binaries this pins the binary itself.
        actual_sha256 = "0x" + hashlib.sha256(raw).hexdigest()
        if actual_sha256 != pinned_sha256:
            raise TronCompilerCacheError("compiler_binary_missing")

        # Extract zip or write binary directly
        is_zip = asset_name.endswith(".zip") or "zip" in asset_name.lower()
        if is_zip:
            binary_data = _extract_linux_binary(raw, asset_name)
            # For zip assets, additionally verify the extracted binary sha256 (binary_sha256).
            if binary_sha256:
                actual_bin = "0x" + hashlib.sha256(binary_data).hexdigest()
                if actual_bin != binary_sha256:
                    raise TronCompilerCacheError("compiler_binary_missing")
        else:
            binary_data = raw

        # Atomic write
        with tempfile.NamedTemporaryFile(dir=tag_dir, delete=False, suffix=".tmp") as tmp:
            tmp.write(binary_data)
            tmp_path = Path(tmp.name)
        tmp_path.chmod(tmp_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        tmp_path.rename(binary_path)


def _extract_linux_binary(zip_data: bytes, asset_name: str) -> bytes:
    """Extract the solc binary from a zip archive (older tron-solc releases, UV5-31)."""
    with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
        candidates = [
            n for n in zf.namelist()
            if ("solc" in n.lower() or "linux" in n.lower())
            and not n.endswith("/")
            and not n.endswith(".zip")
        ]
        if not candidates:
            raise TronCompilerCacheError("compiler_binary_missing")
        name = next(
            (n for n in candidates if n.split("/")[-1] in ("solc", "solc-static-linux")),
            candidates[0],
        )
        return zf.read(name)


def _http_get(url: str) -> bytes:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "soken-review/0.1",
            "Accept": "application/octet-stream,*/*",
        },
    )
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
        return resp.read()


# Module-level singleton
_default_cache: TronSolcCache | None = None


def get_tron_cache(cache_dir: Path | None = None) -> TronSolcCache:
    """Return the module-level TronSolcCache, creating it on first call."""
    global _default_cache
    if cache_dir is not None:
        return TronSolcCache(cache_dir)
    if _default_cache is None:
        _default_cache = TronSolcCache()
    return _default_cache
