"""Learning loop configuration and anonymisation (learning-loop design 2026-10-27, 2.1 and 2.7).

`contract/learning/learning.yaml` holds every threshold, label and protected rule; this module
reads it and holds none of its own. Anonymisation is one keyed hash: `tag(kind, value)` is
HMAC-SHA256 under the learning salt, truncated to `salt.tag_hex` hex digits, used only to count
distinct targets and principals and to replace one job's ledger rows idempotently. Identifying
values (job id, principal key, source pin) never leave this function; every other ledger field
passes a closed-alphabet `token()` check so a free-text value can never be written by accident.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[3]
LEARNING_DIR = REPO_ROOT / "contract" / "learning"
CONFIG_FILE = LEARNING_DIR / "learning.yaml"
TIERS_DIR = LEARNING_DIR / "rule_tiers"

_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$")

# Closed alphabets for every ledger column that is not a tag (anonymisation tests rely on these).
TOKEN_PATTERNS: dict[str, re.Pattern[str]] = {
    "tool": re.compile(r"^[a-z0-9][a-z0-9_.+-]{0,39}$"),
    "tool_version": re.compile(r"^[0-9A-Za-z][0-9A-Za-z_.+-]{0,39}$"),
    "rule_id": re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:+-]{0,119}$"),
    "category": re.compile(r"^[a-z0-9][a-z0-9_.-]{0,59}$"),
    "family": re.compile(r"^[a-z0-9][a-z0-9_-]{0,19}$"),
    "code": re.compile(r"^[A-Z][A-Z0-9_]{1,59}$"),
    "field": re.compile(r"^[a-z][a-z0-9_.\[\]]{0,59}$"),
    "severity_rule": re.compile(r"^[A-Za-z0-9 =\[\],_.:+-]{1,160}$"),
    "cap": re.compile(r"^[A-Za-z0-9_.-]{1,20}$"),
    "word": re.compile(r"^[a-z][a-z_]{0,39}$"),
    "release": re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,79}$"),
    "source": re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/#-]{0,119}$"),
}


@cache
def config() -> dict[str, Any]:
    return yaml.safe_load(CONFIG_FILE.read_text(encoding="utf-8"))


def config_sha256() -> str:
    return hashlib.sha256(CONFIG_FILE.read_bytes()).hexdigest()


def valid_version(version: str | None) -> bool:
    return bool(version) and bool(_VERSION_RE.match(str(version)))


def token(kind: str, value: Any, default: str = "other") -> str:
    """`value` when it matches the closed alphabet for `kind`, else `default`. Never raises."""
    text = "" if value is None else str(value)
    return text if TOKEN_PATTERNS[kind].match(text) else default


def token_or_none(kind: str, value: Any) -> str | None:
    if value is None or value == "":
        return None
    text = str(value)
    return text if TOKEN_PATTERNS[kind].match(text) else None


@dataclass(frozen=True)
class Salt:
    key: bytes
    salt_id: str


def _report_key_salt() -> Salt:
    """Fallback when SOKEN_LEARNING_SALT is unset: a key derived from the current report key (the
    API refuses to start without it), as quota.py does. Rotating the report key rotates this."""
    from ..report.render import current_key_version
    from ..tools.report import key as report_key

    version = current_key_version()
    derived = hmac.new(report_key(version), b"soken-learning-salt", hashlib.sha256).digest()
    return Salt(derived, f"rk{version}")


def current_salt() -> Salt:
    cfg = config()["salt"]
    raw = os.environ.get(cfg["env"], "").encode()
    if len(raw) >= int(cfg["min_bytes"]):
        return Salt(raw, token("release", os.environ.get(cfg["id_env"], "") or "k1", "k1"))
    if raw:
        logger.warning("%s shorter than %s bytes; using the report-key salt", cfg["env"], cfg["min_bytes"])
    return _report_key_salt()


def previous_salt() -> Salt | None:
    cfg = config()["salt"]
    raw = os.environ.get(cfg["previous_env"], "").encode()
    if len(raw) < int(cfg["min_bytes"]):
        return None
    return Salt(raw, token("release", os.environ.get(cfg["previous_id_env"], "") or "k0", "k0"))


def tag(kind: str, value: str, salt: Salt | None = None) -> str:
    """Keyed, truncated hash of an identifying value; the value itself is never stored."""
    s = salt or current_salt()
    n = int(config()["salt"]["tag_hex"])
    return hmac.new(s.key, f"soken-learning:{kind}:{value}".encode(), hashlib.sha256).hexdigest()[:n]


def job_tags(job_id: str) -> list[str]:
    """The job's replace key under the current and the previous salt (a rotation between finalize
    and purge must not leave the finalize rows behind)."""
    out = [tag("job", job_id)]
    prev = previous_salt()
    if prev is not None:
        out.append(tag("job", job_id, prev))
    return out


@cache
def _computed_release() -> str:
    from .. import contract as _contract

    lock = REPO_ROOT / "images.lock.json"
    digest = hashlib.sha256()
    digest.update(_contract.schema_version().encode())
    try:
        digest.update(json.dumps(json.loads(lock.read_text(encoding="utf-8")), sort_keys=True).encode())
    except (OSError, ValueError):
        pass
    try:
        from importlib.metadata import version as _pkg_version

        pkg = _pkg_version("soken-review")
    except Exception:  # noqa: BLE001  # not installed as a distribution (source checkout)
        pkg = "0"
    return f"v{pkg}-{digest.hexdigest()[:10]}"


def release() -> str:
    """Release id stamped on every ledger row: SOKEN_RELEASE when the deploy sets it, else the
    package version plus a hash of the tool contract and the locked image digests."""
    env = os.environ.get(config()["release_env"], "")
    return token("release", env, "") or _computed_release()
