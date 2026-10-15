"""Read-only HTTP for the Move chain_state step (plan v4 07 section 3; 09 provider rows).

Fixed hosts only (Sui GraphQL, Aptos REST, Move Registry); responses are size capped and
parsed as JSON. Any transport error raises `ChainReadError`: a chain read that cannot complete
fails the step (fail closed), it never yields an empty answer.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlparse

SUI_GRAPHQL = os.environ.get("SOKEN_SUI_GRAPHQL", "https://graphql.mainnet.sui.io/graphql")
APTOS_REST = os.environ.get("SOKEN_APTOS_REST", "https://api.mainnet.aptoslabs.com/v1")
MVR_API = os.environ.get("SOKEN_MVR_API", "https://mainnet.mvr.mystenlabs.com")
_ALLOWED_HOSTS = {urlparse(u).hostname for u in (SUI_GRAPHQL, APTOS_REST, MVR_API)}
_MAX_BYTES = 64 * 1024 * 1024
_TIMEOUT_S = 30
_ATTEMPTS = 7


class ChainReadError(RuntimeError):
    """A provider read failed or answered something unusable."""


class NotFound(ChainReadError):
    """HTTP 404 from the provider (resource or package absent)."""


def _request(url: str, body: dict[str, Any] | None = None) -> Any:
    if urlparse(url).hostname not in _ALLOWED_HOSTS:
        raise ChainReadError(f"host not allowed: {urlparse(url).hostname}")
    data = json.dumps(body).encode() if body is not None else None
    headers = {"User-Agent": "soken-review/1", "Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:
            raw = resp.read(_MAX_BYTES + 1)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise NotFound(url) from exc
        if exc.code == 429 or exc.code >= 500:
            raise _Transient(f"HTTP {exc.code} from {urlparse(url).hostname}") from exc
        raise ChainReadError(f"HTTP {exc.code} from {urlparse(url).hostname}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise _Transient(f"transport error: {exc}") from exc
    if len(raw) > _MAX_BYTES:
        raise ChainReadError("response over size cap")
    try:
        return json.loads(raw)
    except ValueError as exc:
        raise ChainReadError("response is not JSON") from exc


class _Transient(ChainReadError):
    """Timeout, connection error, 429 or 5xx: retried."""


def _with_retry(url: str, body: dict[str, Any] | None) -> Any:
    delay = 2.0
    for attempt in range(_ATTEMPTS):
        try:
            return _request(url, body)
        except _Transient:
            if attempt == _ATTEMPTS - 1:
                raise
            time.sleep(delay)
            delay *= 2
    raise ChainReadError("unreachable")


def get_json(url: str) -> Any:
    return _with_retry(url, None)


def post_json(url: str, body: dict[str, Any]) -> Any:
    return _with_retry(url, body)


def graphql(query: str, variables: dict[str, Any] | None = None) -> dict[str, Any]:
    """One Sui GraphQL query; errors in the answer raise (no partial data is used)."""
    out = post_json(SUI_GRAPHQL, {"query": query, "variables": variables or {}})
    if not isinstance(out, dict) or out.get("errors"):
        raise ChainReadError(f"graphql errors: {str(out.get('errors') if isinstance(out, dict) else out)[:300]}")
    data = out.get("data")
    if not isinstance(data, dict):
        raise ChainReadError("graphql answer has no data")
    return data
