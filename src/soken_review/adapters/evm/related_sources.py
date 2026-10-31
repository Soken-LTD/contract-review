"""Related deployed contracts reviewed in the same job (matrix run 2026-10-31, Magnum).

A contract often calls a few others the client deployed with it (a price feed, an NFT). Before,
the reviewer opened one extra job per contract only to read its source, and quotes from those
jobs were refused in the main one. A deployed EVM job may now name up to `MAX_RELATED` related
addresses on the same chain: `source.related` in the current schema, or `scope.include` entries
`related:0xADDR` / `related:Name=0xADDR`, which a client holding an older tool list can send.

Each related contract's verified source is pinned under `_related/<name>/` in scope, so it can be
read, searched and quoted as a location. It is not rebuilt or compared with its deployment (only
the main contract is), and the analyzers run on the main build only; its provenance line says so.
The implementation behind a proxy is the main code; the proxy's own source joins as related `proxy`.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from .fetch import fetch_source

logger = logging.getLogger(__name__)

RELATED_PREFIX = "_related/"
MAX_RELATED = 5
_MAX_FILES_PER_RELATED = 200
_ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,40}$")
_INCLUDE_RE = re.compile(r"^related:(?:(?P<name>[^=\s]{1,40})=)?(?P<addr>\S+)$")
_VERIFIED_PROVIDERS = ("sourcify", "eth_bytecode_db", "ipfs")


class RelatedError(ValueError):
    """An unusable related entry: `field` names the argument, `value` is the bad value."""

    def __init__(self, field: str, value: str, rule: str) -> None:
        super().__init__(rule)
        self.field = field
        self.value = value
        self.rule = rule


def is_related_path(path: str) -> bool:
    return path.startswith(RELATED_PREFIX)


def _default_name(address: str) -> str:
    return "c_" + address.lower()[2:12]


def parse_related(source: dict[str, Any], scope: dict[str, Any] | None,
                  main_address: str | None) -> tuple[list[dict[str, str]], list[str]]:
    """Related entries of a review_start call and the scope.include entries left for scope.

    Returns `(related, include_rest)`. Raises RelatedError on a malformed address or name, more
    than MAX_RELATED entries, or the main address named as related."""
    raw: list[tuple[str, str | None, str]] = []
    for i, row in enumerate(source.get("related") or []):
        raw.append((str(row.get("address") or ""), row.get("name"), f"source.related[{i}]"))
    rest: list[str] = []
    for i, item in enumerate((scope or {}).get("include") or []):
        if not (isinstance(item, str) and item.strip().startswith("related:")):
            rest.append(item)
            continue
        m = _INCLUDE_RE.match(item.strip())
        if m is None:
            raise RelatedError(f"scope.include[{i}]", item, "related:0xADDR or related:Name=0xADDR")
        raw.append((m.group("addr"), m.group("name"), f"scope.include[{i}]"))
    out: list[dict[str, str]] = []
    seen_addr: set[str] = set()
    seen_name: set[str] = set()
    main = (main_address or "").lower()
    for addr, name, field in raw:
        if not _ADDR_RE.match(addr):
            raise RelatedError(field, addr, "an EVM address 0x followed by 40 hex digits")
        if name is not None and not _NAME_RE.match(name):
            raise RelatedError(field, name, "a name of letters, digits, _ or -, at most 40")
        a = addr.lower()
        if a == main:
            raise RelatedError(field, addr, "a contract other than the one under review")
        if a in seen_addr:
            continue
        n = name or _default_name(a)
        if n.lower() == "proxy" or n.lower() in seen_name:
            n = f"{n}_{a[2:8]}"
        seen_addr.add(a)
        seen_name.add(n.lower())
        out.append({"address": a, "name": n})
    if len(out) > MAX_RELATED:
        raise RelatedError("source.related", str(len(out)), f"at most {MAX_RELATED} related contracts")
    return out, rest


async def fetch_related(chain_id: int, entries: list[dict[str, str]], rpc: Any
                        ) -> tuple[dict[str, str], dict[str, str], list[dict[str, Any]]]:
    """Fetch and prefix the verified source of each related contract.

    Returns `(files, langs, records)`: pin paths under `_related/<name>/`, their language, and one
    provenance record per entry (`status` pinned | no_code | no_verified_source | fetch_failed with
    a plain-English `note`). One entry that fails never fails the others or the job."""
    files: dict[str, str] = {}
    langs: dict[str, str] = {}
    records: list[dict[str, Any]] = []
    for e in entries[: MAX_RELATED + 1]:   # + 1: the proxy entry beside the client's five
        rec: dict[str, Any] = {"name": e["name"], "address": e["address"]}
        if e.get("role"):
            rec["role"] = e["role"]
        try:
            code = await rpc.get_code(e["address"])
            if not code or code in ("0x", "0x0"):
                rec.update(status="no_code", note=f"No contract code at {e['address']} on this chain at the "
                                                    "pinned block, so it is not part of this review.")
                records.append(rec)
                continue
            cands = await fetch_source(chain_id=chain_id, address=e["address"], runtime_bytecode=code)
        except Exception as exc:  # noqa: BLE001  # one related contract never fails the job
            logger.info("related %s fetch failed: %s", e["address"][:10], str(exc)[:120])
            rec.update(status="fetch_failed", note=f"The source of {e['name']} could not be fetched; "
                                                     "it is not part of this review. Try again later.")
            records.append(rec)
            continue
        cand = next((c for c in cands if c.provider in _VERIFIED_PROVIDERS and c.files), None)
        if cand is None:
            rec.update(status="no_verified_source",
                       note=f"{e['name']} has no verified source on Sourcify or the bytecode database, "
                            "so it is not part of this review. Verify it there and start a new job.")
            records.append(rec)
            continue
        prefix = f"{RELATED_PREFIX}{e['name']}/"
        for path, content in sorted(cand.files.items())[:_MAX_FILES_PER_RELATED]:
            files[prefix + path.lstrip("/")] = content
            langs[prefix + path.lstrip("/")] = cand.language
        rec.update(status="pinned", provider=cand.provider, match=cand.sourcify_match,
                   entry_contract=cand.entry_contract, files=min(len(cand.files), _MAX_FILES_PER_RELATED),
                   path=prefix.rstrip("/"))
        records.append(rec)
    return files, langs, records
