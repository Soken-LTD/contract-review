"""Context facts (context ingestion spec 2026-10-23, section 5): deterministic records from the
stored documents, each with `source: "context/<path>:<line>"` and the tag `context` (units.yaml).

Every phrase, firm, jurisdiction, vendor and chain alias comes from
`contract/rubric/context_phrases.yaml`; this module holds the regex scaffolding only. A fact is a
`mapping.facts.fact` record (`key, value, unit, unit_id, source, tags`) with optional extra fields
(`shape`, `label`, `phrase`, `chain_id`, `chain`, `via`) that the report reads; `review_facts`
prints the common five. List-valued keys of the spec (`addresses`, `fee_pct[]`, `chains[]`,
`admin_claims[]`, `audit_claims[]`, `restricted_jurisdictions[]`, `data_collected[]`) are one
record per element under the same key.

Keys (only when found): `context.<kind>.addresses`, `.mentions_reviewed_address` (deployed jobs),
`.total_supply`, `.max_supply`, `.decimals`, `.fee_pct`, `.chains`, `.admin_claims`,
`.audit_claims`, `context.terms.restricted_jurisdictions`, `context.terms.kyc`,
`context.privacy.data_collected`, `context.privacy.contact`.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from ..mapping.facts import fact as _fact
from .fetcher import find_addresses
from .store import ContextEntry, ContextStore

_PHRASES_YAML = Path(__file__).resolve().parents[3] / "contract" / "rubric" / "context_phrases.yaml"
CONTEXT_FACTS_FILE = "context_facts.json"
_MAX_PER_LIST = 40

_NUMBER_RE = re.compile(r"(?<![0-9A-Za-z.])(\d{1,3}(?:,\d{3})+|\d+)(?:\.(\d+))?\s*(?:\^\s*(\d{1,2}))?\s*([A-Za-z]{1,8})?")
_PCT_RE = re.compile(r"(?<![0-9A-Za-z.])(\d+(?:[.,]\d+)?)\s*(%|percent|bps|basis points)", re.IGNORECASE)
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_KIND_ORDER = ("whitepaper", "docs", "website", "app", "terms", "privacy", "other")


@lru_cache(maxsize=1)
def phrases() -> dict[str, Any]:
    return yaml.safe_load(_PHRASES_YAML.read_text(encoding="utf-8"))


def _rx(words: list[str]) -> re.Pattern[str]:
    """One case-insensitive alternation; word boundaries where the phrase starts or ends alphanumeric."""
    parts = []
    for w in sorted((str(x) for x in words), key=len, reverse=True):
        esc = re.escape(w.lower()).replace(r"\ ", r"[\s-]+")
        left = r"(?<![0-9A-Za-z])" if w[:1].isalnum() else ""
        right = r"(?![0-9A-Za-z])" if w[-1:].isalnum() else ""
        parts.append(f"{left}{esc}{right}")
    return re.compile("|".join(parts) if parts else r"(?!x)x", re.IGNORECASE)


@lru_cache(maxsize=1)
def _compiled() -> dict[str, Any]:
    p = phrases()
    return {
        "supply": {k: _rx(v) for k, v in (p.get("supply") or {}).items()},
        "fee": _rx((p.get("fee") or {}).get("phrases") or []),
        "admin": {k: _rx(v) for k, v in (p.get("admin_claims") or {}).items()},
        "audit_phrases": _rx((p.get("audit_claims") or {}).get("phrases") or []),
        "audit_firms": _rx((p.get("audit_claims") or {}).get("firms") or []),
        "jur_phrases": _rx(((p.get("terms") or {}).get("restricted_jurisdictions") or {}).get("phrases") or []),
        "jur_names": _rx(((p.get("terms") or {}).get("restricted_jurisdictions") or {}).get("names") or []),
        "kyc": _rx((p.get("terms") or {}).get("kyc") or []),
        "data": {k: _rx(v) for k, v in ((p.get("privacy") or {}).get("data_collected") or {}).items()},
        "vendors": _rx((p.get("privacy") or {}).get("analytics_vendors") or []),
        "chains": [(row, _rx(row.get("aliases") or [])) for row in (p.get("chains") or [])],
        "window": int(p.get("window") or 60),
        "number_words": {str(k).lower(): int(v) for k, v in (p.get("number_words") or {}).items()},
    }


def _canonical(rx: re.Pattern[str], words: list[str], match: str) -> str:
    """The yaml spelling of a matched phrase (first alias whose lowercase equals the match)."""
    low = re.sub(r"[\s-]+", " ", match.lower())
    for w in words:
        if re.sub(r"[\s-]+", " ", str(w).lower()) == low:
            return str(w)
    return match


def fact(key: str, value: Any, *, source: str, unit: str | None = None, **extra: Any) -> dict[str, Any]:
    row = _fact(key, value, unit=unit, unit_id=None, source=source)
    for k, v in extra.items():
        if v is not None:
            row[k] = v
    return row


# ---------------------------------------------------------------------------------------------
# Numbers
# ---------------------------------------------------------------------------------------------

def parse_number(text: str) -> int | float | None:
    """`1,000,000,000`, `1 billion`, `100M`, `10^9` -> number; None when nothing numeric starts `text`."""
    m = _NUMBER_RE.match(text.strip())
    if not m:
        return None
    whole = m.group(1).replace(",", "")
    value: float = float(f"{whole}.{m.group(2)}") if m.group(2) else float(whole)
    if m.group(3):
        if whole != "10":
            return None
        value = 10.0 ** int(m.group(3))
    word = (m.group(4) or "").lower()
    mult = _compiled()["number_words"].get(word)
    if word and mult is None and word not in ("tokens", "token", "units", "coins", "coin", "total", "supply"):
        return None
    if mult:
        value *= mult
    if value.is_integer():
        return int(value)
    return value


def _number_near(line: str, start: int, end: int, window: int) -> int | float | None:
    """A number within `window` chars after the phrase, else before it."""
    after = line[end : end + window]
    for m in _NUMBER_RE.finditer(after):
        n = parse_number(after[m.start():])
        if n is not None:
            return n
    before = line[max(0, start - window) : start]
    found = None
    for m in _NUMBER_RE.finditer(before):
        n = parse_number(before[m.start():])
        if n is not None:
            found = n
    return found


def _label(line: str, limit: int = 120) -> str:
    """The surrounding phrase of a figure: the line, clipped at a word boundary."""
    text = re.sub(r"\s+", " ", line).strip()
    if len(text) <= limit:
        return text
    cut = text[:limit].rsplit(" ", 1)[0]
    return cut if len(cut) >= limit // 2 else text[:limit]


def _fmt(n: float) -> str:
    if isinstance(n, float) and not n.is_integer():
        return f"{n:.6f}".rstrip("0").rstrip(".")
    return str(int(n))


# ---------------------------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------------------------

def context_facts(store: ContextStore, job: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Every context fact of the job's ok documents, deterministic and sorted by key then source."""
    job = job or {}
    out: list[dict[str, Any]] = []
    by_kind: dict[str, list[ContextEntry]] = {}
    for e in store.documents:
        if e.ok:
            by_kind.setdefault(e.kind, []).append(e)
    for kind in _KIND_ORDER:
        docs = by_kind.get(kind)
        if not docs:
            continue
        out.extend(_kind_facts(kind, docs, store, job))
    out.sort(key=lambda f: (f["key"], _source_key(f["source"])))
    return out


def _source_key(source: str) -> tuple[str, int]:
    path, _, line = source.rpartition(":")
    return path, int(line) if line.isdigit() else 0


def _kind_facts(kind: str, docs: list[ContextEntry], store: ContextStore, job: dict[str, Any]) -> list[dict[str, Any]]:
    c = _compiled()
    p = phrases()
    window = c["window"]
    prefix = f"context.{kind}."
    out: list[dict[str, Any]] = []
    seen: dict[str, set[Any]] = {}
    scalar_done: set[str] = set()
    reviewed = _reviewed_address(job)
    mention_source: str | None = None

    def add_list(key: str, value: Any, source: str, dedup: Any = None, **extra: Any) -> None:
        bucket = seen.setdefault(key, set())
        token = dedup if dedup is not None else value
        if token in bucket or len(bucket) >= _MAX_PER_LIST:
            return
        bucket.add(token)
        out.append(fact(prefix + key, value, source=source, **extra))

    for e in docs:
        lines = store.read_all(e.path)
        for n, line in enumerate(lines, start=1):
            src = f"{e.path}:{n}"
            for shape, values in find_addresses(line).items():
                for v in values:
                    add_list("addresses", v, src, dedup=(shape, v), shape=shape)
                    if reviewed is not None and mention_source is None and _same_address(v, reviewed):
                        mention_source = src
            # supply, decimals
            for skey, rx in c["supply"].items():
                if skey in scalar_done:
                    continue
                m = rx.search(line)
                if not m:
                    continue
                n_val = _number_near(line, m.start(), m.end(), window)
                if n_val is None:
                    continue
                if skey == "decimals":
                    if isinstance(n_val, int) and 0 <= n_val <= 36:
                        scalar_done.add(skey)
                        out.append(fact(prefix + "decimals", n_val, source=src, phrase=m.group(0)))
                    continue
                if n_val <= 0:
                    continue
                scalar_done.add(skey)
                out.append(fact(prefix + skey, _fmt(n_val), unit="tokens", source=src, phrase=m.group(0)))
            # fees: every percent or bps figure within `window` chars of a fee phrase, once per line
            for fm in c["fee"].finditer(line):
                lo, hi = max(0, fm.start() - window), min(len(line), fm.end() + window)
                for pm in _PCT_RE.finditer(line[lo:hi]):
                    raw = pm.group(1).replace(",", ".")
                    unit_word = pm.group(2).lower()
                    unit = "bps" if unit_word.startswith("b") else "percent"
                    try:
                        value = float(raw)
                    except ValueError:
                        continue
                    add_list("fee_pct", _fmt(value), src, dedup=(unit, _fmt(value), e.path, n), unit=unit,
                             label=_label(line))
            # chains
            for row, rx in c["chains"]:
                m = rx.search(line)
                if not m:
                    continue
                name, extra = _chain_identity(row)
                add_list("chains", name, src, dedup=name, **extra)
            # admin claims
            for claim, rx in c["admin"].items():
                m = rx.search(line)
                if m:
                    add_list("admin_claims", claim, src, dedup=claim, phrase=m.group(0))
            # audit claims
            phrase = c["audit_phrases"].search(line)
            firms_found = list(c["audit_firms"].finditer(line))
            firms = (p.get("audit_claims") or {}).get("firms") or []
            for firm in firms_found:
                add_list("audit_claims", _canonical(c["audit_firms"], firms, firm.group(0)), src,
                         dedup=firm.group(0).lower(), phrase=(phrase.group(0) if phrase else None))
            if phrase and not firms_found:
                add_list("audit_claims", phrase.group(0).lower(), src, dedup=phrase.group(0).lower())
            if kind == "terms":
                if c["jur_phrases"].search(line) or c["jur_phrases"].search(" ".join(lines[max(0, n - 3):n - 1])):
                    names = ((p.get("terms") or {}).get("restricted_jurisdictions") or {}).get("names") or []
                    for jm in c["jur_names"].finditer(line):
                        add_list("restricted_jurisdictions", _canonical(c["jur_names"], names, jm.group(0)), src)
                if "kyc" not in scalar_done:
                    km = c["kyc"].search(line)
                    if km:
                        scalar_done.add("kyc")
                        out.append(fact(prefix + "kyc", "true", source=src, phrase=km.group(0)))
            if kind == "privacy":
                for cat, rx in c["data"].items():
                    m = rx.search(line)
                    if m:
                        add_list("data_collected", cat, src, dedup=cat, phrase=m.group(0))
                vendors = (p.get("privacy") or {}).get("analytics_vendors") or []
                for vm in c["vendors"].finditer(line):
                    add_list("data_collected", _canonical(c["vendors"], vendors, vm.group(0)), src,
                             dedup=vm.group(0).lower(), phrase="analytics")
                if "contact" not in scalar_done:
                    em = _EMAIL_RE.search(line)
                    if em:
                        scalar_done.add("contact")
                        out.append(fact(prefix + "contact", em.group(0), source=src))
        # bundle hits (website, app): no line in the document, the title line carries them
        hits = (e.bundle_hits or {}).get("addresses") or {}
        for shape, values in hits.items():
            for v in values[:_MAX_PER_LIST]:
                add_list("addresses", v, f"{e.path}:1", dedup=(shape, v), shape=shape, via="bundle")
                if reviewed is not None and mention_source is None and _same_address(v, reviewed):
                    mention_source = f"{e.path}:1"
        for cid in (e.bundle_hits or {}).get("chain_ids") or []:
            row = _chain_row_for_id(int(cid))
            name, extra = _chain_identity(row) if row else (str(cid), {"chain_id": int(cid)})
            add_list("chains", name, f"{e.path}:1", dedup=name, via="bundle", **extra)
    if reviewed is not None:
        if mention_source:
            out.append(fact(prefix + "mentions_reviewed_address", "true", source=mention_source))
        else:
            out.append(fact(prefix + "mentions_reviewed_address", "false", source=f"{docs[0].path}:1"))
    return out


def _reviewed_address(job: dict[str, Any]) -> str | None:
    addr = job.get("address")
    if not addr or not isinstance(addr, str):
        return None
    if re.fullmatch(r"(0x)?[0-9a-fA-F]{40}", addr):
        return "0x" + addr.lower().removeprefix("0x")
    return addr


def _same_address(a: str, b: str) -> bool:
    if a.lower().startswith("0x") and b.lower().startswith("0x"):
        return a.lower().lstrip("0x").lstrip("0") == b.lower().lstrip("0x").lstrip("0")
    return a == b


def _chain_identity(row: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    if row.get("chain_id") is not None:
        cid = int(row["chain_id"])
        try:
            from ..adapters.evm.registry import get_chain

            rec = get_chain(cid)
            name = rec.name if rec else str((row.get("aliases") or [str(cid)])[0])
        except Exception:  # noqa: BLE001  # registry unavailable: the first alias names the chain
            name = str((row.get("aliases") or [str(cid)])[0])
        return name, {"chain_id": cid}
    key = str(row.get("chain") or "")
    return str((row.get("aliases") or [key])[0]), {"chain": key}


def _chain_row_for_id(chain_id: int) -> dict[str, Any] | None:
    for row, _rx in _compiled()["chains"]:
        if row.get("chain_id") == chain_id:
            return row
    return None


# ---------------------------------------------------------------------------------------------
# Persistence beside facts.json (mapping.facts.load_facts merges this file in)
# ---------------------------------------------------------------------------------------------

def write_context_facts(root: Path, job_id: str, facts: list[dict[str, Any]]) -> None:
    d = root / job_id
    d.mkdir(parents=True, exist_ok=True)
    (d / CONTEXT_FACTS_FILE).write_text(json.dumps(facts, indent=1), encoding="utf-8")


def load_context_facts(root: Path, job_id: str) -> list[dict[str, Any]]:
    p = root / job_id / CONTEXT_FACTS_FILE
    if not p.exists():
        return []
    data = json.loads(p.read_text(encoding="utf-8"))
    return data if isinstance(data, list) else []
