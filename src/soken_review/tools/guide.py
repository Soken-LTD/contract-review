"""review_get_guide (03 4.3): one reference topic of the review method, as text.

Topics are reference data only (02 2F): the category list, the severity matrix inputs with the
caps, the challenge answer rules, and the per-family disproof checklist. Everything is rendered
from the rubric files under ``contract/rubric`` (enums.yaml, checklists/<family>.yaml) and the
engine's own rule tables, so the guide can never drift from what the server enforces. The plan's
``methodology/<version>/`` static files were never shipped; until 2026-10-22 the tool had no
handler at all and every call ended in an internal error, which left clients guessing enum values
(matrix.trigger "governance", impact_class "accounting_error") and burning submit attempts.

Thin server (2026-10-31): with no topic the answer is topic ``start``, the short default path under the
budget in ``contract/rubric/guide.yaml``; every other topic is opt-in. All LLM-facing sentences live in
that data file; this module only joins them with lists rendered from the rubric.

Output: first line ``guide_version <v> topic <t> chain <c>``, then compact lines, at most 12,000
characters (03 6). With ``topics`` the blocks of several topics are joined by a blank line, each with
its own header and cap (the 2026-10-25 blind runs spent 4 to 5 guide calls per review, one per topic).
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from ..errors import ReviewError
from ..server import handler

GUIDE_VERSION = "v0"
_TOPICS = ("start", "checklist", "categories", "severity_inputs", "challenge_rules", "context", "invariants", "chain")
_CAP = 12_000
_RUBRIC = Path(__file__).resolve().parents[3] / "contract" / "rubric"

# chain -> checklist / category family (04 §2: one checklist file per family)
_FAMILY = {
    "evm": "evm", "hyperevm": "evm", "tron": "evm",
    "solana": "solana", "ton": "ton", "sui": "move", "aptos": "move", "starknet": "cairo",
}

# 04 §7.4: the rules the severity engine applies on top of the IxL cell, read from the registry the
# client can dispute by id (rubric/severity_rules.yaml; engine/severity.py RULE_TEXT mirrors it).
@lru_cache(maxsize=1)
def _severity_rules() -> list[tuple[str, str, str, str]]:
    doc = yaml.safe_load((_RUBRIC / "severity_rules.yaml").read_text(encoding="utf-8"))
    out = []
    for r in doc.get("rules", []):
        effect = r.get("effect") or (f"caps the calibration at {r['ceiling']}" if r.get("ceiling") else "")
        out.append((str(r["id"]), str(r.get("phase", "all")), str(r.get("condition", "")), effect))
    return out


@lru_cache(maxsize=1)
def _texts() -> dict[str, Any]:
    """Every LLM-facing sentence of the guide (contract/rubric/guide.yaml); Python only joins them."""
    return yaml.safe_load((_RUBRIC / "guide.yaml").read_text(encoding="utf-8")) or {}


def start_text(family: str = "evm") -> str:
    """The default guide body: the five-step path, the optional list and the family's category ids.
    Also carried by the review_start result (`guide`), so a review needs no guide call."""
    t = _texts()["start"]
    ids = [c["id"] for c in _enums().get("categories", [])
           if c.get("family") == family and not c.get("server_only")
           and c.get("legacy") != "read only by corpus import"]
    lines = [str(t["text"]).strip(), str(t["optional"]).strip(),
             str(t["categories_line"]).format(family=family) + " " + ", ".join(ids)]
    return "\n".join(lines)


@lru_cache(maxsize=1)
def _guide_notes() -> dict[str, Any]:
    return yaml.safe_load((_RUBRIC / "guide_notes.yaml").read_text(encoding="utf-8")) or {}


@lru_cache(maxsize=1)
def _lead_links() -> dict[str, Any]:
    return yaml.safe_load((_RUBRIC / "lead_links.yaml").read_text(encoding="utf-8")) or {}


def _enums() -> dict[str, Any]:
    return yaml.safe_load((_RUBRIC / "enums.yaml").read_text(encoding="utf-8"))


@lru_cache(maxsize=8)
def _checklist(family: str) -> dict[str, Any] | None:
    path = _RUBRIC / "checklists" / f"{family}.yaml"
    if not path.is_file():
        return None
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _family_for(chain: str | None) -> str:
    return _FAMILY.get(chain or "evm", "evm")


def _s(value: Any) -> str:
    return str(value).strip()


def _topic_categories(family: str) -> list[str]:
    enums, t = _enums(), _texts()["categories"]
    out = [_s(t["intro"]).format(family=family)]
    for cat in enums.get("categories", []):
        if cat.get("family") != family or cat.get("server_only"):
            continue
        flags = []
        if cat.get("generic"):
            flags.append("generic")
        if cat.get("max_severity"):
            flags.append(f"max {cat['max_severity']}")
        line = f"{cat['id']}  group {cat.get('match_group', '-')}"
        if flags:
            line += "  " + ", ".join(flags)
        out.append(line)
    out.append(_s(t["outro"]))
    from ..engine.category_fit import guide_lines
    fit = guide_lines(family)
    if fit:
        out.append("")
        out.extend(fit)
    return out


def _topic_severity_inputs() -> list[str]:
    enums, t = _enums(), _texts()["severity_inputs"]
    out = [_s(t["intro"])]
    for field, values in enums.get("matrix", {}).items():
        out.append(f"{field}: {', '.join(values)}")
    out.append("")
    out.append(_s(t["rules_head"]))
    for kid, phase, cond, effect in _severity_rules():
        out.append(f"{kid}  {phase}  {cond}  -> {effect}")
    out.append("")
    out.append(_s(t["evidence_head"]))
    for level, how in t["evidence"]:
        out.append(f"{level}: {how}")
    out.append("")
    out.append(_s(t["fill"]) + " " + _s(_guide_notes()["freeze_classes"]["text"]))
    out.append(_s(t["quotes"]))
    return out


def _topic_challenge_rules() -> list[str]:
    enums, t = _enums(), _texts()["challenge_rules"]
    out = [_s(t["intro"]), _s(t["challenge"]),
           _s(t["kinds"]).format(kinds=", ".join(enums.get("checklist_kind", []))),
           _s(t["values"]).format(values=", ".join(enums.get("challenge_value", []))),
           _s(t["na_reasons"]).format(reasons=", ".join(enums.get("na_reasons", []))),
           _s(t["scopes"]).format(scopes=", ".join(enums.get("challenge_scope", []))),
           _s(t["revision"]),
           _s(t["dismissal"]).replace("{reasons}", ", ".join(enums.get("dismissal_reason", {}).get("model", [])))]
    links = _lead_links()
    out.append(str(links.get("intro", "")).strip())
    for rule in links.get("rules") or []:
        out.append(f"  {rule['id']}: {rule['text']} Fix: {rule['fix']}")
    out.append(_s(t["documents"]))
    out.append(_s(t["text_rules"]))
    from ..engine.text_gate import rule_word_lists

    out.append(_s(t["word_lists_head"]))
    out.extend(rule_word_lists())
    from ..engine.gate_policy import policy_lines

    out.append(_s(t["policy_head"]))
    out.extend(policy_lines())
    return out


def _topic_context() -> list[str]:
    enums, t = _enums(), _texts()["context"]
    kinds = ", ".join(enums.get("context_kind", []))
    return [_s(t["intro"]), _s(t["kinds"]).replace("{kinds}", kinds), _s(t["reading"]), _s(t["quoting"]),
            _s(t["facts"]), _s(t["prose"])]


def _topic_chain() -> list[str]:
    """Chain state (auto-read at job start) and the optional chain tools; free sources only."""
    from ..chain.untrusted import GUIDE_NOTE

    lines = [_s(x) for x in _texts()["chain"]["lines"]]
    return [*lines, f"Chain text (token names, revert strings) arrives only in untrusted_text. {GUIDE_NOTE}"]


def _topic_checklist(family: str) -> list[str]:
    doc, t = _checklist(family), _texts()["checklist"]
    if doc is None:
        return [_s(t["missing"]).format(family=family)]
    out = [_s(t["intro"]).format(family=family)]
    generic = doc.get("generic_items") or []
    if generic:
        out.append(_s(t["generic_head"]))
        for item in generic:
            out.append(f"  {item.get('id')}  {item.get('kind')}  {item.get('condition')}")
    for cat_id, cat in (doc.get("categories") or {}).items():
        out.append(f"{cat_id}:")
        for item in cat.get("items") or []:
            na = f"  n/a {', '.join(item['na'])}" if item.get("na") else ""
            out.append(f"  {item.get('id')}  {item.get('kind')}  {item.get('condition')}{na}")
    return out


def _topic_invariants(job_id: str | None, family: str) -> list[str]:
    """Lifecycle and invariant pass (contract/rubric/invariants.yaml): the method, and with a job
    the job's lifecycle leads, protocol types and walks with the code each answer must cover."""
    from ..mapping.lifecycle import load_lifecycle, render_guide

    lc = None
    if job_id:
        try:
            from .read import _get_ctx

            lc = load_lifecycle(_get_ctx().get_pin_root(), job_id)
        except Exception:  # noqa: BLE001 - a guide read never fails on job lookup
            lc = None
    return render_guide(lc, family)


@handler("review_get_guide")
async def _get_guide(args: dict[str, Any]) -> str:
    """One topic (`topic`) or several (`topics`, in the given order) in one call; each topic block keeps
    its own header line and its own cap, so a multi-topic answer is the single answers joined."""
    # No topic: the default guide (topic start, thin server 2026-10-31); every other topic is opt-in.
    topics: list[str] = list(args.get("topics") or ([args["topic"]] if args.get("topic") else ["start"]))
    chain: str | None = args.get("chain")
    if chain is None and args.get("job_id"):
        chain = _job_chain(args["job_id"])
    if "checklist" in topics and "invariants" not in topics and args.get("job_id") and _job_has_walks(args["job_id"]):
        # A tool list from before the invariants topic cannot ask for it (blind round 5): the checklist of
        # a job with invariant walks carries them as a second block, so F9 is answerable from any list.
        topics.append("invariants")
    return "\n\n".join(_render_topic(topic, chain, args.get("job_id")) for topic in dict.fromkeys(topics))


def _job_has_walks(job_id: str) -> bool:
    from ..mapping.lifecycle import load_lifecycle

    try:
        from .read import _get_ctx

        lc = load_lifecycle(_get_ctx().get_pin_root(), job_id)
    except Exception:  # noqa: BLE001 - a guide read never fails on job lookup
        return False
    return bool((lc or {}).get("walks"))


def _render_topic(topic: str, chain: str | None, job_id: str | None = None) -> str:
    family = _family_for(chain)
    if topic == "start":
        body = [start_text(family)]
    elif topic == "categories":
        body = _topic_categories(family)
    elif topic == "severity_inputs":
        body = _topic_severity_inputs()
    elif topic == "challenge_rules":
        body = _topic_challenge_rules()
    elif topic == "checklist":
        body = _topic_checklist(family)
    elif topic == "context":
        body = _topic_context()
    elif topic == "invariants":
        body = _topic_invariants(job_id, family)
    elif topic == "chain":
        body = _topic_chain()
    else:  # the input schema already enumerates topics; keep the error shape consistent
        raise ReviewError("E_INVALID_ARGUMENT", field="topic", rule="enum", value80=topic[:80],
                          example="one of " + ", ".join(_TOPICS))
    text = "\n".join([f"guide_version {GUIDE_VERSION} topic {topic} chain {chain or 'evm'}", *body])
    if len(text) > _CAP:
        text = text[: _CAP - 20].rsplit("\n", 1)[0] + "\n(truncated)"
    return text


def _job_chain(job_id: str) -> str | None:
    """Chain of a job when the read context knows it; None keeps the default family."""
    try:
        from .read import _get_ctx

        ctx = _get_ctx()
    except ReviewError:
        return None
    get_chain = getattr(ctx, "get_job_chain", None)
    if get_chain is None:
        return None
    try:
        return get_chain(job_id)
    except Exception:  # noqa: BLE001 - a guide read never fails on job lookup
        return None
