"""review_get_guide (03 4.3): one reference topic of the review method, as text.

Topics are reference data only (02 2F): the category list, the severity matrix inputs with the
caps, the challenge answer rules, and the per-family disproof checklist. Everything is rendered
from the rubric files under ``contract/rubric`` (enums.yaml, checklists/<family>.yaml) and the
engine's own rule tables, so the guide can never drift from what the server enforces. The plan's
``methodology/<version>/`` static files were never shipped; until 2026-10-22 the tool had no
handler at all and every call ended in an internal error, which left clients guessing enum values
(matrix.trigger "governance", impact_class "accounting_error") and burning submit attempts.

Output: first line ``guide_version <v> topic <t> chain <c>``, then compact lines, at most 12,000
characters (03 6).
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from ..errors import ReviewError
from ..server import handler

GUIDE_VERSION = "v0"
_CAP = 12_000
_RUBRIC = Path(__file__).resolve().parents[3] / "contract" / "rubric"

# chain -> checklist / category family (04 §2: one checklist file per family)
_FAMILY = {
    "evm": "evm", "hyperevm": "evm", "tron": "evm",
    "solana": "solana", "ton": "ton", "sui": "move", "aptos": "move", "starknet": "cairo",
}

# 04 §7.4: the caps the severity engine applies, in the words the engine uses (engine/severity.py).
_CAPS = [
    ("K1", "all", "trigger privileged_role or upgrade_authority", "Medium"),
    ("K3", "all", "magnitude dust", "Low"),
    ("K4", "finalize", "evidence reasoning_only (a draft that never took a challenge)", "Low"),
    ("K5", "post_challenge, finalize", "each downgrade item answered present", "minus one level, at most two"),
    ("K6", "all", "precondition victim_unusual_action", "Low"),
    ("K7", "all", "impact centralization_risk", "Low"),
    ("K8", "post_challenge, finalize", "Critical without evidence E2 or E3, or without attack_steps", "High"),
    ("K10", "post_challenge, finalize", "a checklist item scope not covered, or no contract map", "High"),
    ("K11", "all", "generic category without a linked lead of the same category", "High"),
]

_EVIDENCE = [
    ("E3 analyzer_and_reasoning", "lead_ids names an analyzer lead of the same category that overlaps a location quote"),
    ("E2 reasoning_challenged", "no such lead; the disproof checklist was answered (passed or downgraded)"),
    ("E1 reasoning_only", "neither; prints as Low or Informational at finalize (K4)"),
]


@lru_cache(maxsize=1)
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


def _topic_categories(family: str) -> list[str]:
    enums = _enums()
    out = [(f"Category ids for review_submit_finding.category (family {family}). generic: needs a linked lead of"
            " the same category to print above High; max: ceiling for the category.")]
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
    out.append("Category and lead must agree: a linked lead's category must equal the finding category.")
    return out


def _topic_severity_inputs() -> list[str]:
    enums = _enums()
    out = [("review_submit_finding.matrix: five fields, exact values below. Severity = impact x likelihood,"
            " then the caps; claimed_severity is advisory, the matrix decides.")]
    for field, values in enums.get("matrix", {}).items():
        out.append(f"{field}: {', '.join(values)}")
    out.append("")
    out.append("Caps (id, phase, condition, ceiling):")
    for kid, phase, cond, cap in _CAPS:
        out.append(f"{kid}  {phase}  {cond}  -> {cap}")
    out.append("")
    out.append("Evidence levels (set by the server, never claimed):")
    for level, how in _EVIDENCE:
        out.append(f"{level}: {how}")
    out.append("")
    out.append("To print a High: link an analyzer lead of the same category (review_leads, lead_ids), or"
               " answer the challenge (review_challenge, review_answer_challenge). trigger privileged_role"
               " caps at Medium unless the deployment is a retail token where the owner is the threat.")
    out.append("magnitude: unbounded when the amount lost or frozen is the unit's full balance or a user's whole"
               " position (a stake, a vote allocation), bounded only with a bound_ref quote of the cap, dust for"
               " rounding. A freeze that lasts until an admin acts is permanent_freeze with reversibility"
               " admin_reversible, not temporary_freeze; temporary_freeze is a freeze that clears by itself."
               " precondition: normal_operation when the path runs in a state the protocol expects (a removed"
               " gauge, a slashed round, an admin-added token); uncommon_protocol_state only for a state it does"
               " not expect. A bounded loss under an uncommon state prints Low by the matrix (I2 x L1).")
    out.append("Quotes: role location quotes must copy the pinned lines exactly (review_read_code). Numbers in"
               " text need a source ({fact:<key>} or {calc:...}); a count in words up to ten, once, twice and"
               " third pass on their own (two pools, the third call, paid twice) but not before a unit, percent"
               " or token word (two tokens, ten percent, five days); absence phrases (never, nowhere, no"
               " function) need an absence_claims entry.")
    return out


def _topic_challenge_rules() -> list[str]:
    enums = _enums()
    out = [("review_challenge returns checklist items for the current revision; review_answer_challenge"
            " records one answer per item.")]
    out.append("Item kinds: " + ", ".join(enums.get("checklist_kind", [])) + ". kill: present disproves the finding"
               " (it is withdrawn); downgrade: present lowers severity one level (K5); context and basis: recorded.")
    out.append("Answer values: " + ", ".join(enums.get("challenge_value", [])) + ". present and absent need 1 to 3"
               " quotes (exact pinned lines) and refs path:start-end; not_applicable needs a reason.")
    out.append("not_applicable reasons: " + ", ".join(enums.get("na_reasons", [])))
    out.append("Scopes: " + ", ".join(enums.get("challenge_scope", [])) + ". A scope the quotes do not cover"
               " marks the item not covered and caps the finding at High (K10). An absent answer needs refs that"
               " cover every range in that item's scope.ranges, basis items included, each range read first with"
               " review_read_code; E_CHALLENGE_SCOPE names the failing item.")
    out.append("Revision: pass the revision review_challenge reports; a stale revision is rejected.")
    out.append("Lead dismissal (review_dismiss_lead, arguments job_id and items: a list of {lead_id, reason, quotes, note}) reasons: "
               + ", ".join(enums.get("dismissal_reason", {}).get("model", []))
               + "; every open High or Medium analyzer lead must be promoted or dismissed before review_finalize (F2)."
               " fp_guarded: reentrancy and access-control leads, quote the guard line inside the entry function."
               " fp_unreachable: the map must prove no entry reaches the location."
               " not_a_vulnerability: analyzer leads only; quote a code line inside the function that holds the"
               " lead and give a note of at least 40 characters stating why the detector pattern is not a"
               " weakness there. duplicate_of: an accepted or needs_challenge draft of the same family."
               " Notes are audit-log text: no prose or number rules apply to them.")
    out.append("Project documents (review_add_context): quotes with role context cite context/ paths exactly like"
               " code and never count as a location; {{fact:context.*}} placeholders carry the document line.")
    out.append("Text rules on every model string: no second person, no questions, no severity words or"
               " completeness claims in prose, no analyzer or model names, no URLs, no raw LEAD or finding ids,"
               " paragraphs at most 90 words, titles 10 to 110 characters in one sentence.")
    return out


def _topic_context() -> list[str]:
    enums = _enums()
    kinds = ", ".join(enums.get("context_kind", []))
    out = [("Project context: review_start.context or review_add_context ingest the project's own documents beside"
            " the code so declared facts can be read, quoted and compared with the code and the chain.")]
    out.append("Step 1 (before reading code): ask the user for the project website, whitepaper, documentation,"
                " terms of use, and privacy policy URLs, then pass them via review_add_context."
                " Spec-vs-code issues (README, docs, whitepaper claims that the code contradicts)"
                " cannot be detected without these documents. Skipping this step means the report will say"
                " 'No project documents were supplied' and any documentation mismatch goes unreported.")
    out.append(f"Kinds: {kinds}. Items are {{kind, url}} (https, named host, no credentials) or {{kind, path, content}}"
               " for inline text; at most 12 documents per job, 8 per call; the same URL again returns the existing"
               " document. Fetching runs after the code and never delays ready; review_status reports context"
               " {requested, done, failed}; a document that fails is reported per item (E_CONTEXT_FETCH), never as a"
               " job error.")
    out.append("Reading: documents are pinned as context/<kind>-<n>.md, readable with review_read_code and searchable"
               " with review_search_code (path_glob context/*). Every stored text starts with a six-line provenance"
               " header (title, source, retrieved, sha256, kind, blank), so a quote of the header is a provenance"
               " quote. review_contract_map ignores documents.")
    out.append("Quoting: a quote with role context cites a context/ path with exact stored lines in review_submit_finding"
               " and in challenge answers; a context quote never counts as a location quote, and a location quote may"
               " not cite a context/ path.")
    out.append("Facts: review_facts (filter context.) lists deterministic context.<kind>.* records, each with its source"
               " line: addresses, mentions_reviewed_address, total_supply, max_supply, decimals, fee_pct, chains,"
               " admin_claims, audit_claims, terms.restricted_jurisdictions, terms.kyc, privacy.data_collected,"
               " privacy.contact. A {{fact:context.*}} placeholder in text carries that source; the report prints"
               " declared values next to what the code and the chain show (matches, differs, not_checkable).")
    out.append("Prose: review_set_section(section=context_notes) is the only free-text place for the documents (model"
               " blocks, same text rules as roles_notes, at most 8 blocks).")
    return out


def _topic_checklist(family: str) -> list[str]:
    doc = _checklist(family)
    if doc is None:
        return [f"No checklist file for family {family}."]
    out = [f"Disproof checklist, family {family}. Items the challenge asks per category (kind, condition)."]
    generic = doc.get("generic_items") or []
    if generic:
        out.append("generic (every category marked generic):")
        for item in generic:
            out.append(f"  {item.get('id')}  {item.get('kind')}  {item.get('condition')}")
    for cat_id, cat in (doc.get("categories") or {}).items():
        out.append(f"{cat_id}:")
        for item in cat.get("items") or []:
            na = f"  n/a {', '.join(item['na'])}" if item.get("na") else ""
            out.append(f"  {item.get('id')}  {item.get('kind')}  {item.get('condition')}{na}")
    return out


@handler("review_get_guide")
async def _get_guide(args: dict[str, Any]) -> str:
    topic: str = args["topic"]
    chain: str | None = args.get("chain")
    if chain is None and args.get("job_id"):
        chain = _job_chain(args["job_id"])
    family = _family_for(chain)
    if topic == "categories":
        body = _topic_categories(family)
    elif topic == "severity_inputs":
        body = _topic_severity_inputs()
    elif topic == "challenge_rules":
        body = _topic_challenge_rules()
    elif topic == "checklist":
        body = _topic_checklist(family)
    elif topic == "context":
        body = _topic_context()
    else:  # the input schema already enumerates topics; keep the error shape consistent
        raise ReviewError("E_INVALID_ARGUMENT", field="topic", rule="enum", value80=topic[:80],
                          example="one of checklist, categories, severity_inputs, challenge_rules, context")
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
