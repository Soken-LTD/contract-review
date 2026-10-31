"""`assemble_report(job_id)` (08 3.1): report.json from a finalized job, server fields only.

Reads the pin store, the job work dir (candidates, chain state, build result), `leads.json`,
the finding, challenge, section and read tables. Every printed number is recomputed from rows
here (08 3.1 step 5). Model strings stay in placeholder form; `{{finding:key}}` is replaced by
the final id because report.json has no draft-key map (W0 finding). `project()` at build is the
only place facts expand (08 2.4); every finding prints as is under every profile.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from ..adapters.evm.build_scope import subject_unit
from ..adapters.evm.registry import get_chain
from ..adapters.evm.units import count_nsloc
from ..engine.severity import explain_rules
from ..learning import tiers as rule_tiers
from ..mapping.build import load_map
from ..mapping.build_note import job_build_failure
from ..mapping.facts import load_facts
from ..mapping.lifecycle import load_lifecycle
from ..mapping.related import load_related_contracts
from ..pinning.store import PinnedSource
from .architecture import architecture_block, role_rows
from .kit.build import SEV_PREFIX, SEVS, build_date_text, check_strings, counts, kit_texts, out_name, validate

REPO = Path(__file__).resolve().parents[3]
RUBRIC = REPO / "contract" / "rubric"
LIMITS = REPO / "contract" / "ops" / "limits.yaml"

ROLE_LABELS = {"owner": "Code owner or its team", "authorized": "Party authorized by the code owner",
               "third_party_public_code": "Third party reviewing public code"}
QUOTE_ROLE_ORDER = ["location", "bound_ref", "role_path", "context"]
SEV_RANK = {s: i for i, s in enumerate(SEVS)}
LEAD_SEV = {"Critical": "Critical", "High": "High", "Medium": "Medium", "Low": "Low", "Info": "Informational"}
MAX_LINE = 2000
# Category label words that are not plain title case (08 2.3 category label; enums.yaml has ids only).
_LABEL_WORDS = {"dos": "DoS", "mev": "MEV", "evm": "EVM", "pda": "PDA", "cpi": "CPI", "ata": "ATA", "tron": "TRON",
                "hyperevm": "HyperEVM", "corewriter": "CoreWriter"}


class AssemblyError(Exception):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code, self.detail = code, detail


def category_label(cat: str) -> str:
    """Readable label of an enums.yaml id: family dropped, words title-cased (e.g. `evm.dos` -> DoS)."""
    parts = cat.split(".")[1:] or [cat]
    words = " ".join(parts).replace("_", " ").split()
    out = [_LABEL_WORDS.get(w, w) for w in words]
    label = " ".join(out)
    return (label[:1].upper() + label[1:])[:60]


def _enums() -> list[dict[str, Any]]:
    return yaml.safe_load((RUBRIC / "enums.yaml").read_text(encoding="utf-8"))["categories"]


def coverage_categories(family: str, chain: str | None) -> list[dict[str, Any]]:
    """Checklist areas of a family (04 coverage rows): server-only categories excluded."""
    out = []
    for c in _enums():
        if c["family"] != family or c.get("server_only"):
            continue
        if c.get("chains") and chain not in c["chains"]:
            continue
        out.append(c)
    return out[:60]


def date_text(d: date) -> str:
    return build_date_text(d)


def _limits() -> dict[str, Any]:
    return yaml.safe_load(LIMITS.read_text(encoding="utf-8"))


# ------------------------------------------------------------------ subject chain (08 2.6)
def subject_candidates(job: dict[str, Any], cands: list[dict[str, Any]], pin: PinnedSource) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    repo = _repo_url(job)
    commit = job.get("resolved_commit")
    address = job.get("address")
    proven_by_repo = bool(job.get("ownership_proven") and repo and not address)
    if address and cands and cands[0].get("entry_contract") and not proven_by_repo:
        out.append({"source": "verified_name", "value": cands[0]["entry_contract"].rsplit(":", 1)[-1]})
    if repo:
        name = _project_name(repo.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git"))
        owner_repo = "/".join(repo.rstrip("/").split("/")[-2:]).removesuffix(".git")
        if not proven_by_repo:
            out.append({"source": "repo_name", "value": name})
        if commit:
            out.append({"source": "repo_at_commit", "value": f"{owner_repo}@{commit[:7]}"})
    if address:
        out.append({"source": "address_short", "value": f"{address[:8]}...{address[-6:]}"})
    scoped = [e for e in pin.entries.values() if e.in_scope] or list(pin.entries.values())
    if not address and scoped:
        # the main deployable contract of the scope, never a vendored library or interface file
        # (Lambo.win 2026-10-27: the largest file, 1inchV6.sol, became the subject); the largest
        # file only when no file defines a deployable contract
        unit = subject_unit({e.path: pin.read_text(e.path) for e in scoped if e.role == "source"})
        largest = unit or max(scoped, key=lambda e: e.lines).path
        out.append({"source": "largest_unit", "value": Path(largest).stem})
    out.append({"source": "kit_fallback", "value": kit_texts()["subject_fallback"]})
    return out


_CONTEST_DATE_PREFIX = re.compile(r"^(?:19|20)\d{2}-(?:0[1-9]|1[0-2])-(?=[A-Za-z])")


def _project_name(repo_name: str) -> str:
    """Project name of a repository name: an audit-contest date prefix (`2024-12-lambowin`, the
    code-423n4 and Sherlock naming) is dropped; anything else is the name as written."""
    return _CONTEST_DATE_PREFIX.sub("", repo_name) or repo_name


def pick_subject(candidates: list[dict[str, str]]) -> dict[str, str]:
    """First candidate that passes the 04 gate in scopes server and subject, max 60 chars."""
    from ..engine.text_gate import check_text

    for c in candidates:
        v = c["value"]
        if len(v) > 60 or not v.strip():
            continue
        if check_text(v, "server") or check_text(v, "subject"):
            continue
        return c
    return candidates[-1]


# ------------------------------------------------------------------ provenance helpers
def _bytecode_hash(chain_state: dict[str, Any] | None) -> str | None:
    """sha256 of the on-chain runtime bytes stored in chain_state['bytecode'].

    Returns 'sha256:<hexdigest>' or None when bytecode is absent.
    """
    if chain_state is None:
        return None
    raw_hex = (chain_state.get("bytecode") or "").removeprefix("0x")
    if not raw_hex:
        return None
    try:
        raw_bytes = bytes.fromhex(raw_hex)
    except ValueError:
        return None
    return "sha256:" + hashlib.sha256(raw_bytes).hexdigest()


_PIN_UNITS = frozenset({"block", "slot", "seqno"})


def _tier_a_unit(chain_state: dict[str, Any] | None, deployment: dict[str, Any] | None) -> str:
    """Pin-counting unit name for the tier A label and the verification table: the `unit` the
    family pipeline wrote in deployment.json (Solana 'slot', TON 'seqno'), else 'block' (EVM,
    HyperEVM, TRON, whose supervisor path writes no unit)."""
    unit = (deployment or {}).get("unit")
    return unit if unit in _PIN_UNITS else "block"


def _deployed_code_hash(chain_state: dict[str, Any] | None, deployment: dict[str, Any] | None) -> str | None:
    """On-chain code hash for the cover: sha256 of the EVM runtime in chain_state, else the hash the
    family pipeline recorded in deployment.json (TON code cell hash, Solana F5 program hash)."""
    from_state = _bytecode_hash(chain_state)
    if from_state:
        return from_state
    recorded = (deployment or {}).get("code_hash")
    return str(recorded)[:130] if recorded else None


# meta.chain values outside the EVM registry (report schema enum); `job.chain` holds them as is.
_NON_EVM_CHAINS = frozenset({"solana", "ton", "sui", "aptos", "starknet"})
_CHAIN_NETWORK = {"solana": "Solana mainnet", "ton": "TON mainnet", "sui": "Sui mainnet",
                  "aptos": "Aptos mainnet", "starknet": "Starknet mainnet"}
_DEPLOYED_NOUN = {"solana": "program", "sui": "package", "aptos": "package"}
# report chain -> checklist family (enums.yaml `family`), as tools/submit._family_from_chain
_CHAIN_FAMILY = {"solana": "solana", "ton": "ton", "sui": "move", "aptos": "move", "starknet": "cairo"}


# Families with one mainnet: a deployed job started as `chain: tron` carries no chain id (the
# address alone names the network), so the registry record is found through the family.
_FAMILY_MAINNET_CHAIN_ID = {"tron": 728126428}
_EVM_FAMILY_CHAINS = frozenset({"hyperevm", "tron"})


def _job_chain_id(job: dict[str, Any], chain_state: dict[str, Any] | None = None) -> int | str | None:
    """Chain id of the reviewed deployment: chain_state, then the job row, then the family mainnet
    for a deployed job of a one-mainnet family (TRON, matrix run 2026-10-26: `chain: evm`,
    `network: Not deployed` printed for a TRON mainnet address)."""
    chain_id = (chain_state or {}).get("chain_id") or job.get("chain_id")
    if chain_id is None and job.get("address"):
        chain_id = _FAMILY_MAINNET_CHAIN_ID.get(str(job.get("chain") or ""))
    return chain_id


def _report_chain(job: dict[str, Any]) -> str:
    """meta.chain: the registry family for EVM chain ids (evm, hyperevm, tron), else the job chain
    when it is a report chain (solana, ton, tron, ...), else evm."""
    chain_id = _job_chain_id(job)
    rec = get_chain(int(chain_id)) if chain_id is not None else None
    if rec is not None:
        fam = getattr(rec, "family", "evm")
        return fam if fam in _EVM_FAMILY_CHAINS else "evm"
    chain = str(job.get("chain") or "")
    return chain if chain in _NON_EVM_CHAINS or chain in _EVM_FAMILY_CHAINS else "evm"


# Cover line for a job started without a deployment: a scope statement, not a finding about the
# code (matrix run 2026-10-27, 1inch repo job: "Chain and network: Not deployed" read as a defect).
NO_DEPLOYMENT_LABEL = "No deployment given; source review only"
SOLANA_CONFIG_CLUSTER_LABEL = "Program id for {cluster} in Anchor.toml; not on mainnet"
SOLANA_CONFIG_CLUSTER_UNCHECKED_LABEL = "Program id for {cluster} in Anchor.toml; mainnet not checked"
SOLANA_NOT_ON_MAINNET_LABEL = "Program id not deployed on Solana mainnet"
SOLANA_MAINNET_UNCHECKED_LABEL = "Solana mainnet; deployment not checked"


def _network_label(job: dict[str, Any], chain_state: dict[str, Any] | None,
                   deployment: dict[str, Any] | None) -> str:
    """Server text for meta.network and the verification table: registry name and id for EVM
    chains; the chain's mainnet for a deployed non-EVM unit; the no-deployment scope line without
    an address."""
    chain_id = _job_chain_id(job, chain_state)
    rec = get_chain(int(chain_id)) if chain_id is not None else None
    if rec is not None:
        return f"{rec.name} ({chain_id})"[:60]
    if chain_id:
        return str(chain_id)[:60]
    chain = str((deployment or {}).get("chain") or job.get("chain") or "")
    if job.get("address") and chain == "solana":
        # The label comes from the supervisor's mainnet read, never from repository config alone.
        # Pump Science blind run 2026-10-27: an id with no program on mainnet printed as "Solana
        # mainnet". MetaDAO blind run 2026-10-31: the supplied mainnet id, live on mainnet, printed as
        # "not mainnet" because Anchor.toml also listed it under [programs.localnet].
        cs = chain_state or {}
        clusters = [str(c) for c in cs.get("config_clusters") or []]
        other = clusters[0] if clusters and "mainnet" not in clusters else None
        why = str(cs.get("why") or "")
        if cs.get("kind") == "mint" or cs.get("deployed_program_hash") or (cs.get("loader") and not why.startswith("read_failed")
                                                and why != "no_code"):
            return _CHAIN_NETWORK["solana"]          # a program account exists at the id on mainnet
        if why == "no_code":
            return (SOLANA_CONFIG_CLUSTER_LABEL.format(cluster=other) if other else SOLANA_NOT_ON_MAINNET_LABEL)[:60]
        # no read, or the read failed: say so instead of guessing either way
        return (SOLANA_CONFIG_CLUSTER_UNCHECKED_LABEL.format(cluster=other) if other
                else SOLANA_MAINNET_UNCHECKED_LABEL)[:60]
    if job.get("address") and chain in _CHAIN_NETWORK:
        return _CHAIN_NETWORK[chain]
    return NO_DEPLOYMENT_LABEL


def _source_id_label(prov: dict[str, Any], chain: str) -> str:
    """Label of the hash the cover prints under the source line: the label names the value that
    follows it. With a deployed code hash it is the bytecode hash (code hash on non-EVM chains);
    otherwise the value is the source pin, a sha256 over the pinned files, and the label says so.
    Matrix run 2026-10-27 (1inch repo job): the 64-hex source pin printed under "Commit", directly
    below the real commit."""
    if prov.get("code_hash"):
        return "Bytecode hash" if chain in ("evm", "hyperevm", "tron") else "Code hash"
    return "Files sha256"


_ADDR_URL_RE = re.compile(r"^https://[^\s\"'<>]*\{a\}[^\s\"'<>]*$")   # report schema meta.addr_url


def _addr_url(rec: Any) -> str | None:
    """Explorer address template of a registry record in the report's `{a}` form; None when the
    record has none or its template does not fit the schema (addresses then print as plain
    monospace). chains.json writes the TRON template with `{address}`."""
    template = getattr(rec, "addr_url", None) if rec else None
    if not template:
        return None
    template = str(template).replace("{address}", "{a}")
    return template if _ADDR_URL_RE.fullmatch(template) else None


def _repo_url(job: dict[str, Any]) -> str | None:
    """Repository URL of a repo job from `source_args` (`repo_url`, the key review_start stores;
    `repo` accepted for older rows). Apyee blind run 2026-10-26: the cover printed the
    requester-supplied label for a public GitHub commit because only `repo` was read."""
    args = job.get("source_args") or {}
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except ValueError:
            args = {}
    if not isinstance(args, dict):
        return None
    url = args.get("repo_url") or args.get("repo")
    return str(url)[:200] if url else None


def _dep_reason_text(code: Any) -> str | None:
    """Kit text for a dep.match reason code (dep_match.yaml, 06 2.5 codes in either case); an
    unknown code prints as plain words, never as the bare enum."""
    key = str(code or "").strip().lower()
    if not key or not _ENUM_TOKEN.fullmatch(key):
        return None
    labels = kit_texts()["dep_match_reasons"]
    return labels.get(key) or labels["other"].format(code=key.replace("_", " "))


_OUT_OF_SCOPE_MAX = 40   # report schema scope.out_of_scope maxItems


def scope_excluded_rows(cands: list[dict[str, Any]], budget: int = _OUT_OF_SCOPE_MAX) -> list[dict[str, Any]]:
    """Out-of-scope rows for the files the scope rules excluded from the reviewed candidate
    (`scope_excluded` in candidates.json: test and mock contracts), reason from the kit. The
    disclosure is never silently cut: when the rows exceed `budget`, the last row states how
    many more files were excluded."""
    labels = kit_texts()["scope_reasons"]
    rows: list[dict[str, Any]] = []
    for item in ((cands[0].get("scope_excluded") if cands else None) or []):
        if not isinstance(item, dict) or not item.get("path"):
            continue
        rows.append({"path": str(item["path"])[:300], "reason": labels.get(str(item.get("reason") or ""))
                     or labels["other"], "by": "server"})
    budget = max(1, budget)
    if len(rows) > budget:
        shown = rows[:budget - 1]
        shown.append({"path": labels["more_path"], "reason": labels["more"].format(n=len(rows) - len(shown)),
                      "by": "server"})
        return shown
    return rows


def _pin_date_text(chain_state: dict[str, Any] | None, today: date) -> str:
    """Human date of the chain-state pin.  chain_state may carry a pre-formatted 'date_text'
    (e.g. from a future supervisor version); otherwise fall back to the assembly date."""
    if chain_state and chain_state.get("date_text"):
        return chain_state["date_text"]
    return build_date_text(today)


# ------------------------------------------------------------------ verification blocks (08 plan K3 part 08)
_ENUM_TOKEN = re.compile(r"^[a-z][a-z0-9_]{0,63}$")   # enum codes allowed as server text


def _build_verification_blocks(
    deployment: dict[str, Any],
    chain_state: dict[str, Any] | None,
    job: dict[str, Any],
) -> list[dict[str, Any]]:
    """Build the list of server_block items for the report's 'verification' field.

    Reads only from deployment.json (written by the supervisor) and chain_state.json.
    All cells are server_cell form: strings, integers, or {'addr': ...} objects.
    Returns at most 6 blocks as required by the schema.
    """
    dep = deployment.get("dep") or {}
    comparison = dep.get("comparison") or {}
    address = (chain_state or {}).get("address") or job.get("address") or ""
    block = deployment.get("block") or (chain_state or {}).get("block")
    code_hash = _deployed_code_hash(chain_state, deployment) or ""
    unit_label = {"block": "Block", "slot": "Slot", "seqno": "Masterchain seqno"}[_tier_a_unit(chain_state, deployment)]
    entry_contract_full = dep.get("contract") or ""
    # Shorten "File.sol:ContractName" to just the contract name for display
    entry_contract = entry_contract_full.rsplit(":", 1)[-1] if ":" in entry_contract_full else entry_contract_full

    # Chain / network label
    network = _network_label(job, chain_state, deployment)

    blocks: list[dict[str, Any]] = []

    # Table 1: Deployment — address, chain/network, block, on-chain code hash, entry contract
    dep_rows: list[list[Any]] = []
    proxy = (chain_state or {}).get("proxy") or {}
    impl = str(proxy.get("implementation") or "")
    if address:
        dep_rows.append(["Proxy address" if impl else "Address", {"addr": address}])
    if impl and _ADDR_OK.match(impl):
        # one job for a proxy: the implementation source was rebuilt and compared; state was read
        # at the proxy address above
        if re.fullmatch(r"[a-z0-9_]{1,40}", str(proxy.get("pattern_name") or "")):
            dep_rows.append(["Proxy pattern", str(proxy["pattern_name"])])
        dep_rows.append(["Implementation", {"addr": impl}])
        for label, key in (("Proxy admin", "admin"), ("Beacon", "beacon")):
            if proxy.get(key) and _ADDR_OK.match(str(proxy[key])):
                dep_rows.append([label, {"addr": str(proxy[key])}])
    dep_rows.append(["Chain / network", network])
    if block is not None:
        dep_rows.append([unit_label, int(block)])
    if code_hash:
        dep_rows.append(["Implementation code hash" if impl else "On-chain code hash", code_hash])
    if entry_contract:
        # Contract names come from the source tree: a `src` cell, never server text (text classes).
        dep_rows.append(["Entry contract", {"src": entry_contract[:300]}])
    for lib in (deployment.get("library_refs") or [])[:4]:
        # TON: a masterchain library the code references by hash (multisig v2 order code)
        if not isinstance(lib, dict) or not lib.get("hash"):
            continue
        state = "read from the chain" if lib.get("status") == "ok" else "not found on the chain"
        src = ("source verified on verifier.ton.org" if lib.get("verified_source")
               else "its source is not part of this review")
        dep_rows.append(["Library reference", f"{str(lib['hash'])[:64]} ({state}; {src})"])
    if dep_rows:
        blocks.append({"table": {"head": ["Field", "Value"], "rows": dep_rows}})

    # Table 2: Runtime comparison — outcome, lengths, masked bytes, differing bytes, auxdata source
    cmp_rows: list[list[Any]] = []
    outcome = dep.get("match") or comparison.get("outcome") or ""
    if outcome and _ENUM_TOKEN.fullmatch(str(outcome)):
        cmp_rows.append(["Outcome", str(outcome)])
    local_len = comparison.get("local_len")
    if local_len is not None:
        cmp_rows.append(["Local length", int(local_len)])
    onchain_len = comparison.get("onchain_len")
    if onchain_len is not None:
        cmp_rows.append(["On-chain length", int(onchain_len)])
    masked = comparison.get("masked_bytes") or {}
    if masked.get("immutables") is not None:
        cmp_rows.append(["Masked bytes (immutables)", int(masked["immutables"])])
    if masked.get("links") is not None:
        cmp_rows.append(["Masked bytes (links)", int(masked["links"])])
    if masked.get("auxdata") is not None:
        cmp_rows.append(["Masked bytes (auxdata)", int(masked["auxdata"])])
    differing_bytes = comparison.get("differing_bytes")
    if differing_bytes is not None:
        cmp_rows.append(["Differing bytes", int(differing_bytes)])
    auxdata_source = comparison.get("auxdata_source")
    if auxdata_source and _ENUM_TOKEN.fullmatch(str(auxdata_source)):
        cmp_rows.append(["Auxdata source", str(auxdata_source)])
    if cmp_rows:
        blocks.append({"table": {"head": ["Field", "Value"], "rows": cmp_rows}})

    # Table 3: Linked libraries (only when present)
    libraries = comparison.get("linked_libraries") or {}
    if libraries:
        # Library names are source identifiers (src cells); addresses are addr cells.
        lib_rows = [[{"src": str(name)[:300]}, {"addr": addr}] for name, addr in sorted(libraries.items())][:20]
        blocks.append({"table": {"head": ["Library", "Address"], "rows": lib_rows}})

    # Paragraph: the dep.match reason code (an enum from rubric/dep_match.yaml) printed as the
    # kit text for that code (matrix run 2026-10-26: the TON cover showed `match_rebuild`). The
    # free-text comparison detail is build-influenced and never enters a server paragraph.
    reason_text = _dep_reason_text(dep.get("reason"))
    if reason_text:
        blocks.append({"p": reason_text})

    return blocks[:6]


# ------------------------------------------------------------------ provenance (08 1.4 label_key)
_ADDR_OK = re.compile(r"^[0-9A-Za-z:_.-]{20,130}$")


def provenance(
    job: dict[str, Any],
    cands: list[dict[str, Any]],
    chain_state: dict[str, Any] | None,
    deployment: dict[str, Any] | None = None,
    *,
    today: date | None = None,
    related: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """`_provenance_tier` plus the proxy and related-contract lines of the cover: the deployed
    address is a proxy (implementation reviewed, state read at the proxy) and the related
    contracts pinned in the same job (adapters/evm/related_sources)."""
    prov = _provenance_tier(job, cands, chain_state, deployment, today=today)
    proxy = (chain_state or {}).get("proxy") or {}
    impl = str(proxy.get("implementation") or "")
    if impl and _ADDR_OK.match(impl):
        prov["implementation"] = impl
        prov["upgradeable"] = True
        pattern = str(proxy.get("pattern_name") or "")
        if re.fullmatch(r"[a-z0-9_]{1,40}", pattern):
            prov["proxy_pattern"] = pattern
        admin = str(proxy.get("admin") or "")
        if prov["tier"] == "A" and admin and _ADDR_OK.match(admin):
            # the EIP-1967 admin slot read at the pinned block: on-chain evidence of who upgrades
            prov["upgrade_authority"] = {"addr": admin}
    rows = [{"name": str(r["name"]), "address": str(r["address"]), "status": str(r["status"])}
            for r in (related or []) if isinstance(r, dict) and r.get("role") != "proxy"
            and re.fullmatch(r"[A-Za-z0-9_-]{1,40}", str(r.get("name") or ""))
            and _ADDR_OK.match(str(r.get("address") or ""))
            and r.get("status") in ("pinned", "no_code", "no_verified_source", "fetch_failed")]
    if rows:
        prov["related"] = rows[:6]
    return prov


def _provenance_tier(
    job: dict[str, Any],
    cands: list[dict[str, Any]],
    chain_state: dict[str, Any] | None,
    deployment: dict[str, Any] | None = None,
    *,
    today: date | None = None,
) -> dict[str, Any]:
    """Build the provenance sub-object for a finalized job.

    For tier A and C the deployment dict (deployment.json written by the supervisor) is
    required; for tier B it is ignored.  `today` defaults to UTC today and is used only
    when chain_state has no pre-formatted date_text.
    """
    t = kit_texts()["tier_labels"]
    tier = job.get("tier")
    address = job.get("address")
    repo = _repo_url(job)
    cand = cands[0] if cands else {}
    _today = today or datetime.now(UTC).date()

    if tier == "A":
        if deployment is None:
            raise AssemblyError("schema", "tier A provenance requires deployment.json data")
        block = deployment.get("block") or (chain_state or {}).get("block")
        unit = _tier_a_unit(chain_state, deployment)
        date_str = _pin_date_text(chain_state, _today)
        label = t["tier_a"].format(unit=unit, n=block, date=date_str)
        code_hash = _deployed_code_hash(chain_state, deployment)
        if not code_hash:
            # The schema requires the on-chain code hash on a tier A cover; a pipeline that matched
            # a rebuild without recording the deployed hash is a server defect, named as such.
            raise AssemblyError("schema", "tier A provenance requires the deployed code hash "
                                          "(chain_state bytecode or deployment.json code_hash)")
        as_of = {"block_or_slot": int(block) if block is not None else 0, "date": date_str}
        prov: dict[str, Any] = {
            "tier": "A",
            "label": label,
            "label_key": "tier_a",
            "source_hash": job["source_pin"],
            "address": address,
            "code_hash": code_hash,
            "as_of": as_of,
            # Stated only from on-chain evidence; the EVM artifacts carry none today, so the cover
            # prints the kit "not checked" text rather than a claim the review did not make.
            "upgrade_authority": "NotChecked",
        }
        if repo:
            prov["repo"] = repo
            if job.get("resolved_commit"):
                prov["commit"] = job["resolved_commit"]
        return prov

    if tier == "C":
        if deployment is None:
            raise AssemblyError("schema", "tier C provenance requires deployment.json data")
        code_hash = _deployed_code_hash(chain_state, deployment)
        prov = {
            "tier": "C",
            "label": t["tier_c"],
            "label_key": "tier_c",
            "source_hash": job["source_pin"],
        }
        if address:
            prov["address"] = address
        if code_hash:
            prov["code_hash"] = code_hash
        if repo:
            prov["repo"] = repo
            if job.get("resolved_commit"):
                prov["commit"] = job["resolved_commit"]
        return prov

    # Tier B (default): the label names the real source kind. Deployed address with explorer or
    # Sourcify source: third party; deployed address with other source: not checked; repository
    # at a resolved commit: commit; anything else (upload, inline files): supplied by the requester.
    if address and (deployment or {}).get("unlinked_reason"):
        # TON SOURCE_UNLINKED: the requester's source was reviewed, the deployment was not matched
        # to it; the cover says so in words (security review 2026-10-27), not only the method row.
        key = "tier_b_unmatched"
    elif address:
        third = bool(cand.get("explorer_verified") or cand.get("sourcify_match"))
        key = "tier_b_third_party" if third else "tier_b_not_checked"
    elif repo and job.get("resolved_commit"):
        key = "tier_b_commit"
    else:
        key = "tier_b_files"
    label = t[key].format(commit=(job.get("resolved_commit") or "")[:12])
    prov = {"tier": "B", "label": label, "label_key": key, "source_hash": job["source_pin"]}
    if address:
        prov["address"] = address
    if repo:
        prov["repo"] = repo
        if job.get("resolved_commit"):
            prov["commit"] = job["resolved_commit"]
    return prov


# ------------------------------------------------------------------ helpers
def _ref(path: str, start: int, end: int) -> dict[str, Any]:
    return {"path": path, "start": int(start), "end": int(max(start, end))}


def _parse_ref(s: str) -> dict[str, Any]:
    m = re.match(r"^(.+):(\d+)(?:-(\d+))?$", s)
    if not m:
        raise AssemblyError("schema", f"bad code ref {s!r}")
    return _ref(m[1], int(m[2]), int(m[3] or m[2]))


def _code_block(pin: Any, path: str, start: int, end: int, cap: int) -> dict[str, Any]:
    """`pin` is the code pin or, for `context/` paths, the context store (same read API)."""
    end = min(end, start + cap - 1, pin.line_count(path))
    lines = pin.read_lines(path, start, end)
    return {"code": {"ref": _ref(path, start, end),
                     "lines": [[start + i, line[:MAX_LINE]] for i, line in enumerate(lines)]}}


def _quote_source(pin: PinnedSource, ctx_store: Any | None, path: str) -> Any:
    """Quotes with a `context/` path (role `context`) read from the context store; the render
    step crashed with KeyError 'context/docs-1.md' when the first such quote reached the pin
    (2026-10-23)."""
    if path.startswith("context/"):
        if ctx_store is None or not ctx_store.has_path(path):
            raise AssemblyError("schema", f"context quote {path} has no stored document")
        return ctx_store
    return pin


def _unit_of(path: str) -> str:
    return Path(path).stem or path


def _sub_findings(obj: Any, keymap: dict[str, str]) -> Any:
    if isinstance(obj, str):
        def rep(m: re.Match) -> str:
            if m[1] not in keymap:
                raise AssemblyError("schema", f"finding placeholder {m[1]} has no final id")
            return keymap[m[1]]
        return re.sub(r"\{\{finding:([a-z0-9][a-z0-9-]{2,47})\}\}", rep, obj)
    if isinstance(obj, list):
        return [_sub_findings(x, keymap) for x in obj]
    if isinstance(obj, dict):
        return {k: _sub_findings(v, keymap) for k, v in obj.items()}
    return obj


def _model_blocks(blocks: list[Any]) -> list[dict[str, Any]]:
    """finding.v1 blocks to report model blocks (p, ul, table); others are rejected."""
    out = []
    for b in blocks:
        if "p" in b or "ul" in b or "table" in b:
            out.append({k: b[k] for k in ("p", "ul", "table") if k in b})
        else:
            raise AssemblyError("schema", f"unknown body block {sorted(b)}")
    return out


async def _rows(conn: Any, sql: str, params: tuple) -> list[dict[str, Any]]:
    from psycopg.rows import dict_row

    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(sql, params)
        return list(await cur.fetchall())


# ------------------------------------------------------------------ related contracts (feat/context-related-state)

_ADDR_SHORT_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_UNVERIFIED_NOTE = "Source not verified; behaviour cannot be checked."


def _short_addr_related(addr: str) -> str:
    """Shorten an address for the related contracts table: ``0xABCD...1234`` (14 chars)."""
    if _ADDR_SHORT_RE.match(addr):
        return f"{addr[:6]}...{addr[-4:]}"
    return addr[:20]


def _kind_label(entry: dict[str, Any]) -> str:
    k = entry.get("kind", "unknown")
    return {"eoa": "EOA", "multisig": "Multisig", "contract": "Contract"}.get(k, "Unknown")


def _verified_label(entry: dict[str, Any]) -> str:
    v = entry.get("verified")
    if v is True:
        return "Verified"
    if v is False:
        return "Unverified"
    return "Unknown"


def _related_note(entry: dict[str, Any], verified_label: str) -> str | None:
    """Build a server note for the related contract row."""
    parts: list[str] = []
    # Unverified notice first (security-relevant; auditor must see it)
    if verified_label == "Unverified":
        parts.append(_UNVERIFIED_NOTE)
    kind = entry.get("kind")
    if kind == "multisig":
        owners = entry.get("owners_count")
        threshold = entry.get("threshold")
        if threshold is not None and owners is not None:
            parts.append(f"{threshold}-of-{owners} Safe.")
    delay = entry.get("min_delay_s")
    if delay is not None and delay > 0:
        h = delay // 3600
        parts.append(f"Min delay {h} h." if h else f"Min delay {delay} s.")
    combined = " ".join(parts)
    return combined[:120] if combined else None


def related_contract_rows(
    pin_root: Path,
    job_id: str,
) -> list[dict[str, Any]]:
    """Build ``roles.related_contracts`` rows from the pin-root related_contracts.json.

    Unverified entries sort first so reviewers see the highest-risk rows at the top.
    Empty list when the file is absent or contains no entries.
    """
    entries = load_related_contracts(pin_root, job_id)
    if not entries:
        return []
    rows = []
    for entry in entries:
        addr = entry.get("address") or ""
        label = entry.get("role") or entry.get("name") or "?"
        kind_label = _kind_label(entry)
        verified_label = _verified_label(entry)
        note = _related_note(entry, verified_label)
        row: dict[str, Any] = {
            "label": label[:80],
            "address": _short_addr_related(addr),
            "kind": kind_label,
            "verified": verified_label,
        }
        if note:
            row["note"] = note
        rows.append(row)
    # Unverified first, then Unknown, then Verified; within each group preserve original order
    _order = {"Unverified": 0, "Unknown": 1, "Verified": 2}
    rows.sort(key=lambda r: _order.get(r["verified"], 1))
    return rows[:20]


def _roles_related(pin_root: Path, job_id: str) -> dict[str, Any]:
    """Return ``{"related_contracts": rows}`` or ``{}`` when there are no related contracts.

    The empty-dict branch means the roles dict never gains a ``related_contracts: []`` key
    when there is nothing to show, keeping the JSON diff-clean and matching the optional
    schema field.
    """
    rows = related_contract_rows(pin_root, job_id)
    if rows:
        return {"related_contracts": rows}
    return {}


def _json(path: Path, default: Any) -> Any:
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else default


# ------------------------------------------------------------------ project context (context ingestion spec 4 to 7)
CONTEXT_KINDS = ("whitepaper", "website", "app", "docs", "terms", "privacy", "other")
CONTEXT_STATUSES = ("matches", "differs", "not_checkable")
CONTEXT_FACT_PREFIX = "context."
MAX_CONTEXT_DOCS, MAX_CONTEXT_ROWS, MAX_CONTEXT_NOTES = 12, 40, 8
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def context_store(pin_root: Path, job_id: str) -> Any | None:
    """Coupling point 1 (spec 4): `soken_review.context.store.ContextStore.load(pin_root, job_id)`.

    The module ships with the context-core branch. No module, or no manifest for the job, means no
    documents (the section prints its empty line). Anything else is an error and surfaces."""
    try:
        from ..context.store import ContextStore
    except ImportError:
        return None
    try:
        return ContextStore.load(pin_root, job_id)
    except FileNotFoundError:
        return None


def context_compare(facts: list[dict[str, Any]], map_doc: dict[str, Any] | None, job: dict[str, Any]) -> list[dict[str, Any]]:
    """Coupling point 2 (spec 6): `soken_review.context.compare.compare(facts, map_doc, job)`, pure.

    `facts` is the whole facts.json list (the comparison reads `context.*` next to `onchain.*`)."""
    try:
        from ..context.compare import compare
    except ImportError:
        return []
    return list(compare(facts, map_doc, job))


def _src_text(value: Any, cap: int) -> str:
    """Document-derived text as a SRC cell: control characters out, length capped; lists joined."""
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        value = ", ".join(str(v) for v in value)
    return _CTRL_RE.sub(" ", str(value)).strip()[:cap]


def _retrieved_date(fetched_at: Any, today: date) -> date:
    if isinstance(fetched_at, str) and fetched_at:
        try:
            return datetime.fromisoformat(fetched_at).date()
        except ValueError:
            pass
    return today


def context_documents(entries: list[dict[str, Any]], today: date) -> list[dict[str, Any]]:
    """Documents table rows (spec 7) from manifest entries (spec 4), in manifest order, max 12."""
    rows = []
    for e in entries[:MAX_CONTEXT_DOCS]:
        kind = e.get("kind") if e.get("kind") in CONTEXT_KINDS else "other"
        url = e.get("final_url") or e.get("url") or ""
        host = (urlsplit(url).hostname or "") if url else ""
        sha = str(e.get("sha256_raw") or "")[:12]
        rows.append({"kind": kind, "title": _src_text(e.get("title"), 200), "host": _src_text(host, 253),
                     "retrieved": build_date_text(_retrieved_date(e.get("fetched_at"), today)),
                     "sha256_short": sha if re.fullmatch(r"[0-9a-f]{12}", sha) else "",
                     "status": "ok" if e.get("status") == "ok" else "failed"})
    return rows


_NOT_TAKEN_KINDS = frozenset({"leads_not_triaged", "challenge_not_answered", "coverage_na_unconfirmed",
                              "roles_notes_missing", "drafts_not_accepted", "walks_not_answered"})


def context_rows(raw: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Declared-vs-observed rows (spec 6) in report shape. The claim is server text from the fixed
    claim set; a row with an unknown status or an empty claim is a compare bug and fails assembly."""
    rows = []
    for x in raw[:MAX_CONTEXT_ROWS]:
        status = x.get("status")
        if status not in CONTEXT_STATUSES:
            raise AssemblyError("schema", f"context comparison status {status!r}")
        claim = _CTRL_RE.sub(" ", str(x.get("claim") or "")).strip()[:120]
        if not claim:
            raise AssemblyError("schema", "context comparison row without a claim")
        rows.append({"claim": claim, "declared": _src_text(x.get("declared"), 300),
                     "declared_source": _src_text(x.get("declared_source"), 120),
                     "observed": _src_text(x.get("observed"), 300),
                     "observed_source": _src_text(x.get("observed_source"), 200), "status": status})
    return rows


def context_facts(facts: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """`context.*` fact records (spec 5) as report facts, so `{{fact:context.*}}` in context notes
    expands at build. A value that fails the server text gate (document text) is left out; the
    build then reports the placeholder as unresolved instead of printing gated text."""
    return report_facts(facts, prefix=CONTEXT_FACT_PREFIX)


def report_facts(facts: list[dict[str, Any]], prefix: str = "") -> dict[str, dict[str, Any]]:
    """Every job fact the kit may expand (`{{fact:key}}`, `{{calc:...}}`): `report.facts` per the
    schema (value, unit, amount_at_risk). Blind run 2026-10-26: only `context.*` facts were passed,
    so a finding that cited `{{fact:state.initial_minted}}` (accepted by the submit gate against the
    full fact list) failed the build with "fact ... not in facts" and no PDF was delivered."""
    from ..engine.text_gate import check_text

    out: dict[str, dict[str, Any]] = {}
    for f in facts:
        key = str(f.get("key") or "")
        if not key.startswith(prefix) or not re.fullmatch(r"[a-z][a-z0-9_.]{0,79}", key):
            continue
        value = _src_text(f.get("value"), 80)
        if re.fullmatch(r"[0-9]{5,}", value):  # plain integers print grouped (calc operands strip the commas)
            value = f"{int(value):,}"[:80]
        unit = f.get("unit")
        chain_tool = f.get("origin") == "chain_tool"
        if chain_tool and value and check_text(value, "server"):
            # text read from the chain that fails the server gate is replaced, not dropped: a dropped
            # fact would fail the whole render on an unresolved placeholder (never-worse)
            value = "[chain text not printable]"
        if not value or check_text(value, "server") or (unit is not None and check_text(str(unit)[:40], "server")):
            continue
        rec: dict[str, Any] = {"value": value, "unit": str(unit)[:40] if unit is not None else None,
                               "amount_at_risk": "amount_at_risk" in (f.get("tags") or [])}
        if chain_tool:
            from ..chain.facts import at_text

            at = at_text(f)
            if at and not check_text(at[:80], "server"):
                rec["at"] = at[:80]
            if f.get("class") == "chain_text":
                rec["literal"] = True
        out[key] = rec
    return out


_FACT_REF_RE = re.compile(r"(?<![a-z0-9_.])fact:([a-z][a-z0-9_.]{0,79})")


def chain_figures(content: dict[str, Any], facts: list[dict[str, Any]], printable: dict[str, Any]) -> list[dict[str, Any]]:
    """Figures used rows (04 6.4 `figure`) for the chain facts a finding cites: value, the read
    and its block, so every chain number in a finding prints with where and when it was read."""
    by_key = {f.get("key"): f for f in facts if f.get("origin") == "chain_tool"}
    seen: list[str] = []
    for key in _FACT_REF_RE.findall(json.dumps(content, ensure_ascii=False)):
        key = key.rstrip(".")
        if key in by_key and key in printable and key not in seen:
            seen.append(key)
    rows = []
    for key in seen[:30]:
        f, p = by_key[key], printable[key]
        block = f.get("block")
        if not isinstance(block, int) or isinstance(block, bool):
            continue
        shown = (f'"{p["value"]}"' if p.get("literal") else p["value"]) + (f" {p['unit']}" if p.get("unit") else "")
        rows.append({"figure": shown[:80], "operands": [{"value": p["value"][:80], "source": {
            "fact": key, "method": str(f.get("method") or "chain read")[:60], "block_or_slot": int(block)}}]})
    return rows


def pass_label(tool: str, limit: int = 40) -> str:
    """A server pass name as printed in the report: `soken-lifecycle@1` and `soken-lifecycle:STALE`
    become `lifecycle 1` and `lifecycle:STALE`. The printed strings are server text, and gate T25
    (`\bsoken\b`) failed whole renders on them (blind run 2026-10-26, method line and lead evidence)."""
    return str(tool).removeprefix("soken-").replace("@", " ")[:limit]


def section_rows(section: Any, key: str = "rows") -> list[dict[str, Any]]:
    """Rows of a stored report section. `review_set_section` stores the row list itself; older jobs
    hold `{rows: [...]}` (or `{notes: [...]}`). Blind run 2026-10-26: every job with roles_notes,
    coverage or out_of_scope_reasons crashed at assembly on `list.get`, so no PDF was delivered."""
    rows = section.get(key, []) if isinstance(section, dict) else (section or [])
    return [r for r in rows if isinstance(r, dict)]


def roles_section(rows_in: list[dict[str, Any]], notes_rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Attach each `roles_notes` row (`{role, risk_note}`) to the role row with that name; a note for
    a role the map does not list becomes a paragraph under the table. Prose blocks (`{p: ...}`) pass
    through as notes. Text was gated at write time; the assembly gate runs again on the result."""
    rows = [dict(r) for r in rows_in]
    by_name = {str(r.get("role", "")).strip().lower(): r for r in rows}
    notes: list[Any] = []
    for n in notes_rows:
        if "risk_note" not in n:
            notes.append(n)
            continue
        role, note = str(n.get("role", "")).strip(), str(n["risk_note"]).strip()
        hit = by_name.get(role.lower())
        if hit is not None and not hit.get("risk_note"):
            hit["risk_note"] = note[:300]
        else:
            notes.append({"p": f"{role}: {note}" if role else note})
    return rows, _model_blocks(notes)[:8]


def _dependency_package(path: str) -> str:
    """`node_modules/@scope/pkg` or `lib/name` of a pinned dependency path (report scope table)."""
    parts = path.split("/")
    if parts[0] == "node_modules" and len(parts) > 2:
        return "/".join(parts[:3] if parts[1].startswith("@") else parts[:2])
    if parts[0] == "lib" and len(parts) > 1:
        return "/".join(parts[:2])
    return parts[0] if len(parts) > 1 else path


def context_notes(section: Any) -> list[dict[str, Any]]:
    """The stored `context_notes` section (a list of blocks, or `{notes: [...]}`) as model blocks, max 8."""
    blocks = section.get("notes", []) if isinstance(section, dict) else (section or [])
    return _model_blocks(list(blocks))[:MAX_CONTEXT_NOTES]


def invariant_walk_rows(lc: dict[str, Any] | None, section: Any, keymap: dict[str, str]) -> list[dict[str, Any]]:
    """`review_coverage.invariant_walks` (feat/lifecycle-invariant-pass): one row per walk of the job
    with the session's verdict, the traced code (at most four refs) and the final id of the finding a
    violated walk names. The answer note is audit-log text and is not printed. No walks, no rows."""
    walks = (lc or {}).get("walks") or []
    rows_in = section.get("rows", []) if isinstance(section, dict) else (section or [])
    answers = {str(r.get("walk_id")): r for r in rows_in if isinstance(r, dict)}
    out = []
    for w in walks[:20]:
        a = answers.get(w["id"]) or {}
        verdict = a.get("outcome") if a.get("outcome") in ("holds", "violated", "not_applicable") else "not_answered"
        lines = []
        for ref in (a.get("refs") or [])[:4]:
            m = re.match(r"^(.+):(\d+)-(\d+)$", str(ref))
            if m:
                lines.append(_ref(m[1], int(m[2]), int(m[3])))
        row: dict[str, Any] = {"walk_id": w["id"], "title": str(w.get("title", ""))[:80], "verdict": verdict,
                               "lines": lines}
        if verdict == "violated" and keymap.get(str(a.get("draft_key"))):
            row["finding"] = keymap[str(a["draft_key"])]
        out.append(row)
    return out


def context_section(pin_root: Path, job_id: str, job: dict[str, Any], sections: dict[str, Any], today: date) -> dict[str, Any]:
    """The report `context` object (spec 7) plus the context facts for `report.facts`."""
    store = context_store(pin_root, job_id)
    entries = list((store.manifest() or {}).get("entries") or []) if store is not None else []
    facts = load_facts(pin_root, job_id) or []
    rows: list[dict[str, Any]] = []
    if entries:
        map_doc, _ = load_map(pin_root, job_id)
        rows = context_rows(context_compare(facts, map_doc, job))
    return {"documents": context_documents(entries, today), "comparison": rows,
            "notes": context_notes(sections.get("context_notes")), "facts": context_facts(facts)}


# ------------------------------------------------------------------ main

def _deployed_code_kpi(job: dict[str, Any], deployment: dict[str, Any] | None) -> str:
    """Summary KPI (schema enum): Matched for tier A, Does not match for tier C, else Not checked."""
    tier = job.get("tier")
    if tier == "A" and deployment:
        return "Matched"
    if tier == "C" and deployment:
        return "Does not match"
    return "Not checked"


def _deployment_method_detail(job: dict[str, Any], deployment: dict[str, Any] | None) -> str:
    """Method row for the deployment check (05 13.1), consistent with the cover label and the
    verification tables: what was compared and the outcome, numbers from deployment.json only."""
    tier = job.get("tier")
    dep = (deployment or {}).get("dep") or {}
    cmp_ = dep.get("comparison") or {}
    block = (deployment or {}).get("block")
    unit = _tier_a_unit(None, deployment)
    where = f" at {unit} {int(block):,}" if isinstance(block, int) else ""
    if tier == "A" and deployment:
        how = "byte for byte" if dep.get("match") == "exact" else "with immutables, library links and metadata masked"
        return f"The pinned source was rebuilt and compared with the deployed runtime code{where}: matched {how}"
    if tier == "C" and deployment:
        n = cmp_.get("differing_bytes")
        diff = f" ({int(n):,} differing bytes)" if isinstance(n, int) else ""
        return f"The pinned source was rebuilt and compared with the deployed runtime code{where}: it does not match{diff}"
    unlinked = (deployment or {}).get("unlinked_reason")
    if tier == "B" and isinstance(unlinked, str) and unlinked:
        # TON SOURCE_UNLINKED: the requester's source was reviewed; the deployment is not matched
        return f"The reviewed source could not be matched to the deployed code{where}: {unlinked}"
    return "Not run: the deployed code was not compared with a rebuild of the source"


async def assemble_report(conn: Any, job_id: str, pin_root: Path, *, today: date | None = None,
                          report_id_short: str | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return (report, extras). extras: subject candidates, profile, final ids, nsloc (reports row)."""
    texts = kit_texts()
    today = today or datetime.now(UTC).date()
    job = (await _rows(conn, "select * from jobs where job_id = %s", (job_id,)) or [None])[0]
    if job is None:
        raise AssemblyError("schema", "job not found")
    if not job.get("report_id") or not job.get("source_pin"):
        raise AssemblyError("schema", "job has no report_id or source_pin (finalize first)")
    work = pin_root.parent / "work" / job_id
    pin = PinnedSource.load(pin_root, job_id)
    ctx_store = context_store(pin_root, job_id)
    cands = _json(work / "candidates.json", [])
    chain_state = _json(work / "chain_state.json", None)
    deployment = _json(work / "deployment.json", None)
    if deployment is None and job.get("chain") == "ton":
        # TON jobs built before 2026-10-26 wrote provenance.json only; the same document is
        # derived from it so a finalized job renders without a new build (re-finalize path).
        ton_prov = _json(work / "provenance.json", None)
        if isinstance(ton_prov, dict) and ton_prov.get("tier"):
            from ..adapters.ton.provenance import deployment_doc as _ton_deployment_doc

            src_idx = ton_prov.get("src")
            cand_row = cands[src_idx] if isinstance(src_idx, int) and 0 <= src_idx < len(cands) else None
            deployment = _ton_deployment_doc(ton_prov, cand_row, job.get("address"))
    map_doc = load_map(pin_root, job_id)[0] if job.get("map_status") != "failed" else None
    facts = load_facts(pin_root, job_id) or []
    file_leads: list[dict[str, Any]] = _json(pin_root / job_id / "leads.json", [])
    db_leads = await _rows(conn, "select * from leads where job_id = %s", (job_id,))
    lead_state = {r["lead_id"]: r for r in db_leads}
    leads = []
    for lead in file_leads:
        st = lead_state.get(lead["id"])
        leads.append({**lead, "state": st["state"] if st else lead.get("state", "open"),
                      "reason": st["reason"] if st else None})
    chain_id = _job_chain_id(job, chain_state)
    rec = get_chain(int(chain_id)) if chain_id is not None else None
    network = _network_label(job, chain_state, deployment)
    # meta.chain and the coverage family: the EVM registry family for chain ids, else the job's own
    # chain (a TON or Solana job printed as an EVM review listed the EVM checklist areas).
    chain = _report_chain(job)
    family = _CHAIN_FAMILY.get(chain, "evm")

    # Findings (03 4.14 final ids, 08 2.3 card)
    drafts = await _rows(conn, """
        select d.*, r.content, r.category, r.impact_class, r.computed_severity,
               r.severity_rule as submit_severity_rule, r.caps_applied as submit_caps_applied,
               r.map_unavailable
        from finding_drafts d join finding_revisions r
          on r.job_id = d.job_id and r.draft_key = d.draft_key and r.revision = d.current_revision
        where d.job_id = %s order by d.finding_no""", (job_id,))
    ranges = await _rows(conn, """select q.* from finding_quote_ranges q join finding_drafts d
        on d.job_id = q.job_id and d.draft_key = q.draft_key and d.current_revision = q.revision
        where q.job_id = %s order by q.draft_key, q.ord""", (job_id,))
    challenges = await _rows(conn, """select c.* from challenge_answers c join finding_drafts d
        on d.job_id = c.job_id and d.draft_key = c.draft_key and d.current_revision = c.revision
        where c.job_id = %s""", (job_id,))
    flinks = await _rows(conn, """select l.* from finding_leads l join finding_drafts d
        on d.job_id = l.job_id and d.draft_key = l.draft_key and d.current_revision = l.revision
        where l.job_id = %s""", (job_id,))
    by_key_ranges: dict[str, list[dict[str, Any]]] = {}
    for q in ranges:
        by_key_ranges.setdefault(q["draft_key"], []).append(q)
    chal = {c["draft_key"]: c for c in challenges}
    lead_of = {}
    for fl in flinks:
        lead_of.setdefault(fl["draft_key"], fl["lead_id"])
    lead_by_id = {lead["id"]: lead for lead in leads}

    accepted = [d for d in drafts if d["status"] == "accepted" and d["final_id"]]
    keymap = {d["draft_key"]: d["final_id"] for d in accepted}
    accepted.sort(key=lambda d: (SEV_RANK[d["severity"]], d["final_id"]))
    expect = {}
    for d in accepted:
        expect[d["severity"]] = expect.get(d["severity"], 0) + 1
        want = f"{SEV_PREFIX[d['severity']]}-{expect[d['severity']]:03d}"
        if d["final_id"] != want:
            raise AssemblyError("schema", f"final id {d['final_id']} out of order, expected {want} (03 4.14)")
    findings = []
    printable_facts = report_facts(facts)
    for d in accepted:
        c = d["content"]
        sev = d["severity"]
        low = sev in ("Low", "Informational")
        blocks_cap, lines_cap = (1, 20) if low else (3, 40)
        qs = sorted(by_key_ranges.get(d["draft_key"], []), key=lambda q: (QUOTE_ROLE_ORDER.index(q["role"])
                                                                        if q["role"] in QUOTE_ROLE_ORDER else 9, q["ord"]))
        code_qs = [q for q in qs if q["role"] in QUOTE_ROLE_ORDER]
        loc = next((q for q in code_qs if q["role"] == "location"), None)
        if loc is None:
            raise AssemblyError("schema", f"{d['final_id']} has no location quote")
        code = [_code_block(_quote_source(pin, ctx_store, q["path"]), q["path"], q["start_line"], q["end_line"], lines_cap)
                for q in code_qs[:blocks_cap]]
        further = [_ref(q["path"], q["start_line"], q["end_line"]) for q in code_qs[blocks_cap:]][:20]
        matrix = d.get("matrix_effective") or c.get("matrix") or {}
        # The rule, who set the severity and why are the draft's final values (challenge and finalize
        # write them); the revision's submit-time rule is the fallback for rows older than migration 014.
        rule = d.get("severity_rule") or d.get("submit_severity_rule") or ""
        set_by = d.get("severity_set_by") or ("reviewer" if c.get("claimed_severity") == sev else "matrix")
        reason = d.get("severity_reason") or explain_rules(list(d.get("caps_applied") or d.get("submit_caps_applied") or []))
        basis = {"head": ["Impact class", "Magnitude", "Trigger", "Precondition", "Reversibility", "Rule",
                          "Set by", "Reason"],
                 "rows": [[matrix.get("impact_class", d["impact_class"]), matrix.get("magnitude", ""),
                           matrix.get("trigger", ""), matrix.get("precondition", ""), matrix.get("reversibility", ""),
                           rule, set_by, reason[:200]]]}
        level = d["evidence_level"] or "reasoning_only"
        ch = chal.get(d["draft_key"])
        challenge = None
        if level != "reasoning_only" and ch:
            answers = ch["answers"] if isinstance(ch["answers"], list) else ch["answers"].get("items", [])
            items = {i["id"]: i for i in (ch["items"] if isinstance(ch["items"], list) else [])}
            challenge = {"head": ["Item", "Condition", "Answer"],
                         "rows": [[a.get("item_id", a.get("id", "")), items.get(a.get("item_id", a.get("id")), {})
                                   .get("condition", "")[:600], str(a.get("answer", ""))[:600]] for a in answers][:60]}
        if level != "reasoning_only" and challenge is None:
            challenge = {"head": ["Item", "Condition", "Answer"], "rows": []}
        lead = None
        if level == "analyzer_and_reasoning":
            lid = lead_of.get(d["draft_key"])
            ld = lead_by_id.get(lid) if lid else None
            if ld is None:
                raise AssemblyError("schema", f"{d['final_id']} analyzer evidence without a lead row")
            tool = (ld.get("tools") or ["analyzer"])[0]
            lead = {"analyzer": pass_label(tool), "rule_id": pass_label(ld["rule_id"], 80)}
        body = c.get("body", {})
        f: dict[str, Any] = {
            "id": d["final_id"], "severity": sev, "evidence_level": level,
            "title": _sub_findings(c["title"], keymap),
            "component": _unit_of(loc["path"]),
            "location": _ref(loc["path"], loc["start_line"], loc["end_line"]),
            "category": category_label(d["category"]), "category_key": d["category"],
            "description": _sub_findings(_model_blocks(body.get("description", [])), keymap),
            "impact": _sub_findings(_model_blocks(body.get("impact", [])), keymap),
            "recommendation": _sub_findings(_model_blocks(body.get("recommendation", [])), keymap),
            "evidence": {"code": code, "basis": basis, "challenge": challenge, "lead": lead},
        }
        if further:
            f["evidence"]["further"] = further
        figs = chain_figures(c, facts, printable_facts)
        if figs:
            f["evidence"]["figures"] = figs
        if c.get("attack_steps"):
            f["attack_steps"] = [{"text": _sub_findings(s["text"], keymap), "ref": _parse_ref(s["ref"])}
                                 for s in c["attack_steps"]][:10]
        di = c.get("documented_intent_ref")
        if di:
            f["documented_intent"] = _ref(di["file"], di["start"], di["end"])
        if job["tier"] == "C":
            f["tier_c_line"] = True
        if job["map_status"] == "failed" or d.get("map_unavailable"):
            f["no_map_line"] = True
        if job.get("previous_report_id"):
            f["status"] = "Open"
        findings.append(f)

    # Scope (08 2.2): in-scope source files, nSLOC counted from the pinned lines
    scope_files, oos = [], []
    dep_groups: dict[str, int] = {}
    entry_file = (cands[0].get("entry_contract") or "").rsplit(":", 1)[0] if cands else ""
    # Address column: behind a followed proxy the reviewed entry file is the implementation's; a
    # related contract's entry file carries its own address (adapters/evm/related_sources).
    related = _json(work / "related_sources.json", [])
    entry_addr = {entry_file: ((chain_state or {}).get("proxy") or {}).get("implementation") or job.get("address")}
    for r in related if isinstance(related, list) else []:
        if isinstance(r, dict) and r.get("status") == "pinned" and r.get("path") and r.get("entry_contract"):
            entry_addr[f"{r['path']}/{str(r['entry_contract']).rsplit(':', 1)[0]}"] = r.get("address")
    # files the scope rules or the build left out are listed once, with their reason (below)
    excluded_paths = {str(r.get("path")) for r in ((cands[0].get("scope_excluded") if cands else None) or [])
                      if isinstance(r, dict)}
    for path, e in sorted(pin.entries.items()):
        if e.in_scope and e.role == "source":
            row: dict[str, Any] = {"name": _unit_of(path), "file": path, "nsloc": count_nsloc("\n".join(pin.read_all(path)))}
            if job.get("address") and entry_addr.get(path):
                row["addr"] = entry_addr[path]
            scope_files.append(row)
        elif not e.in_scope and e.role == "dependency":
            dep_groups[_dependency_package(path)] = dep_groups.get(_dependency_package(path), 0) + 1
        elif not e.in_scope and path not in excluded_paths:
            oos.append({"path": path, "reason": "Excluded by the scope rules", "by": "server"})
    for pkg, n in sorted(dep_groups.items()):
        oos.append({"path": f"{pkg} ({n} file{'s' if n != 1 else ''})",
                    "reason": "Dependency imported by the reviewed sources; readable, not reviewed", "by": "server"})
    if not scope_files:
        raise AssemblyError("schema", "no in-scope file")
    sections = {r["section"]: r["content"] for r in await _rows(conn, """
        select distinct on (section) section, content from sections where job_id = %s
        order by section, revision desc""", (job_id,))}
    model_oos = [{"path": row["path"], "reason": row["reason"], "by": "model"}
                 for row in section_rows(sections.get("out_of_scope_reasons"))[:20] if pin.has_path(row.get("path", ""))]
    # Files the scope rules kept out of the reviewed candidate (test and mock contracts): listed
    # with the rule's reason within the schema cap; the count of any further files is printed.
    oos.extend(scope_excluded_rows(cands, budget=_OUT_OF_SCOPE_MAX - len(oos) - len(model_oos)))
    oos.extend(model_oos)
    nsloc = sum(f["nsloc"] for f in scope_files)

    # Leads per analyzer, promoted, dismissed (08 2.2 Review coverage; KPIs)
    promoted_ids = {fl["lead_id"] for fl in flinks} | {lead["id"] for lead in leads if lead["state"] == "promoted"}
    per_tool: dict[tuple[str, str], dict[str, int]] = {}
    # Rule tiers the reviewer was shown (learning-loop design 2.2): every lead stays counted here;
    # the ones a tier listed lower or collapsed are counted again as lower priority, so the client
    # sees what was run and what was set aside.
    tier_version = str(job.get("learning_policy_version") or rule_tiers.baseline_version())
    tiered, tier_summary = rule_tiers.apply_tiers(leads, tier_version, job_id)
    lower = {x.get("id") for x in tiered if x["tier"] in ("demoted", "collapsed")}
    for lead in leads:
        tool = (lead.get("tools") or ["analyzer@"])[0]
        name, _, ver = pass_label(tool, 120).partition("@")
        row = per_tool.setdefault((name, ver or "unknown"), {"leads": 0, "promoted": 0, "dismissed": 0})
        row["leads"] += 1
        row["promoted"] += lead["id"] in promoted_ids
        row["dismissed"] += lead["state"] == "dismissed"
        if lower:
            row["lower_priority"] = row.get("lower_priority", 0) + (lead.get("id") in lower)
    reads = await _rows(conn, "select path, start_line, end_line from job_reads where job_id = %s", (job_id,))

    def returned(cat: str) -> bool:
        for lead in leads:
            if lead["category"] == cat and any(r["path"] == lead["file"] and r["start_line"] <= lead["end"]
                                               and r["end_line"] >= lead["start"] for r in reads):
                return True
        return any(f["category_key"] == cat for f in findings)

    areas = []
    na_rows = {r["area_id"]: r for r in section_rows(sections.get("coverage")) if "area_id" in r}
    for cat in coverage_categories(family, chain if chain != "evm" else None):
        ids = [f["id"] for f in findings if f["category_key"] == cat["id"]][:20]
        a: dict[str, Any] = {"area_id": cat["id"][:40], "area": category_label(cat["id"])}
        if cat["id"] in na_rows:
            a.update(code_returned="Not applicable", result="Not applicable (marked by the requester's session)",
                     note=na_rows[cat["id"]]["note"])
        elif ids:
            a.update(code_returned="Yes", result=ids)
        elif returned(cat["id"]):
            a.update(code_returned="Yes", result="No finding submitted")
        else:
            a.update(code_returned="No", result="Not covered")
        areas.append(a)
    n_returned = sum(1 for a in areas if a["code_returned"] in ("Yes", "Partly"))

    withdrawn = []
    for d in drafts:
        if d["status"] != "withdrawn":
            continue
        loc = next((q for q in by_key_ranges.get(d["draft_key"], []) if q["role"] == "location"), None)
        if loc is None:
            continue
        w = {"candidate": f"F-{d['finding_no']:02d}", "category": category_label(d["category"]),
             "withdrawn_by": d["withdrawn_by"] or "model", "lines": _ref(loc["path"], loc["start_line"], loc["end_line"])}
        if w["withdrawn_by"] == "challenge":
            w["item_id"] = (d.get("kill_item") or "")[:40]
            w["condition"] = ""
        withdrawn.append(w)

    c = counts(findings)
    dismissed = [lead for lead in leads if lead["state"] == "dismissed"]
    # Project context (spec 7): documents, declared vs observed, context_notes; KPI when n > 0
    ctx = context_section(pin_root, job_id, job, sections, today)
    context_facts_map = {**report_facts(facts), **ctx.pop("facts")}
    n_documents = sum(1 for d in ctx["documents"] if d["status"] == "ok")
    summary: dict[str, Any] = {"kpis": [
        {"key": "files", "value": len(scope_files), "label": texts["kpi_labels"]["files"]},
        {"key": "nsloc", "value": nsloc, "label": texts["kpi_labels"]["nsloc"]},
        {"key": "leads", "value": len(leads), "label": texts["kpi_labels"]["leads"]},
        {"key": "promoted", "value": len(promoted_ids), "label": texts["kpi_labels"]["promoted"]},
        {"key": "areas_returned", "value": f"{n_returned} of {len(areas)}", "label": texts["kpi_labels"]["areas_returned"]},
        {"key": "deployed_code", "value": _deployed_code_kpi(job, deployment), "label": texts["kpi_labels"]["deployed_code"]}]}
    if n_documents > 0:
        summary["kpis"].append({"key": "documents", "value": n_documents, "label": texts["kpi_labels"]["documents"]})
    if c["Critical"] == 0 and c["High"] == 0 and dismissed:
        rows = sorted(dismissed, key=lambda x: (SEV_RANK[LEAD_SEV[x["severity_norm"]]], x["file"], x["start"]))
        summary["dismissed_leads"] = {"rows": [{"detector": x["rule_id"][:80], "severity_class": LEAD_SEV[x["severity_norm"]],
                                                "location": _ref(x["file"], x["start"], x["end"]),
                                                "reason": x.get("reason") or "not_reviewed"} for x in rows[:10]],
                                      "remainder": max(0, len(rows) - 10)}

    m = texts["method_steps"]
    tools_line = ", ".join(f"{n} {v}: {r['leads']:,} leads" for (n, v), r in sorted(per_tool.items())) or "No analyzer leads"
    degraded = ""
    if job.get("analyzer_degraded"):
        from ..mapping.analyzer_note import job_analyzer_note

        degraded = " " + job_analyzer_note(pin_root, job_id)
    # A failed build is one sentence (compiler, error class, consequence) on the cover, in the
    # summary and in the method table; review_status carries the same sentence before submitting.
    build_failure = job_build_failure(pin_root, job_id, map_status=job.get("map_status"), family=family)
    method = [
        {"step": m["pin"], "detail": f"{len(pin.entries):,} file{"s" if len(pin.entries) != 1 else ""} pinned by sha256; source pin {job['source_pin'][:16]}"},
        {"step": m["analyzer"], "detail": (build_failure or tools_line + "." + degraded)[:400]},
        {"step": m["selection"], "detail": f"{len(accepted):,} findings accepted, "
                                           f"{sum(1 for d in drafts if d['status'] == 'withdrawn'):,} withdrawn"},
        {"step": m["checks"], "detail": "Every code quote matched to the pinned source; text and number rules on every "
                                        "finding; severity mapped from the classifications through the fixed matrix"},
        {"step": m["deployment"], "detail": _deployment_method_detail(job, deployment)},
    ]
    roles_rows, roles_notes = roles_section(role_rows(map_doc, facts, job), section_rows(sections.get("roles_notes"), "notes")
                                            or section_rows(sections.get("roles_notes")))
    profile = "owner" if job["ownership_proven"] else "public_review"
    rid = job["report_id"]
    short = report_id_short or rid[:10]
    subj_cands = subject_candidates(job, cands, pin)
    subj = pick_subject(subj_cands)
    days = int(_limits()["report"]["default_days"])
    prov = provenance(job, cands, chain_state, deployment, today=today, related=related)
    meta: dict[str, Any] = {
        "report_type": "automated", "kind": texts["sub_line"], "subject": subj["value"], "subject_source": subj["source"],
        "chain": chain, "network": network[:60], "chain_id": chain_id, "explorer": None,
        "addr_url": _addr_url(rec),
        "deployed_noun": _DEPLOYED_NOUN.get(chain, "contract"),
        "source_id_label": _source_id_label(prov, chain),
        "provenance": prov, "report_id": rid, "report_id_short": short,
        "ownership_proven": bool(job["ownership_proven"]), "profile": profile,
        "requested_by": {"role": job["requester_role"], "label": ROLE_LABELS[job["requester_role"]]},
        "date": date_text(today), "expires": (today + timedelta(days=days)).isoformat(),
    }
    if build_failure:
        meta["build_failure"] = build_failure[:400]
    if job.get("previous_report_id"):
        meta["previous_report_id"] = job["previous_report_id"]
    meta["out_name"] = out_name({**meta, "date_iso": today.isoformat()}, profile, subj["value"])
    t = texts
    report = {
        "meta": meta, "facts": context_facts_map, "summary": summary,
        "scope": {"head": ["Unit", "File", "nSLOC", "Address"], "files": scope_files[:400], "out_of_scope": oos[:40]},
        "context": ctx,
        "architecture": architecture_block(map_doc, facts, job, deployment),
        "roles": {
            "rows": roles_rows,
            "notes": roles_notes,
            **_roles_related(pin_root, job_id),
        },
        "method": method,
        "severity_scale": [{"severity": s, "text": t["severity_scale"][s.lower()]} for s in SEVS],
        "findings": findings,
        "review_coverage": {"areas": areas,
                            "leads": [{"analyzer": n[:40], "version": v[:40], **r} for (n, v), r in sorted(per_tool.items())],
                            "withdrawn": withdrawn[:60], "injection_flags": []},
    }
    if lower:
        report["review_coverage"]["rule_tiers"] = {"version": tier_summary["version"][:40], "lower_priority": len(lower)}
    # Coverage note (never-worse, gate_policy.yaml finalize_checks): the advisory steps the requester's
    # session did not take, as finalize recorded them. Server data, printed from kit text.
    not_taken = [{"kind": str(g["kind"]), "count": max(1, int(g.get("count") or 1))}
                 for g in (job.get("coverage_gaps") or []) if isinstance(g, dict) and g.get("kind") in _NOT_TAKEN_KINDS]
    if not_taken:
        report["review_coverage"]["not_taken"] = not_taken[:9]
    walk_rows = invariant_walk_rows(load_lifecycle(pin_root, job_id), sections.get("invariant_walks"), keymap)
    if walk_rows:
        report["review_coverage"]["invariant_walks"] = walk_rows
    # Verification blocks: present only for tier A and C (schema: "present for tier A and C only")
    if job.get("tier") in ("A", "C") and deployment is not None:
        report["verification"] = _build_verification_blocks(deployment, chain_state, job)
    validate(report)
    check_strings(report)
    extras = {"subject_candidates": subj_cands, "profile": profile, "final_ids": sorted(keymap.values()),
              "counts": c, "nsloc": nsloc}
    return report, extras
