"""`soken-eval corpus import`: EVMbench (S1) and sealevel-attacks (S6) into case.v1 files.

Both importers read only pinned checkouts (sources.lock.yaml) and write one case.yaml per case.
`dev` and `neg` cases go to evals/corpus/<chain>/, `gate` cases to the gitignored
evals/heldout/<chain>/ (held-out ACL, 10 2.1). Every ground-truth line range is located in the
checked-out tree at the case commit (locate.py); a judged finding no evidence can place is kept
out of the case and listed in the import log, never given guessed lines.
"""

from __future__ import annotations

import datetime as dt
import re
from pathlib import Path
from typing import Any

import yaml

from . import locate
from .sources import CORPUS_DIR, HELDOUT_DIR, TREES_DIR, UPSTREAM_DIR, case_dir, checkout, load_lock, remote_head

# Title keywords -> rubric/enums.yaml category for EVMbench findings. EVMbench carries no
# category, so the category is importer-assigned and every EVMbench GT uses
# `min_match: location_only` (10 3.2): the category never decides a match on these cases.
EVM_CATEGORY_RULES: tuple[tuple[str, str], ...] = (
    (r"signature|replay|domainseparator", "evm.signature_replay"),
    (r"reenter|reentranc", "evm.reentrancy"),
    (r"oracle|twap|price can be manipulated|chainlink", "evm.oracle_manipulation"),
    (r"access control|called by anyone|anyone can|by anyone|unauthori[sz]ed|unrestricted|^public |lacks access",
     "evm.access_control"),
    (r"front-?run|race condition", "evm.ordering_mev"),
    ((r"rounding|precision|sqrt|logarithm|decimal|underflow|overflow|percentage calculation|digit|mantissa|"
      r"truncat|exponent"), "evm.arithmetic_precision"),
    ((r"blocked|halt|brick|prevent|griefing|bloating|unable|never be able|stuck|lock |locked|freeze|cannot|"
      r"won.t be able|fail"), "evm.dos"),
    (r"validation|accepts invalid|missing check|lack of check|arbitrary", "evm.input_validation"),
)
EVM_DEFAULT_CATEGORY = "evm.accounting_logic"
EVM_CHAIN_ID = 1          # Code4rena code is not deployed; chain_id is required for `evm` (case.v1)
EVM_DEV_COUNT = 18        # 10 2.2 E-BENCH: 37 audits by date, 18 dev and 19 gate
EVM_EXCLUDE = re.compile(r"tempo")   # 10 2.1: EVMbench Tempo tasks are refused


def evm_category(title: str) -> str:
    low = title.lower()
    for pattern, category in EVM_CATEGORY_RULES:
        if re.search(pattern, low):
            return category
    return EVM_DEFAULT_CATEGORY


def _today() -> dt.date:
    return dt.datetime.now(tz=dt.UTC).date()


def _write(case: dict[str, Any]) -> Path:
    base = HELDOUT_DIR if case["split"] == "gate" else CORPUS_DIR
    path = base / case["chain"] / case["case_id"] / "case.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(case, sort_keys=False, allow_unicode=True, width=120))
    return path


def import_evmbench(trees: Path = TREES_DIR, log: list[str] | None = None) -> list[Path]:
    log = log if log is not None else []
    row = load_lock()["evmbench"]
    root = UPSTREAM_DIR / "evmbench" / row["path"]
    raw = locate.RawCache(UPSTREAM_DIR / "raw-cache")
    manual = _manual_lines()
    audits = [a for a in _read(root, "splits/detect-tasks.txt").split() if re.fullmatch(r"[a-z0-9][a-z0-9-]{0,80}", a)]
    excluded = [a for a in audits if EVM_EXCLUDE.search(a)]
    audits = sorted(a for a in audits if not EVM_EXCLUDE.search(a))
    log.append(f"evmbench@{row['commit'][:12]}: {len(audits)} audits imported, excluded (Tempo, 10 2.1): {excluded}")
    split_rows: dict[str, list[str]] = {"dev": [], "gate": []}
    written: list[Path] = []
    for n, audit in enumerate(audits, start=1):
        cfg = yaml.safe_load(_read(root, f"audits/{audit}/config.yaml"))
        repo = f"https://github.com/evmbench-org/{audit}"
        commit = cfg.get("base_commit")
        pinned_by = "config.yaml base_commit"
        if not commit:
            commit = remote_head(repo)
            pinned_by = f"default-branch head on {_today()} (config.yaml has no base_commit)"
        case_id = f"evm-contest-{n:04d}"
        tree = checkout(repo, commit, case_dir(trees, case_id))
        files = locate.source_files(tree)
        split = "dev" if n <= EVM_DEV_COUNT else "gate"
        split_rows[split].append(audit)
        gts = []
        for vuln in cfg.get("vulnerabilities") or []:
            vid = str(vuln["id"])
            if not re.fullmatch(r"[A-Z]-\d{1,3}", vid):
                raise ValueError(f"{audit}: vulnerability id {vid!r}")
            text = locate.safe_read(root, f"audits/{audit}/findings/{vid}.md") or ""
            spans = locate.from_links(text, tree, files, raw) + locate.from_markers(text, tree, files)
            diff = locate.safe_read(root, f"audits/{audit}/patch/{vid}.diff")
            patch_spans = locate.from_patch(diff, tree) if diff else []
            root_spans = spans or patch_spans
            related = patch_spans if spans else []
            hand = manual.get((audit, vid))
            if not root_spans and hand and hand.get("root"):
                root_spans = [_anchor_span(tree, a, f"{audit} {vid}") for a in hand["root"]]
                related = [_anchor_span(tree, a, f"{audit} {vid}") for a in hand.get("related") or []]
            if not root_spans:
                log.append(f"{case_id} {audit} {vid}: no located lines (links, markers, patch); GT left out")
                continue
            vias = sorted({s.via for s in root_spans})
            severity = {"H": "High", "M": "Medium", "L": "Low"}.get(vid[:1], "High")
            gts.append({
                "gt_id": f"GT-{len(gts) + 1}",
                "title_ref": f"{vid} {vuln['title']}",
                "severity": severity,
                "category": evm_category(vuln["title"]),
                "root_cause_lines": locate.merge(root_spans),
                "related_lines": locate.merge(related),
                "source_url": f"{row['repo']}/blob/{row['commit']}/{row['path']}/audits/{audit}/findings/{vid}.md",
                "min_match": "location_only",
                "exclude_chains": [],
                "located_by": vias,
            })
        if not gts:
            log.append(f"{case_id} {audit}: no GT located; case not written")
            continue
        case = {
            "case_id": case_id,
            "chain": "evm",
            "chain_id": EVM_CHAIN_ID,
            "split": split,
            "origin": "contest",
            "source": {
                "provider": "repo",
                "repo": repo,
                "commit": commit,
                "subdir": None,
                "license": row["code_license"],
                "dataset": f"evmbench@{row['commit']}:{row['path']}/audits/{audit}",
                "dataset_license": row["license"],
                "pinned_by": pinned_by,
            },
            "input_mode": "repo",
            "run_as_chain": None,
            "provenance_tier_expected": "B",
            "expected_outcome": "report",
            "j_class": None,
            "ground_truth": gts,
            "judged": True,
            "seeded": None,
            "rereview_of": None,
            "negatives_note": None,
            "consent": "not_needed",
            "created": _today(),
            "created_by": "eval-agent",
        }
        written.append(_write(case))
    split_file = CORPUS_DIR / "evm" / "split.yaml"
    split_file.parent.mkdir(parents=True, exist_ok=True)
    split_file.write_text(yaml.safe_dump({
        "set": "E-BENCH",
        "rule": f"EVMbench detect audits sorted by audit date (id prefix); oldest {EVM_DEV_COUNT} dev, rest gate (10 2.2)",
        "source": f"evmbench@{row['commit']}",
        "dev": split_rows["dev"],
        "gate": split_rows["gate"],
        "excluded": {a: "Tempo task (10 2.1)" for a in excluded},
    }, sort_keys=False))
    return written


def import_sealevel(trees: Path = TREES_DIR, log: list[str] | None = None) -> list[Path]:
    log = log if log is not None else []
    row = load_lock()["sealevel-attacks"]
    upstream = UPSTREAM_DIR / "sealevel-attacks"
    spec = yaml.safe_load((CORPUS_DIR / "solana" / "sealevel.gt.yaml").read_text())
    programs = sorted(
        p.parent.parent.relative_to(upstream).as_posix() for p in (upstream / "programs").glob("*/*/src/lib.rs")
    )
    written: list[Path] = []
    pos = neg = 0
    for subdir in sorted(programs, key=lambda s: (int(s.split("/")[1].split("-")[0]), s)):
        variant = subdir.rsplit("/", 1)[1]
        insecure = variant.startswith("insecure")
        if insecure:
            pos += 1
            case_id = f"sol-pattern-{pos:04d}"
        else:
            neg += 1
            case_id = f"sol-reference-{neg:04d}"
        tree = checkout(row["repo"], row["commit"], case_dir(trees, case_id)) / subdir
        gts = []
        if insecure:
            entry = spec["programs"].get(subdir)
            if entry is None:
                log.append(f"{case_id} {subdir}: no GT spec; case not written")
                continue
            lines = _read(tree, "src/lib.rs").splitlines()
            gts.append({
                "gt_id": "GT-1",
                "title_ref": entry["title"],
                "severity": entry["severity"],
                "category": entry["category"],
                "root_cause_lines": [_anchor(lines, a, subdir) for a in entry["root"]],
                "related_lines": [_anchor(lines, a, subdir) for a in entry.get("related", [])],
                "source_url": f"{row['repo']}/tree/{row['commit']}/{subdir}",
                "min_match": "location_and_category",
                "exclude_chains": [],
            })
        case = {
            "case_id": case_id,
            "chain": "solana",
            "chain_id": None,
            "split": "dev" if insecure else "neg",
            "origin": "pattern" if insecure else "reference",
            "source": {
                "provider": "repo",
                "repo": row["repo"],
                "commit": row["commit"],
                "subdir": subdir,
                "license": row["license"],
                "dataset": f"sealevel-attacks@{row['commit']}",
                "dataset_license": row["license"],
                "pinned_by": "sources.lock.yaml",
            },
            "input_mode": "repo",
            "run_as_chain": None,
            "provenance_tier_expected": "B",
            "expected_outcome": "report",
            "j_class": None,
            "ground_truth": gts,
            "judged": False,
            "seeded": None,
            "rereview_of": None,
            "negatives_note": None if insecure else (
                f"sealevel-attacks {variant} program of class {subdir.split('/')[1]}: the fixed counterpart "
                "of the insecure program (upstream README), no known High or Medium"),
            "consent": "not_needed",
            "created": _today(),
            "created_by": "eval-agent",
        }
        written.append(_write(case))
    log.append(f"sealevel-attacks@{row['commit'][:12]}: {pos} insecure (dev), {neg} secure/recommended (neg)")
    return written


def _read(root: Path, rel: str) -> str:
    text = locate.safe_read(root, rel)
    if text is None:
        raise ValueError(f"{root}/{rel}: missing, or a symlink, or not a regular file")
    return text


def _manual_lines() -> dict[tuple[str, str], dict[str, Any]]:
    """Hand-located anchors for findings with no permalink, marker or patch: evals/corpus/evm and,
    for `gate` audits, the gitignored evals/heldout/evm copy (same format)."""
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for base in (CORPUS_DIR, HELDOUT_DIR):
        path = base / "evm" / "gt_manual.yaml"
        if path.is_file():
            for row in (yaml.safe_load(path.read_text()) or {}).get("findings") or []:
                out[(str(row["audit"]), str(row["vid"]))] = row
    return out


def _anchor_span(tree: Path, anchor: dict[str, Any], where: str) -> locate.Span:
    rel = str(anchor["file"])
    text = locate.safe_read(tree, rel)
    if text is None:
        raise ValueError(f"{where}: {rel} not a regular file in the tree")
    rng = _anchor(text.splitlines(), anchor, f"{where} {rel}", rel)
    return locate.Span(rel, rng["start"], rng["end"], "manual")


def _anchor(lines: list[str], anchor: dict[str, Any], where: str, file: str = "src/lib.rs") -> dict[str, Any]:
    """Lines located by text: `text` must occur exactly once; `span` extends the range downwards."""
    hits = [i + 1 for i, line in enumerate(lines) if anchor["text"] in line]
    if len(hits) != 1:
        raise ValueError(f"{where}: anchor {anchor['text']!r} found {len(hits)} times")
    start = hits[0]
    return {"file": file, "start": start, "end": start + int(anchor.get("span", 0))}
