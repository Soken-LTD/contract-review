"""soken-eval: corpus tooling (10 section 2)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

from .corpus import check_case
from .sources import TREES_DIR, case_dir, case_tree, fetch_case_tree, fetch_upstream, git_run, load_lock


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="soken-eval")
    sub = parser.add_subparsers(dest="group", required=True)
    corpus = sub.add_parser("corpus").add_subparsers(dest="cmd", required=True)
    check = corpus.add_parser("check", help="validate case.yaml files")
    check.add_argument("paths", nargs="+", type=Path, help="case.yaml files or corpus directories")
    check.add_argument("--tree", type=Path, help="checked-out source for line-range checks (one case)")
    check.add_argument("--trees", type=Path, help="dir of per-case checkouts (<dir>/<case_id>), e.g. .sbx/corpus-src")
    check.add_argument("--enforce-licences", action="store_true", help="release corpus: licence rules are errors")
    fetch = corpus.add_parser("fetch", help="check out pinned upstream sources and per-case trees")
    fetch.add_argument("paths", nargs="*", type=Path, help="case.yaml files or dirs whose trees to fetch")
    fetch.add_argument("--upstream", action="store_true", help="also fetch every source in sources.lock.yaml")
    imp = corpus.add_parser("import", help="convert an upstream benchmark into case.v1 files")
    imp.add_argument("source", choices=["evmbench", "sealevel"])
    args = parser.parse_args(argv)

    if args.cmd == "fetch":
        return _fetch(args)
    if args.cmd == "import":
        return _import(args.source)

    files = _case_files(args.paths)
    failed = 0
    for f in files:
        tree = args.tree
        head_error = None
        if args.trees is not None:
            case = next(yaml.safe_load_all(f.read_text()))
            try:
                tree = case_tree(case, root=args.trees)
                head_error = _tree_head_error(case_dir(args.trees, case.get("case_id")),
                                              (case.get("source") or {}).get("commit"))
            except ValueError as exc:
                tree, head_error = None, f"tree path refused: {exc}"
        report = check_case(f, tree=tree, enforce_licences=args.enforce_licences)
        if head_error:
            report.errors.append(head_error)
        for w in report.warnings:
            print(f"{f}: warning: {w}")
        for e in report.errors:
            print(f"{f}: error: {e}")
        failed += not report.ok
    print(f"{len(files)} cases, {failed} failed")
    return 1 if failed else 0


def _tree_head_error(checkout: Path, commit: str | None) -> str | None:
    """10 2.4: a missing commit is refused. The checkout must exist and sit at source.commit."""
    if not (checkout / ".git").exists():
        return f"no checkout at {checkout} (run soken-eval corpus fetch)"
    try:
        head = git_run("rev-parse", "HEAD", cwd=checkout).strip()
    except RuntimeError as exc:
        return f"checkout unreadable: {exc}"
    return None if head == commit else f"checkout at {head}, case pins {commit}"


def _case_files(paths: list[Path]) -> list[Path]:
    return [f for p in paths for f in (sorted(p.rglob("case.yaml")) if p.is_dir() else [p])]


def _fetch(args: argparse.Namespace) -> int:
    if args.upstream:
        for source_id in load_lock():
            print(f"{source_id}: {fetch_upstream(source_id)}")
    failed = 0
    for f in _case_files(args.paths):
        case = next(yaml.safe_load_all(f.read_text()))
        try:
            fetch_case_tree(case, TREES_DIR)
        except RuntimeError as exc:
            failed += 1
            print(f"{case['case_id']}: error: {exc}")
    return 1 if failed else 0


def _import(source: str) -> int:
    from . import importers

    log: list[str] = []
    if source == "evmbench":
        fetch_upstream("evmbench")
        written = importers.import_evmbench(log=log)
    else:
        fetch_upstream("sealevel-attacks")
        written = importers.import_sealevel(log=log)
    for line in log:
        print(line)
    print(f"{len(written)} case files written")
    return 0


if __name__ == "__main__":
    sys.exit(main())
