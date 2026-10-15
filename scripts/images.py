#!/usr/bin/env python3
"""Sandbox image build plan and digest lock (09 4.4).

    python scripts/images.py plan [--only name,name]   # JSON build plan on stdout
    python scripts/images.py lock <results_dir>         # write pushed digests into images.lock.json
    python scripts/images.py check                      # lock entries well-formed (CI)
    python scripts/images.py argv '<plan entry>' [deps]  # build options, one per line

Every `docker/<dir>/Dockerfile` is an image: name `<dir>`, repository `ghcr.io/soken-ltd/<dir>`,
built with the repo root as context. A `docker/<dir>/variants.json` list
(`[{"name", "tag", "build_args"}]`) turns one Dockerfile into several images (one per toolchain
line). The tag comes from the lock entry with that repository, else `0.1.0-dev`.

A Dockerfile `FROM ghcr.io/soken-ltd/<other>:<tag>` makes `<other>` a dependency: it is built in
an earlier level and the dependant is built against its pushed digest (build context override),
never a floating tag. Two levels at most.

Lock entries are matched by repository, so aliases (`solana-analyze` = the `solana-build` image)
receive the same digest. `lock` only touches `digest`, `platforms` and `built`; it never removes
or reorders entries of other images, so parallel additions merge line by line.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "images.lock.json"
REGISTRY = "ghcr.io/soken-ltd"
DEFAULT_TAG = "0.1.0-dev"
PLATFORM = "linux/amd64"
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")
_TAG_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_FROM_RE = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)", re.IGNORECASE | re.MULTILINE)
_ARG_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")


def _load_lock() -> dict:
    return json.loads(LOCK.read_text())


def _tag_for(repository: str, lock: dict) -> str:
    for entry in lock["images"].values():
        if entry.get("repository") == repository and entry.get("tag"):
            return entry["tag"]
    return DEFAULT_TAG


def discover(lock: dict) -> list[dict]:
    images = []
    for dockerfile in sorted((ROOT / "docker").glob("*/Dockerfile")):
        d = dockerfile.parent
        text = dockerfile.read_text()
        froms = _FROM_RE.findall(text)
        deps = sorted({f.split("@")[0].split(":")[0].removeprefix(REGISTRY + "/")
                       for f in froms if f.startswith(REGISTRY + "/")})
        variants_file = d / "variants.json"
        variants = json.loads(variants_file.read_text()) if variants_file.is_file() else [{"name": d.name}]
        for v in variants:
            name = v["name"]
            repository = f"{REGISTRY}/{name}"
            tag = v.get("tag") or _tag_for(repository, lock)
            args = v.get("build_args") or {}
            if not _NAME_RE.match(name) or not _TAG_RE.match(tag):
                raise SystemExit(f"bad image name or tag: {name}:{tag}")
            for key, value in args.items():
                if not _ARG_RE.match(key) or not re.match(r"^[A-Za-z0-9_.:/@+-]{0,200}$", str(value)):
                    raise SystemExit(f"bad build arg in {name}: {key}")
            images.append({
                "name": name, "dir": d.relative_to(ROOT).as_posix(),
                "dockerfile": dockerfile.relative_to(ROOT).as_posix(),
                "repository": repository, "tag": tag, "build_args": args, "deps": deps,
                # the FROM refs a dependant names, overridden at build time by the dep's digest
                "dep_refs": sorted({f for f in froms if f.startswith(REGISTRY + "/")}),
            })
    names = {i["name"] for i in images}
    for i in images:
        missing = set(i["deps"]) - names
        if missing:
            raise SystemExit(f"{i['name']} depends on unknown images {sorted(missing)}")
    return images


def plan(only: set[str] | None) -> dict:
    images = discover(_load_lock())
    by_name = {i["name"]: i for i in images}
    level = {}
    for i in images:
        level[i["name"]] = 0 if not i["deps"] else 1
    for i in images:
        if any(level[d] != 0 for d in i["deps"]):
            raise SystemExit(f"{i['name']}: dependency chains deeper than two levels are not supported")
    if only:
        unknown = only - set(by_name)
        if unknown:
            raise SystemExit(f"unknown images {sorted(unknown)}")
        wanted = set(only)
        for n in only:
            wanted.update(by_name[n]["deps"])  # a dependant is always built on a fresh dep
        images = [i for i in images if i["name"] in wanted]
    return {
        "level0": [i for i in images if level[i["name"]] == 0],
        "level1": [i for i in images if level[i["name"]] == 1],
        "platform": PLATFORM,
    }


def lock(results_dir: Path) -> int:
    data = _load_lock()
    results = [json.loads(p.read_text()) for p in sorted(results_dir.rglob("*.json"))]
    if not results:
        print("no results", file=sys.stderr)
        return 1
    changed = []
    for r in results:
        repo, digest, tag = r["repository"], r["digest"], r["tag"]
        if not repo.startswith(REGISTRY + "/") or not _DIGEST_RE.match(digest):
            raise SystemExit(f"bad result {r}")
        matched = [k for k, e in data["images"].items() if e.get("repository") == repo]
        # An entry of the same name pinned to an upstream repository (solana-build) is left alone.
        if not matched and r["name"] in data["images"]:
            print(f"{r['name']}: lock entry pins another repository; add an alias entry", file=sys.stderr)
            continue
        if not matched:
            data["images"][r["name"]] = {"repository": repo, "tag": tag, "digest": digest,
                                         "platforms": [PLATFORM], "tools": {}}
            matched = [r["name"]]
        for key in matched:
            entry = data["images"][key]
            entry.update(tag=tag, digest=digest, platforms=[PLATFORM])
            entry["built"] = {"commit": r.get("commit"), "run_id": r.get("run_id"), "trivy_critical": r.get("trivy_critical")}
            changed.append(f"{key} {repo}@{digest}")
    data["images"] = dict(sorted(data["images"].items()))
    LOCK.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
    print("\n".join(changed))
    return 0


def build_argv(image: dict, deps_dir: Path | None) -> list[str]:
    """`docker buildx build` options for one plan entry, one per line (no shell parsing).

    Each in-repo FROM is replaced by the dependency's pushed digest through a named build
    context, so a dependant never builds on a floating tag."""
    argv = ["--platform", PLATFORM, "--provenance=false", "--sbom=false", "-f", image["dockerfile"]]
    for key, value in sorted(image["build_args"].items()):
        argv += ["--build-arg", f"{key}={value}"]
    for ref in image["dep_refs"]:
        dep = ref.split("@")[0].split(":")[0].removeprefix(REGISTRY + "/")
        result = (deps_dir / f"{dep}.json") if deps_dir else None
        if result is None or not result.is_file():
            raise SystemExit(f"{image['name']}: no pushed digest for dependency {dep}")
        r = json.loads(result.read_text())
        if not _DIGEST_RE.match(r["digest"]):
            raise SystemExit(f"bad digest for {dep}")
        argv += ["--build-context", f"{ref}=docker-image://{r['repository']}@{r['digest']}"]
    return argv


def check() -> int:
    data = _load_lock()
    bad = []
    for key, e in data["images"].items():
        if not _DIGEST_RE.match(e.get("digest", "")):
            bad.append(f"{key}: digest")
        if "@" in e.get("repository", "") or ":" in e.get("repository", "").split("/")[-1]:
            bad.append(f"{key}: repository must carry no tag or digest")
    print("\n".join(bad) or "ok")
    return 1 if bad else 0


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    if argv[0] == "plan":
        only = None
        if len(argv) > 2 and argv[1] == "--only" and argv[2].strip():
            only = {s.strip() for s in argv[2].split(",") if s.strip()}
        print(json.dumps(plan(only)))
        return 0
    if argv[0] == "lock":
        return lock(Path(argv[1]))
    if argv[0] == "check":
        return check()
    if argv[0] == "argv":
        image = json.loads(argv[1])
        deps_dir = Path(argv[2]) if len(argv) > 2 and argv[2] else None
        print("\n".join(build_argv(image, deps_dir)))
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
