"""Sui build step and deployment comparison (plan v4 07 sections 4, 6.2, 9.1).

  build   (ALWAYS --network=none, MOVE_HOME r/o):  sui move build --install-dir /work/out
  compare (supervisor, host only):                  DESIGN.md checks against chain_state

The pinned source is mounted read-only; only /work/out receives artifacts.  The build container
NEVER gets network access (step = "build" → sandbox profile sets --network=none regardless of
any manifest or lockfile content; no condition, no parser, no decision from Move.toml/Move.lock).

Dependency supply:
  * Framework packages (Sui, MoveStdlib) are baked into the image at /opt/sui-framework.
  * External (git) deps must be fetched by the supervisor via soken_review.sandbox.git_materializer
    (hosts allow-listed, pinned by rev) and placed in the offline MOVE_HOME cache before build()
    is called.  If a dep was not pre-fetched, sui move build fails offline →
    build.status = "failed" / reason "build_failed" → supervisor maps it to insufficient_source.
    This is fail-closed by construction: the container never gets network to compensate.

Toolchain: the recorded version (Published.toml, then Move.lock) decides `mismatch` vs
`not_checkable` (07 3.1, 9.1); this image is mainnet-v1.81.1 and a different recorded version
is `toolchain_unavailable`.
"""

from __future__ import annotations

import json
import re
import tempfile
import tomllib
from pathlib import Path
from typing import Any

from soken_review.adapters.base import BuildResult, Candidate
from soken_review.adapters.move import sandbox, trust
from soken_review.adapters.move.provenance import sui_dep_match
from soken_review.adapters.move.units import count_nsloc, declared_modules, is_in_scope, write_tree

IMAGE_VERSION = "1.81.1"
LINT_VERSION = IMAGE_VERSION
_SBX = Path(__file__).resolve().parents[4] / ".sbx"
_SKIP_GIT = "--skip-fetch-latest-" + "git-deps"
_FRAMEWORK = "/opt/sui-framework"

# Dep name → local image path (inside the sui-build image, from the sparse-clone of MystenLabs/sui).
# Used as the cp source when pre-populating MOVE_HOME for framework git deps.
_FRAMEWORK_LOCALS: dict[str, str] = {
    "Sui":        f"{_FRAMEWORK}/sui-framework",
    "MoveStdlib": f"{_FRAMEWORK}/move-stdlib",
    "SuiSystem":  f"{_FRAMEWORK}/sui-system",
    "Deepbook":   f"{_FRAMEWORK}/deepbook",
    "Bridge":     f"{_FRAMEWORK}/bridge",
}

_IMAGE_MAP_CACHE: dict | None = None


def _image_map() -> dict:
    """Load data/image_map.json (cached).  Records framework_url, framework_commit,
    and framework_packages subdir per dep name (verified from Sui 1.81.1 source tree)."""
    global _IMAGE_MAP_CACHE
    if _IMAGE_MAP_CACHE is None:
        p = Path(__file__).parent / "data" / "image_map.json"
        _IMAGE_MAP_CACHE = json.loads(p.read_text())
    return _IMAGE_MAP_CACHE


def dep_cache_url_sanitize(url: str) -> str:
    """Replicate url_to_file_name from Sui CLI 1.81.1.

    Source: external-crates/move/crates/move-package-alt/src/git/cache.rs
      fn url_to_file_name(url: &str) -> String {
          regex::Regex::new(r"/|:|\\.|\\.@").unwrap().replace_all(url, "_").to_string()
      }
    The regex matches each of [/ : . @] individually and replaces with _.
    """
    return re.sub(r'[/:.@]', '_', url)


def git_dep_cache_path(move_home_container: str, url: str, rev: str, subdir: str) -> str:
    """Compute the container-side MOVE_HOME cache path for a git dep.

    Format: $MOVE_HOME/git/{url_to_file_name(url)}_{rev}/{subdir}
    Source: external-crates/move/crates/move-package-alt/src/git/cache.rs
      get_cache_path()  → MOVE_HOME.join("git")
      tree_for_sha()    → root_dir.join(format!("{filename}_{sha}"))
      path_to_tree()    → path_to_repo.join(path_in_repo)
    """
    return f"{move_home_container}/git/{dep_cache_url_sanitize(url)}_{rev}/{subdir}"


def populate_move_home_deps(
    files: dict[str, str],
    pkg_dir: str,
    chain: str,
    dirs: dict[str, Path],
) -> str | None:
    """Populate the host-side MOVE_HOME cache with framework git deps from Move.lock.

    Never modifies Move.lock or Move.toml.  For each git dep in Move.lock:

    - If (url, rev) EXACTLY matches the image framework commit recorded in image_map.json
      AND name is in the framework package map: the framework package is copied from the
      image's /opt/sui-framework/{name} to the CLI-expected MOVE_HOME cache path
      by running a deps-step container (deps step mounts /work/move writable).
    - Otherwise (wrong URL, wrong rev, unknown name, non-framework dep):
      returns a deps_unreachable error string (fail closed; the offline build then fails
      naturally — the container never gets network to compensate).

    Move.lock absent or non-TOML: returns None — let the offline build fail naturally.

    Returns None on success, error string on failure.
    """
    lock_path = "Move.lock" if pkg_dir in (".", "") else f"{pkg_dir}/Move.lock"
    if lock_path not in files:
        return None  # No lock → offline build will fail naturally (no git deps)

    try:
        data = tomllib.loads(files[lock_path])
    except tomllib.TOMLDecodeError:
        return None  # Unparsable → same

    deps = (data.get("move") or {}).get("dependency") or []
    if not isinstance(deps, list):
        return None

    meta = _image_map().get(IMAGE_VERSION) or {}
    image_url: str = meta.get("framework_url", "")
    image_commit: str = meta.get("framework_commit", "")
    pkg_subdirs: dict[str, str] = meta.get("framework_packages") or {}

    _CONTAINER_MOVE_HOME = "/work/move"

    for dep in deps:
        if not isinstance(dep, dict):
            continue
        source = dep.get("source") or {}
        if "local" in source:
            continue  # Already resolved, no fetch needed
        if "git" not in source:
            continue  # on-chain or unknown variant: offline build handles it

        url: str = source.get("git", "")
        rev: str = source.get("rev", "")
        subdir: str = source.get("subdir", "")
        name: str = dep.get("name", "")

        # Identity check: url+rev must match exactly, and name must be in our framework map.
        # A dep named "Sui" pointing to a different repo or rev is NOT substituted — fail closed.
        if url != image_url or rev != image_commit or name not in _FRAMEWORK_LOCALS:
            return (
                f"dep {name!r}: git url/rev does not match image framework commit "
                f"(url={url!r} rev={rev!r}); deps_unreachable"
            )

        expected_subdir = pkg_subdirs.get(name)
        if expected_subdir is None:
            return f"dep {name!r}: name not in image_map framework_packages; deps_unreachable"

        if subdir and subdir != expected_subdir:
            return (
                f"dep {name!r}: subdir {subdir!r} != image framework subdir "
                f"{expected_subdir!r}; deps_unreachable"
            )

        # Compute the host-side cache path (mirrors the container-side path)
        url_san = dep_cache_url_sanitize(url)
        host_cache = dirs["move"] / "git" / f"{url_san}_{rev}" / expected_subdir

        if host_cache.exists():
            continue  # Already populated (restartable step)

        # Create the parent directory on the host side (container will see it as writable)
        host_cache.parent.mkdir(parents=True, exist_ok=True)

        # Run a deps-step container to copy the framework package into the MOVE_HOME cache.
        # deps step mounts dirs["move"] as /work/move (writable).
        # cp -r {src}/ {parent}/ copies the directory into parent creating parent/basename.
        src_in_image = _FRAMEWORK_LOCALS[name]           # e.g. /opt/sui-framework/sui-framework
        parent_container = git_dep_cache_path(           # parent of the target path
            _CONTAINER_MOVE_HOME, url, rev, expected_subdir
        ).rsplit("/", 1)[0]
        run = sandbox.run(
            chain, "deps", dirs,
            ["cp", "-r", src_in_image, parent_container + "/"],
            timeout=60,
        )
        if run.returncode != 0:
            return (
                f"dep {name!r}: failed to copy framework to MOVE_HOME cache "
                f"(exit {run.returncode}): {run.stderr[:200]}"
            )
        if not host_cache.exists():
            return (
                f"dep {name!r}: copy succeeded but cache path missing: {host_cache}"
            )

    return None


def in_scope_for(c: Candidate):
    d = (c.settings or {}).get("package_dir") or "."
    return lambda path: is_in_scope(path, (d,))


def load_chain_state(c: Candidate) -> dict[str, Any] | None:
    f = (c.settings or {}).get("chain_state_file")
    return json.loads(Path(f).read_text()) if f else None


def _pkg_path(pkg_dir: str) -> str:
    return "/work/src" if pkg_dir in (".", "") else f"/work/src/{pkg_dir}"


def lint_argv(pkg_dir: str) -> list[str]:
    return ["sui", "move", "build", "--lint", "--path", _pkg_path(pkg_dir), "--install-dir", "/work/out/lint", _SKIP_GIT]


def inline_manifest(named: dict[str, str]) -> str:
    """07 4 fixed template: package name, edition, framework deps from the image, named addresses 0x0."""
    lines = ['[package]', 'name = "inline"', 'edition = "2024"', "", "[dependencies]",
             f'Sui = {{ local = "{_FRAMEWORK}/sui-framework" }}', f'MoveStdlib = {{ local = "{_FRAMEWORK}/move-stdlib" }}',
             "", "[addresses]"]
    lines += [f'{n} = "0x0"' for n in sorted(named)]
    return "\n".join(lines) + "\n"


def build(c: Candidate, work_dir: Path | None = None) -> BuildResult:
    _SBX.mkdir(exist_ok=True)
    work = work_dir or Path(tempfile.mkdtemp(dir=_SBX))
    try:
        dirs = sandbox.prepare_dirs(work)
    except PermissionError as exc:
        return BuildResult(candidate=c, status="failed", reason="sandbox_unavailable", stderr_head=str(exc))
    host = dirs["host"]
    settings = c.settings or {}
    reasons = trust.scan(c.files)
    if reasons:
        c.untrusted_inputs = True
        sandbox.write_host(host / "untrusted_inputs.txt", "\n".join(reasons))
    cs = load_chain_state(c)
    onchain = {}
    if cs:
        import base64
        onchain = {n: base64.b64decode(b) for n, b in cs.get("modules", {}).items()}
    tc = settings.get("toolchain") or {}
    toolchain = {"recorded": tc.get("version"), "recorded_from": tc.get("source"), "image": IMAGE_VERSION,
                 "matches": tc.get("version") == IMAGE_VERSION}
    pkg_dir = settings.get("package_dir") or "."
    in_scope = in_scope_for(c)
    nsloc = sum(count_nsloc(t) for p, t in c.files.items() if in_scope(p))

    def finish(rebuilt: dict[str, bytes] | None, reason: str | None, status: str, detail: str | None) -> BuildResult:
        prov = sui_dep_match(cs or {}, onchain, rebuilt, untrusted=c.untrusted_inputs, toolchain=toolchain,
                             built_original_id=tc.get("original_id"), build_reason=reason) if cs else \
            {"chain": "sui", "dep_match": None, "reason": "no_deployment"}
        if rebuilt is not None:
            declared = set()
            for p, t in c.files.items():
                if in_scope(p):
                    declared |= declared_modules(t)
            unmapped = sorted(set(rebuilt) - declared)
            if unmapped:
                prov["source_module_unmapped"] = unmapped
                if prov.get("dep_match") not in ("mismatch", None):
                    prov |= {"dep_match": "not_checkable", "reason": "source_module_unmapped"}
        prov |= {"untrusted_reasons": reasons}
        sandbox.write_host(host / "provenance.json", json.dumps(prov, indent=2))
        if status != "ok":
            return BuildResult(candidate=c, status="failed", reason=reason, stderr_head=detail, nsloc=nsloc,
                               work_dir=str(work))
        return BuildResult(candidate=c, status="ok", nsloc=nsloc, work_dir=str(work))

    tree = {p: t for p, t in c.files.items() if not p.endswith((".mv", ".mvsm")) and "bytecode_modules" not in p}
    if settings.get("kind") == "inline":
        tree["Move.toml"] = inline_manifest(settings.get("named_addresses") or {})
    if write_tree(tree, dirs["src"]):
        return finish(None, "build_failed", "failed", "unsafe path in candidate")
    try:
        sandbox.image_for("sui")
    except sandbox.SandboxUnavailable as exc:
        return BuildResult(candidate=c, status="failed", reason="sandbox_unavailable", stderr_head=str(exc))

    path = _pkg_path(pkg_dir)
    # Build always runs offline (step = "build" → sandbox profile enforces --network=none).
    # External deps must be pre-populated in MOVE_HOME by the supervisor via git_materializer.
    # Any dep not pre-fetched → build fails offline → insufficient_source (fail-closed).
    run = sandbox.run("sui", "build", dirs, ["sui", "move", "build", "--path", path, "--install-dir", "/work/out",
                                             _SKIP_GIT], timeout=sandbox.BUILD_WALL_S)
    sandbox.write_host(host / "build.log", run.stdout + "\n" + run.stderr)
    if run.returncode != 0:
        return finish(None, "build_failed", "failed", _tail(run))
    arts = sandbox.read_artifacts(dirs["out"] / "build")
    name = settings.get("package_name") or "inline"
    prefix = f"{name}/bytecode_modules/"
    rebuilt = {k[len(prefix):-3]: v for k, v in arts.items() if k.startswith(prefix) and "/" not in k[len(prefix):]}
    if not rebuilt:
        return finish(None, "build_failed", "failed", f"no modules under build/{name}; got {sorted(arts)[:5]}")
    for mod, data in rebuilt.items():
        sandbox.write_host(host / "artifacts" / name / f"{mod}.mv", data)
    return finish(rebuilt, None, "ok", None)


def _tail(run: sandbox.RunResult) -> str:
    return "\n".join((run.stderr.strip() or run.stdout.strip()).splitlines()[-20:])


def _check_move_lock(files: dict[str, str], pkg_dir: str = ".") -> str | None:
    """Read Move.lock and report the first non-local dep, or None if all deps are local.

    Used by the supervisor to identify which deps need pre-fetching via git_materializer
    before the offline build runs.  An unknown dep source variant returns a description
    so the supervisor can skip pre-fetching it; the offline build then fails, which is
    the desired fail-closed outcome.

    NOTE: this function does NOT gate network access.  The build container ALWAYS runs
    with --network=none (step = "build" in sandbox.run).  This function is a dep-list
    reader only.

      * Move.lock absent   → returns description (supervisor skips pre-fetch; build fails)
      * Move.lock invalid  → returns description
      * source = {local}   → None (dep already local; no pre-fetch needed)
      * source = {git/...} → returns description (supervisor must pre-fetch this dep)
      * unknown source key → returns description (supervisor skips; build fails offline)
    """
    import tomllib

    lock_path = "Move.lock" if pkg_dir in (".", "") else f"{pkg_dir}/Move.lock"
    if lock_path not in files:
        return f"Move.lock absent at {lock_path!r}"
    try:
        data = tomllib.loads(files[lock_path])
    except tomllib.TOMLDecodeError:
        return f"Move.lock unparsable at {lock_path!r}"

    deps = (data.get("move") or {}).get("dependency") or []
    if not isinstance(deps, list):
        return "Move.lock: [move.dependency] is not an array"
    for dep in deps:
        if not isinstance(dep, dict):
            return f"Move.lock: dependency entry is not a dict: {dep!r:.60}"
        name = dep.get("name", "<unnamed>")
        source = dep.get("source")
        if not isinstance(source, dict):
            return f"{name}: source is not a dict: {source!r:.60}"
        if "local" not in source:
            source_kind = next(iter(source), "empty") if source else "empty"
            return f"{name}: non-local source ({source_kind!r}) — supervisor must pre-fetch"
        unknown_src_keys = set(source.keys()) - {"local"}
        if unknown_src_keys:
            return f"{name}: local source has unrecognised keys {sorted(unknown_src_keys)}"
    return None


def _check_dep_allowlist(files: dict[str, str]) -> str | None:
    """Compatibility shim; delegates to _check_move_lock."""
    return _check_move_lock(files)
