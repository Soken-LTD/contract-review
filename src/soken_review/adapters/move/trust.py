"""Move build-input trust scan (plan v4 07 6.2, 7.2 with the 06 3.3.4 rule: never tier A).

Move has no build scripts, but a source tree can still carry inputs that make a rebuild prove
nothing about the code under review: prebuilt bytecode (`*.mv`, `build/` output) that a package
manager can link or that could stand in for compiled output, and manifest fields outside the
strict allow-list.  Such a candidate is still built and analyzed; the flag makes the provenance
decision `not_checkable` (`build_input_untrusted`).

Design rule (wave-8): every check is a POSITIVE gate.  A value is trusted only when it passes
a positive test; absence of a declared set is not permission.  The function returns reasons
for every element that did NOT pass a positive check.

Strict allow-list for Move.toml fields (wave-6/7/8):

  [package]          name, version, authors, license only; must be a TOML table (dict);
                     any other key (upgrade_policy, edition, flavor, published-at …) → flag
  [addresses]        must be a TOML table; each value must be either:
                       (a) a framework address (0x1–0x4), or
                       (b) a value in the caller-supplied declared_addresses set;
                     "_" placeholder, non-string value, unverifiable address → flag
  [dependencies]     must be a TOML table; each entry must be a table containing exactly:
                       {local = <inside pinned tree>}  OR
                       {git = <https URL>, rev = <40-char sha> [, subdir = <safe rel path>]}
                     local+git together → manifest_dep_ambiguous;
                     non-string local/git → flag; non-sha rev → flag;
                     subdir with ".." or absolute → flag;
                     empty dep or unknown form → manifest_dep_unknown_form
  prebuilt *.mv      case-insensitive suffix match; Build/bytecode_modules case-insensitive
  Anything else      → manifest_disallowed_field reason → BUILD_INPUT_UNTRUSTED

Fields such as ``[build]`` compiler flags, ``dev-addresses``, and ``dev-dependencies`` can change
compiled bytecode or override addresses, making a rebuild non-comparable to the deployed artifact.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import PurePosixPath

_GIT_OK = re.compile(r"^https://[A-Za-z0-9.-]+/[A-Za-z0-9_.\-/]+$")
_SHA40 = re.compile(r"[0-9a-f]{40}", re.IGNORECASE)

# Top-level TOML table names that are safe to keep (all others → flag).
_ALLOWED_SECTIONS: frozenset[str] = frozenset({"package", "addresses", "dependencies"})

# Keys allowed inside [package]; anything else can change the compiled artifact.
_ALLOWED_PACKAGE_KEYS: frozenset[str] = frozenset({"name", "version", "authors", "license"})

# Keys allowed inside a single dependency entry.
_ALLOWED_DEP_KEYS: frozenset[str] = frozenset({"local", "git", "rev", "subdir"})

# Framework addresses: 0x1–0x4 (Sui stdlib/framework, Aptos stdlib/token).
# Comparison is on the bare hex digits, leading-zero-stripped.
_FRAMEWORK_SHORTS: frozenset[str] = frozenset({"1", "2", "3", "4"})


def _is_framework_addr(value: str) -> bool:
    s = str(value).strip().lower().removeprefix("0x")
    if not re.fullmatch(r"[0-9a-f]+", s):
        return False
    return s.lstrip("0") in _FRAMEWORK_SHORTS


def _addr_stripped(value: str) -> str:
    """Normalise: lowercase, strip 0x, strip leading zeros (or keep '0' for zero)."""
    return value.strip().lower().removeprefix("0x").lstrip("0") or "0"


def scan(files: dict[str, str], declared_addresses: set[str] | None = None) -> list[str]:
    """Reasons the candidate's build inputs are untrusted (empty = all checks passed).

    *declared_addresses* — normalised hex addresses known to belong to this package
    (from chain-state metadata).  Absence of this set causes every non-framework address
    to be flagged as ``manifest_address_unverified`` (positive gate: no declared set ≠
    permission to trust any address).
    """
    reasons: list[str] = []
    for path, content in sorted(files.items()):
        # Case-insensitive prebuilt detection: .MV, .Mvsm, Build/, build/
        pl = PurePosixPath(path.lower())
        if pl.suffix in (".mv", ".mvsm") or "bytecode_modules" in pl.parts:
            reasons.append(f"prebuilt_bytecode:{path}")
        elif PurePosixPath(path).name == "Move.toml":
            reasons += _manifest(path, content, declared_addresses)
    return reasons


def _manifest(path: str, text: str, declared_addresses: set[str] | None = None) -> list[str]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return [f"manifest_unparsable:{path}"]
    out: list[str] = []

    # 1. Top-level section allow-list.
    for section in data:
        if section not in _ALLOWED_SECTIONS:
            out.append(f"manifest_disallowed_field:{path}:[{section}]")

    # 2. [package] — must be a dict; per-key allow-list.
    pkg = data.get("package")
    if pkg is not None:
        if not isinstance(pkg, dict):
            out.append(f"manifest_bad_section_type:{path}:[package]")
        else:
            for key in pkg:
                if key not in _ALLOWED_PACKAGE_KEYS:
                    out.append(f"manifest_disallowed_field:{path}:[package].{key}")

    # 3. [addresses] — must be a dict; positive gate on each value.
    addrs = data.get("addresses")
    if addrs is not None:
        if not isinstance(addrs, dict):
            out.append(f"manifest_bad_section_type:{path}:[addresses]")
        else:
            norm_declared = {_addr_stripped(da) for da in declared_addresses} if declared_addresses else set()
            for name, value in addrs.items():
                if value == "_":
                    # Placeholder: address not bound at analysis time.
                    out.append(f"manifest_address_placeholder:{path}:{name}")
                elif not isinstance(value, str):
                    out.append(f"manifest_bad_address:{path}:{name}")
                elif _is_framework_addr(value):
                    pass  # positive: framework address is always trusted
                elif norm_declared and _addr_stripped(value) in norm_declared:
                    pass  # positive: matches declared package address
                else:
                    # No positive proof → flag regardless of whether declared set is available.
                    out.append(f"manifest_address_unverified:{path}:{name}")

    # 4. [dependencies] — must be a dict; per-entry positive gate.
    deps = data.get("dependencies")
    if deps is not None:
        if not isinstance(deps, dict):
            out.append(f"manifest_bad_section_type:{path}:[dependencies]")
        else:
            base = PurePosixPath(path).parent
            for name, dep in deps.items():
                if not isinstance(dep, dict):
                    out.append(f"manifest_disallowed_field:{path}:dependencies.{name}")
                    continue
                # Disallowed keys.
                for dep_key in dep:
                    if dep_key not in _ALLOWED_DEP_KEYS:
                        out.append(f"manifest_disallowed_field:{path}:dependencies.{name}.{dep_key}")
                # Ambiguous: both local and git present.
                has_local = "local" in dep
                has_git = "git" in dep
                if has_local and has_git:
                    out.append(f"manifest_dep_ambiguous:{path}:{name}")
                elif has_local:
                    local = dep["local"]
                    if not isinstance(local, str):
                        out.append(f"manifest_dep_local_not_string:{path}:{name}")
                    else:
                        target = _norm(base / local)
                        if target is None:
                            out.append(f"local_dependency_outside_tree:{path}:{name}")
                elif has_git:
                    git = dep["git"]
                    if not isinstance(git, str):
                        out.append(f"manifest_dep_git_not_string:{path}:{name}")
                    elif not _GIT_OK.match(git.strip()):
                        out.append(f"git_dependency_not_https:{path}:{name}")
                    # rev must be a pinned 40-char SHA.
                    rev = dep.get("rev", "")
                    if not isinstance(rev, str) or not _SHA40.fullmatch(rev):
                        out.append(f"manifest_dep_rev_not_pinned:{path}:{name}")
                    # subdir, if present, must be a safe relative path.
                    if "subdir" in dep:
                        subdir = dep["subdir"]
                        if not isinstance(subdir, str):
                            out.append(f"manifest_dep_subdir_not_string:{path}:{name}")
                        elif _norm(PurePosixPath(subdir)) is None:
                            out.append(f"manifest_dep_subdir_unsafe:{path}:{name}")
                else:
                    # Neither local nor git — unknown dep form (includes empty dict).
                    out.append(f"manifest_dep_unknown_form:{path}:{name}")

    return out


def _norm(p: PurePosixPath) -> PurePosixPath | None:
    if p.is_absolute():
        return None
    parts: list[str] = []
    for part in p.parts:
        if part in ("", "."):
            continue
        if part == "..":
            if not parts:
                return None
            parts.pop()
        else:
            parts.append(part)
    return PurePosixPath(*parts) if parts else PurePosixPath(".")
