"""Move trust scan: strict allow-list for Move.toml fields (wave-6 security fix).

The trust scan previously only checked for unsafe dep forms (local escaping tree,
non-https git).  It now also flags any top-level TOML section outside the allow-list
(``[package]``, ``[addresses]``, ``[dependencies]``).

Fields such as ``[build]`` (compiler flags, language_version), ``[dev-addresses]``
(address overrides active in dev mode), and ``[dev-dependencies]`` can change
compiled bytecode or override named addresses, making a rebuild non-comparable to
the deployed artifact.  When any such field is present the trust scan returns a
``manifest_disallowed_field`` reason → ``c.untrusted_inputs = True`` → tier B,
not tier A (plan 07 7.2 + 06 3.3.4).
"""

from __future__ import annotations

import pytest

from soken_review.adapters.move.trust import scan

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _toml_files(**sections: str) -> dict[str, str]:
    """Build a minimal files dict with a single Move.toml whose body is the concatenation
    of the given section strings keyed by section header."""
    body = "\n".join(f"[{k}]\n{v}" for k, v in sections.items())
    return {"Move.toml": body}


# ---------------------------------------------------------------------------
# Tests that FAIL before the fix (disallowed fields not previously flagged)
# ---------------------------------------------------------------------------

def test_build_section_flags_manifest_as_untrusted():
    """A ``[build]`` section in Move.toml must trigger BUILD_INPUT_UNTRUSTED.

    ``[build]`` can set compiler flags and ``language_version`` that affect
    the compiled bytecode, making a rebuild non-comparable to deployed artifacts.
    Before the fix: ``[build]`` was silently accepted.
    After the fix: any ``[build]`` section → ``manifest_disallowed_field`` reason.
    """
    files = {"Move.toml": '[package]\nname = "pkg"\n\n[build]\nlanguage_version = "2.0"\n'}
    reasons = scan(files)
    assert any("manifest_disallowed_field" in r and "[build]" in r for r in reasons), (
        f"[build] section must be flagged; got: {reasons}"
    )


def test_dev_addresses_section_flags_manifest_as_untrusted():
    """A ``[dev-addresses]`` section must trigger BUILD_INPUT_UNTRUSTED.

    ``[dev-addresses]`` can override named addresses during dev/test compilation.
    If a repo targets ``dev-addresses`` to redirect module IDs, the rebuilt artifact
    will differ from the deployed one.
    Before the fix: ``[dev-addresses]`` was silently accepted.
    """
    files = {
        "Move.toml": '[package]\nname = "pkg"\n\n[dev-addresses]\nadmin = "0xBEEF"\n'
    }
    reasons = scan(files)
    assert any("manifest_disallowed_field" in r and "[dev-addresses]" in r for r in reasons), (
        f"[dev-addresses] section must be flagged; got: {reasons}"
    )


def test_dev_dependencies_section_flags_manifest_as_untrusted():
    """A ``[dev-dependencies]`` section must trigger BUILD_INPUT_UNTRUSTED.

    ``[dev-dependencies]`` can pull in extra code that is compiled when
    ``--dev`` mode is active.  A malicious dev-dep could redefine a module.
    """
    files = {
        "Move.toml": '[package]\nname = "pkg"\n\n[dev-dependencies]\nFakeOracle = { git = "https://github.com/a/b" }\n'
    }
    reasons = scan(files)
    assert any("manifest_disallowed_field" in r and "[dev-dependencies]" in r for r in reasons), (
        f"[dev-dependencies] section must be flagged; got: {reasons}"
    )


def test_unknown_top_level_section_flags_manifest():
    """Any unrecognised top-level section (e.g. ``[scripts]``) must be flagged."""
    files = {"Move.toml": '[package]\nname = "pkg"\n\n[scripts]\ncheck = "aptos move test"\n'}
    reasons = scan(files)
    assert any("manifest_disallowed_field" in r for r in reasons), (
        f"unknown section must be flagged; got: {reasons}"
    )


# ---------------------------------------------------------------------------
# Tests for correct clean-manifest behaviour (must NOT flag allowed fields)
# ---------------------------------------------------------------------------

def test_clean_manifest_is_trusted():
    """A Move.toml with only allowed sections must NOT be flagged."""
    files = {
        "Move.toml": (
            '[package]\nname = "MyPkg"\nversion = "1.0.0"\n\n'
            '[addresses]\nmy_addr = "0x" + "0" * 64 + "\n\n"'
            '[dependencies]\nMoveStdlib = { local = "/opt/stdlib" }\n'
        )
    }
    reasons = scan(files)
    assert not any("manifest_disallowed_field" in r for r in reasons), (
        f"clean manifest must not be flagged; got: {reasons}"
    )


def test_clean_manifest_with_valid_local_dep_is_trusted():
    """A manifest with a local dep inside the tree must not trigger trust warnings."""
    files = {
        "packages/a/Move.toml": '[package]\nname = "A"\n\n[dependencies]\nB = { local = "../b" }\n',
        "packages/b/Move.toml": '[package]\nname = "B"\n',
    }
    reasons = scan(files)
    assert not reasons, f"clean tree-local dep must not be flagged; got: {reasons}"


def test_manifest_with_disallowed_field_and_local_dep_outside_tree():
    """Both reasons must be present when a manifest has both a disallowed field and an
    unsafe local dependency."""
    files = {
        "Move.toml": (
            '[package]\nname = "pkg"\n\n'
            '[build]\nflags = ["--skip-checks"]\n\n'
            '[dependencies]\nEvil = { local = "../../outside/pkg" }\n'
        )
    }
    reasons = scan(files)
    assert any("manifest_disallowed_field" in r and "[build]" in r for r in reasons)
    assert any("local_dependency_outside_tree" in r for r in reasons)


def test_prebuilt_bytecode_still_flagged():
    """Prebuilt `.mv` files remain flagged regardless of manifest content."""
    files = {
        "Move.toml": '[package]\nname = "pkg"\n',
        "build/pkg/bytecode_modules/MyMod.mv": b"\x00\x00\x00\x00".decode("latin-1"),
    }
    reasons = scan(files)
    assert any("prebuilt_bytecode" in r for r in reasons)


# ---------------------------------------------------------------------------
# Wave-7: per-key checks inside allowed sections
# ---------------------------------------------------------------------------

def test_package_edition_key_is_disallowed():
    """``edition`` inside [package] must be flagged (wave-7 per-key check).

    ``edition`` selects the Move compiler edition (e.g. "2024.beta"), which can
    change language semantics and compiled bytecode.  Before the fix: only section
    names were checked; ``edition`` inside [package] was accepted silently.
    After the fix: ``manifest_disallowed_field`` for ``[package].edition``.
    """
    files = {"Move.toml": '[package]\nname = "pkg"\nedition = "2024.beta"\n'}
    reasons = scan(files)
    assert any("manifest_disallowed_field" in r and "[package].edition" in r for r in reasons), (
        f"[package].edition must be flagged; got: {reasons}"
    )


def test_package_upgrade_policy_key_is_disallowed():
    """``upgrade_policy`` inside [package] must be flagged (wave-7 per-key check).

    ``upgrade_policy`` controls on-chain upgradeability semantics.  It can make the
    compiled artifact non-comparable to the deployed one if it differs between the
    source tree and the chain state.
    Before the fix: ``upgrade_policy`` inside [package] was accepted silently.
    After the fix: ``manifest_disallowed_field`` for ``[package].upgrade_policy``.
    """
    files = {"Move.toml": '[package]\nname = "pkg"\nupgrade_policy = "compatible"\n'}
    reasons = scan(files)
    assert any("manifest_disallowed_field" in r and "[package].upgrade_policy" in r for r in reasons), (
        f"[package].upgrade_policy must be flagged; got: {reasons}"
    )


def test_package_published_at_key_is_disallowed():
    """``published-at`` inside [package] must be flagged (wave-7 per-key check).

    ``published-at`` embeds the on-chain package address directly in the manifest,
    which can mislead the analysis into trusting an attacker-supplied address.
    """
    files = {
        "Move.toml": (
            '[package]\nname = "pkg"\n'
            'published-at = "0xdeadbeef"\n'
        )
    }
    reasons = scan(files)
    assert any("manifest_disallowed_field" in r and "[package].published-at" in r for r in reasons), (
        f"[package].published-at must be flagged; got: {reasons}"
    )


def test_addresses_placeholder_is_untrusted():
    """A ``_`` placeholder value in [addresses] must be flagged (wave-7).

    The placeholder means "this address is not yet bound".  The compiled artifact
    used the substitution provided at build time, which is unknown to the analysis.
    Before the fix: placeholder values were accepted silently.
    After the fix: ``manifest_address_placeholder`` reason.
    """
    files = {
        "Move.toml": '[package]\nname = "pkg"\n\n[addresses]\nadmin = "_"\n'
    }
    reasons = scan(files)
    assert any("manifest_address_placeholder" in r and "admin" in r for r in reasons), (
        f"_ placeholder must be flagged; got: {reasons}"
    )


def test_addresses_framework_address_is_not_flagged():
    """Framework addresses (0x1, 0x2, 0x3, 0x4) in [addresses] must NOT be flagged.

    These are well-known immutable framework modules; their addresses are fixed
    by the chain and do not require a declared-address cross-check.
    """
    files = {
        "Move.toml": (
            '[package]\nname = "pkg"\n\n'
            '[addresses]\nstd = "0x1"\nsui = "0x2"\n'
        )
    }
    reasons = scan(files)
    assert not any("manifest_address" in r for r in reasons), (
        f"framework addresses must not be flagged; got: {reasons}"
    )


def test_dep_git_branch_rev_is_untrusted():
    """A git dependency whose rev is a branch name (not a 40-char SHA) must be flagged (wave-7).

    A branch name can be force-pushed; only a commit SHA is immutable.  Without a
    pinned SHA the supervisor cannot reproduce a deterministic source tree offline.
    Before the fix: any non-empty ``rev`` value was accepted.
    After the fix: ``manifest_dep_rev_not_pinned`` when rev is a branch name.
    """
    files = {
        "Move.toml": (
            '[package]\nname = "pkg"\n\n'
            '[dependencies]\nMyDep = { git = "https://github.com/a/b", rev = "main" }\n'
        )
    }
    reasons = scan(files)
    assert any("manifest_dep_rev_not_pinned" in r and "MyDep" in r for r in reasons), (
        f"branch-name rev must be flagged; got: {reasons}"
    )


def test_dep_git_sha_rev_is_not_flagged():
    """A git dependency with a full 40-char SHA rev must NOT be flagged (wave-7).

    A 40-char hex SHA is an immutable commit reference; it is the only form the
    supervisor can use to pre-fetch a deterministic source tree offline.
    """
    sha = "a" * 40
    files = {
        "Move.toml": (
            '[package]\nname = "pkg"\n\n'
            f'[dependencies]\nMyDep = {{ git = "https://github.com/a/b", rev = "{sha}" }}\n'
        )
    }
    reasons = scan(files)
    assert not any("manifest_dep_rev_not_pinned" in r for r in reasons), (
        f"pinned-SHA rev must not be flagged; got: {reasons}"
    )


def test_dep_addr_subst_key_is_disallowed():
    """An ``addr_subst`` key inside a dependency entry must be flagged (wave-7).

    ``addr_subst`` injects address substitutions that change module IDs and can
    silently redirect named addresses to attacker-controlled values.
    Before the fix: only section names and dep form (local/git) were checked;
    ``addr_subst`` inside a dep entry was accepted.
    After the fix: ``manifest_disallowed_field`` for the offending key.
    """
    sha = "b" * 40
    files = {
        "Move.toml": (
            '[package]\nname = "pkg"\n\n'
            '[dependencies]\n'
            f'Evil = {{ git = "https://github.com/a/b", rev = "{sha}", addr_subst = {{ pkg = "0xdead" }} }}\n'
        )
    }
    reasons = scan(files)
    assert any(
        "manifest_disallowed_field" in r and "addr_subst" in r for r in reasons
    ), (f"addr_subst dep key must be flagged; got: {reasons}")


# ---------------------------------------------------------------------------
# Wave-8: 7 fail-open fixes — parametrized
# ---------------------------------------------------------------------------

# Fix 1: declared_addresses is None → non-framework address → manifest_address_unverified
@pytest.mark.parametrize("addr,label", [
    ("0xdeadbeef", "short_nonframework"),
    ("0x" + "ab" * 32, "long_nonframework"),
    ("0xbeef", "four_char_nonframework"),
])
def test_address_without_declared_set_is_unverified(addr: str, label: str) -> None:
    """Non-framework address with no declared_addresses set must be flagged (wave-8 fix 1).

    Before the fix: when declared_addresses=None, any non-framework address passed silently.
    Positive gate: absence of a declared set is NOT permission to trust any address.
    After the fix: manifest_address_unverified for every non-framework address when no
    declared set is provided.
    """
    files = {
        "Move.toml": f'[package]\nname = "pkg"\n\n[addresses]\npkg_addr = "{addr}"\n'
    }
    reasons = scan(files)  # no declared_addresses → should flag
    assert any("manifest_address_unverified" in r for r in reasons), (
        f"[{label}] non-framework addr with no declared set must be flagged; got: {reasons}"
    )


def test_address_matches_declared_set_is_not_flagged() -> None:
    """An address that exactly matches the caller-supplied declared_addresses must NOT be flagged."""
    addr = "0x" + "ab" * 32
    files = {
        "Move.toml": f'[package]\nname = "pkg"\n\n[addresses]\npkg_addr = "{addr}"\n'
    }
    reasons = scan(files, declared_addresses={addr})
    assert not any("manifest_address" in r for r in reasons), (
        f"address matching declared set must not be flagged; got: {reasons}"
    )


# Fix 2: non-dict section value → manifest_bad_section_type
@pytest.mark.parametrize("toml_text,section_label", [
    ('package = "not_a_table"\n', "[package]"),
    ('[package]\nname = "pkg"\n\naddresses = ["array"]\n', "[addresses]"),
    ('[package]\nname = "pkg"\n\ndependencies = 42\n', "[dependencies]"),
])
def test_non_dict_section_is_flagged(toml_text: str, section_label: str) -> None:
    """An allowed section with a non-dict value (string, array, int) must be flagged (wave-8 fix 2).

    ``data.get("package") or {}`` silently skips or iterates over non-dict values.
    Positive gate: the section must be a TOML table (dict) to be valid.
    """
    files = {"Move.toml": toml_text}
    reasons = scan(files)
    assert any("manifest_bad_section_type" in r or "manifest_disallowed_field" in r for r in reasons), (
        f"{section_label} non-dict value must be flagged; got: {reasons}"
    )


# Fix 3: non-string local value → flag
@pytest.mark.parametrize("local_value,label", [
    ("42", "integer_local"),
    ('["../b"]', "array_local"),
])
def test_non_string_local_is_flagged(local_value: str, label: str) -> None:
    """A non-string ``local`` value inside a dep entry must be flagged (wave-8 fix 3).

    Before the fix: ``if isinstance(local, str)`` silently skipped non-string local values.
    After the fix: ``manifest_dep_local_not_string``.
    """
    files = {
        "Move.toml": (
            '[package]\nname = "pkg"\n\n'
            f'[dependencies]\nB = {{ local = {local_value} }}\n'
        )
    }
    reasons = scan(files)
    assert any("manifest_dep_local_not_string" in r or "manifest_disallowed_field" in r for r in reasons), (
        f"[{label}] non-string local must be flagged; got: {reasons}"
    )


# Fix 4a: non-string git value → flag
def test_non_string_git_is_flagged() -> None:
    """A non-string ``git`` value inside a dep entry must be flagged (wave-8 fix 4a).

    Before the fix: ``if isinstance(git, str) and not _GIT_OK.match(...)`` silently
    skipped when ``git`` was not a string (no flag emitted).
    After the fix: ``manifest_dep_git_not_string``.
    """
    files = {
        "Move.toml": (
            '[package]\nname = "pkg"\n\n'
            '[dependencies]\nB = { git = 42, rev = "' + ("a" * 40) + '" }\n'
        )
    }
    reasons = scan(files)
    assert any("manifest_dep_git_not_string" in r or "manifest_disallowed_field" in r for r in reasons), (
        f"non-string git must be flagged; got: {reasons}"
    )


# Fix 4b: dep with both local and git → manifest_dep_ambiguous
def test_dep_with_both_local_and_git_is_ambiguous() -> None:
    """A dep entry with both ``local`` and ``git`` must be flagged as ambiguous (wave-8 fix 4b).

    Before the fix: only ``local`` was checked (the ``if/elif`` short-circuited).
    After the fix: ``manifest_dep_ambiguous`` when both are present.
    """
    sha = "c" * 40
    files = {
        "Move.toml": (
            '[package]\nname = "pkg"\n\n'
            f'[dependencies]\nB = {{ local = "../b", git = "https://github.com/a/b", rev = "{sha}" }}\n'
        )
    }
    reasons = scan(files)
    assert any("manifest_dep_ambiguous" in r for r in reasons), (
        f"local+git dep must be flagged as ambiguous; got: {reasons}"
    )


# Fix 5a: empty dep dict → manifest_dep_unknown_form
def test_empty_dep_dict_is_flagged() -> None:
    """An empty dep dict ``{}`` must be flagged (wave-8 fix 5a).

    An empty dep has neither ``local`` nor ``git`` — the form is unknown and the
    source will not be fetched, making the dep unverifiable.
    """
    files = {
        "Move.toml": '[package]\nname = "pkg"\n\n[dependencies]\nB = {}\n'
    }
    reasons = scan(files)
    assert any("manifest_dep_unknown_form" in r for r in reasons), (
        f"empty dep dict must be flagged; got: {reasons}"
    )


# Fix 5b: subdir with ".." or absolute path → manifest_dep_subdir_unsafe
@pytest.mark.parametrize("subdir_value,label", [
    ("../escape", "dotdot_escape"),
    ("/absolute/path", "absolute_path"),
    ("a/../../escape", "nested_dotdot"),
])
def test_dep_subdir_unsafe_path_is_flagged(subdir_value: str, label: str) -> None:
    """A ``subdir`` value with ``..`` or an absolute path must be flagged (wave-8 fix 5b).

    ``subdir`` is passed to the build tool to locate the package inside the git repo.
    An unsafe path could redirect to code outside the pinned tree.
    """
    sha = "d" * 40
    files = {
        "Move.toml": (
            '[package]\nname = "pkg"\n\n'
            f'[dependencies]\n'
            f'B = {{ git = "https://github.com/a/b", rev = "{sha}", subdir = "{subdir_value}" }}\n'
        )
    }
    reasons = scan(files)
    assert any("manifest_dep_subdir_unsafe" in r for r in reasons), (
        f"[{label}] unsafe subdir must be flagged; got: {reasons}"
    )


def test_dep_subdir_safe_path_is_not_flagged() -> None:
    """A safe relative ``subdir`` (no `..`, not absolute) must NOT be flagged."""
    sha = "e" * 40
    files = {
        "Move.toml": (
            '[package]\nname = "pkg"\n\n'
            f'[dependencies]\n'
            f'B = {{ git = "https://github.com/a/b", rev = "{sha}", subdir = "packages/core" }}\n'
        )
    }
    reasons = scan(files)
    assert not any("manifest_dep_subdir" in r for r in reasons), (
        f"safe subdir must not be flagged; got: {reasons}"
    )


# Fix 6: case-insensitive prebuilt detection
@pytest.mark.parametrize("path,label", [
    ("build/pkg/bytecode_modules/Foo.MV", "uppercase_MV"),
    ("build/pkg/bytecode_modules/Foo.Mvsm", "mixed_Mvsm"),
    ("Build/pkg/Bytecode_Modules/foo.mv", "uppercase_dir_Build"),
])
def test_prebuilt_detection_is_case_insensitive(path: str, label: str) -> None:
    """Prebuilt bytecode detection must be case-insensitive (wave-8 fix 6).

    Before the fix: ``p.suffix in ('.mv', '.mvsm')`` was case-sensitive; ``.MV`` and
    ``Build/`` were not flagged.
    After the fix: suffix and directory checks are lowercased before comparison.
    """
    files = {path: b"\x00\x00\x00\x00".decode("latin-1")}
    reasons = scan(files)
    assert any("prebuilt_bytecode" in r for r in reasons), (
        f"[{label}] case-variant prebuilt path must be flagged; got: {reasons}"
    )
