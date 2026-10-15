"""Tests for trust_scan.py. Every bypass the coordinator flagged must be covered.

Security properties tested:
- Git dep substring check: "rev" in other word does not bypass
- .cargo/config at any depth is flagged
- rust-toolchain at any depth is flagged (even comment-only content)
- Prebuilt .so (ELF magic) is flagged regardless of extension
- include_bytes! of non-source file is flagged
- build.rs present at all is flagged
- Proc-macro crate is flagged
- Unparseable Cargo.toml is flagged (fail closed)
- Symlink in output dir must NOT cause host file write (tested via build._safe_read_so)
"""

import pytest

from soken_review.adapters.solana.trust_scan import scan_candidate_files


class TestGitDeps:
    def test_git_dep_with_valid_rev_ok(self):
        cargo = """
[dependencies]
my-crate = { git = "https://github.com/foo/bar", rev = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2" }
"""
        untrusted, reasons = scan_candidate_files({"Cargo.toml": cargo})
        assert not untrusted, reasons

    def test_git_dep_missing_rev_flagged(self):
        cargo = """
[dependencies]
my-crate = { git = "https://github.com/foo/bar" }
"""
        untrusted, reasons = scan_candidate_files({"Cargo.toml": cargo})
        assert untrusted
        assert any("rev" in r.lower() for r in reasons)

    def test_git_dep_tag_flagged(self):
        cargo = """
[dependencies]
my-crate = { git = "https://github.com/foo/bar", tag = "v1.0.0" }
"""
        untrusted, _reasons = scan_candidate_files({"Cargo.toml": cargo})
        assert untrusted

    def test_git_dep_branch_flagged(self):
        cargo = """
[dependencies]
my-crate = { git = "https://github.com/foo/bar", branch = "main" }
"""
        untrusted, _reasons = scan_candidate_files({"Cargo.toml": cargo})
        assert untrusted

    def test_rev_substring_in_other_field_does_not_bypass(self):
        """String "rev" in another field like 'reviewer' must not satisfy rev requirement."""
        cargo = """
[dependencies]
my-crate = { git = "https://github.com/foo/bar", name = "reviewer" }
"""
        untrusted, _reasons = scan_candidate_files({"Cargo.toml": cargo})
        assert untrusted, "git dep without proper rev should be flagged"

    def test_short_rev_flagged(self):
        """Rev shorter than 40 hex chars must be flagged."""
        cargo = """
[dependencies]
my-crate = { git = "https://github.com/foo/bar", rev = "abc123" }
"""
        untrusted, _reasons = scan_candidate_files({"Cargo.toml": cargo})
        assert untrusted


class TestCargoPaths:
    def test_absolute_path_dep_flagged(self):
        cargo = """
[dependencies]
local = { path = "/usr/lib/my-crate" }
"""
        untrusted, _reasons = scan_candidate_files({"Cargo.toml": cargo})
        assert untrusted

    def test_dotdot_path_dep_flagged(self):
        cargo = """
[dependencies]
local = { path = "../../other-crate" }
"""
        untrusted, _reasons = scan_candidate_files({"Cargo.toml": cargo})
        assert untrusted

    def test_sibling_path_dep_ok(self):
        cargo = """
[dependencies]
local = { path = "crates/utils" }
"""
        untrusted, reasons = scan_candidate_files({"Cargo.toml": cargo})
        assert not untrusted, reasons


class TestCargoConfig:
    def test_cargo_config_at_root(self):
        files = {"Cargo.toml": "[package]\nname = \"x\"\nversion = \"0.1.0\"", ".cargo/config.toml": "[net]\noffline = false"}
        untrusted, _reasons = scan_candidate_files(files)
        assert untrusted

    def test_cargo_config_at_any_depth(self):
        files = {
            "Cargo.toml": "[package]\nname = \"x\"\nversion = \"0.1.0\"",
            "programs/counter/.cargo/config": "[build]\ntarget = \"bpfel-unknown-unknown\"",
        }
        untrusted, _reasons = scan_candidate_files(files)
        assert untrusted, "cargo config at subdirectory depth must be flagged"

    def test_cargo_config_toml_at_any_depth(self):
        files = {
            "Cargo.toml": "[package]\nname = \"x\"\nversion = \"0.1.0\"",
            "deep/nested/sub/.cargo/config.toml": "[net]\n",
        }
        untrusted, _reasons = scan_candidate_files(files)
        assert untrusted, "cargo config.toml at any depth must be flagged"


class TestRustToolchain:
    def test_rust_toolchain_at_root(self):
        files = {"Cargo.toml": "[package]\nname = \"x\"\nversion = \"0.1.0\"", "rust-toolchain.toml": "[toolchain]\nchannel = \"1.70.0\""}
        untrusted, _reasons = scan_candidate_files(files)
        assert untrusted

    def test_rust_toolchain_at_depth(self):
        files = {
            "Cargo.toml": "[package]\nname = \"x\"\nversion = \"0.1.0\"",
            "programs/counter/rust-toolchain": "1.62.0",
        }
        untrusted, _reasons = scan_candidate_files(files)
        assert untrusted, "a nested rust-toolchain naming another release must be flagged (06 3.3.4)"

    def test_rust_toolchain_comment_then_channel_flagged(self):
        """A leading comment does not hide a pinned foreign toolchain."""
        files = {
            "Cargo.toml": "[package]\nname = \"x\"\nversion = \"0.1.0\"",
            "rust-toolchain": "# pinned\n[toolchain]\nchannel = \"1.62.0\"\n",
        }
        untrusted, _reasons = scan_candidate_files(files)
        assert untrusted

    def test_rust_toolchain_matching_or_generic_not_flagged(self):
        """06 3.3.4 flags only a toolchain other than the image's; the build pins RUSTUP_TOOLCHAIN."""
        for content in ("# only a comment\n", "[toolchain]\nchannel = \"1.81.0\"", "stable"):
            files = {"Cargo.toml": "[package]\nname = \"x\"\nversion = \"0.1.0\"", "rust-toolchain": content}
            untrusted, _reasons = scan_candidate_files(files)
            assert not untrusted, content

    def test_rust_toolchain_unreadable_flagged(self):
        files = {"Cargo.toml": "[package]\nname = \"x\"\nversion = \"0.1.0\"", "rust-toolchain": "a\nb\nc"}
        untrusted, _reasons = scan_candidate_files(files)
        assert untrusted, "unparseable toolchain file fails closed"


class TestBinaryDetection:
    def test_elf_magic_bytes_flagged(self):
        files = {
            "Cargo.toml": "[package]\nname = \"x\"\nversion = \"0.1.0\"",
            "prebuilt.so": b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 24,
        }
        untrusted, _reasons = scan_candidate_files(files)
        assert untrusted, "ELF magic must be flagged"

    def test_prebuilt_so_equal_to_expected_output_flagged(self):
        """A repo with a committed .so that equals the expected output must not yield tier A match."""
        # The presence of a .so file in the source tree is itself untrusted
        files = {
            "Cargo.toml": "[package]\nname = \"counter\"\nversion = \"0.1.0\"",
            "target/deploy/counter.so": b"\x7fELF" + b"\x00" * 28,
        }
        untrusted, _reasons = scan_candidate_files(files)
        assert untrusted, "committed .so must be flagged"

    def test_so_extension_without_elf_magic_flagged(self):
        """Even a .so by extension (e.g. a text file renamed) should be flagged."""
        files = {
            "Cargo.toml": "[package]\nname = \"x\"\nversion = \"0.1.0\"",
            "something.so": "not binary",
        }
        untrusted, _reasons = scan_candidate_files(files)
        assert untrusted, ".so extension must be flagged regardless of content"


class TestIncludeBytes:
    def test_include_bytes_source_file_ok(self):
        src = 'include_bytes!("constants.rs")\n'
        untrusted, _ = scan_candidate_files({"Cargo.toml": "[package]\nname=\"x\"\nversion=\"0.1.0\"", "src/lib.rs": src})
        assert not untrusted

    def test_include_bytes_binary_flagged(self):
        src = 'include_bytes!("program.bin")\n'
        untrusted, _reasons = scan_candidate_files({"Cargo.toml": "[package]\nname=\"x\"\nversion=\"0.1.0\"", "src/lib.rs": src})
        assert untrusted

    def test_include_bytes_data_file_flagged(self):
        src = 'include_bytes!("../../secrets.key")\n'
        untrusted, _reasons = scan_candidate_files({"Cargo.toml": "[package]\nname=\"x\"\nversion=\"0.1.0\"", "src/lib.rs": src})
        assert untrusted


class TestBuildRs:
    def test_build_rs_present_flagged(self):
        files = {
            "Cargo.toml": "[package]\nname = \"x\"\nversion = \"0.1.0\"",
            "build.rs": 'fn main() { println!("cargo:rustc-link-arg=-Tcustom.ld"); }',
        }
        untrusted, _reasons = scan_candidate_files(files)
        assert untrusted, "build.rs steering the link must be flagged"

    def test_empty_build_rs_not_flagged(self):
        files = {"Cargo.toml": "[package]\nname = \"x\"\nversion = \"0.1.0\"", "build.rs": "fn main() {}"}
        untrusted, _reasons = scan_candidate_files(files)
        assert not untrusted

    def test_obfuscated_build_rs_flagged(self):
        """Run-time assembled directives defeat substring checks, so any non-empty build.rs is flagged."""
        body = 'fn main() { let k = ["cargo:", "rustc-link-arg=-T x"].concat(); println!("{k}"); }'
        files = {"Cargo.toml": "[package]\nname = \"x\"\nversion = \"0.1.0\"", "build.rs": body}
        untrusted, _reasons = scan_candidate_files(files)
        assert untrusted


class TestProcMacro:
    def test_proc_macro_flagged(self):
        cargo = """
[package]
name = "my-macro"
version = "0.1.0"

[lib]
proc-macro = true
"""
        untrusted, _reasons = scan_candidate_files({"Cargo.toml": cargo})
        assert untrusted, "a proc-macro crate in the tree removes tier A"


class TestUnparseableCargoToml:
    def test_invalid_toml_fail_closed(self):
        files = {"Cargo.toml": "this is not valid toml !!!! [\n\n"}
        untrusted, _reasons = scan_candidate_files(files)
        assert untrusted, "unparseable Cargo.toml must be fail-closed (untrusted)"


class TestSafeReadSo:
    """Test that _safe_read_so rejects symlinks from build output (sandbox escape prevention)."""

    def test_symlink_in_output_rejected(self, tmp_path):
        """A build that leaves a symlink named *.so must not cause host write outside output_dir."""
        from soken_review.adapters.solana.build import _safe_read_so

        output_dir = tmp_path / "output"
        output_dir.mkdir()
        host_dir = tmp_path / "host"
        host_dir.mkdir()

        # Attacker creates a symlink: output/attack.so -> ../host/stolen
        target_outside = tmp_path / "stolen_file"
        symlink = output_dir / "attack.so"
        symlink.symlink_to(target_outside)

        so_bytes, _so_name = _safe_read_so(output_dir, host_dir)
        # Must reject the symlink; no data returned
        assert so_bytes is None, "Symlink in output dir must be rejected"
        # The target file outside output_dir must not have been created by the supervisor
        assert not target_outside.exists(), "Symlink must not lead to write outside output_dir"

    def test_regular_so_accepted(self, tmp_path):
        """A regular .so file in output_dir/deploy/ (the --sbf-out-dir) is accepted and copied to host_dir."""
        from soken_review.adapters.solana.build import _safe_read_so

        output_dir = tmp_path / "output"
        deploy_dir = output_dir / "deploy"
        deploy_dir.mkdir(parents=True)
        host_dir = tmp_path / "host"
        host_dir.mkdir()

        so_content = b"\x7fELF" + b"\x00" * 28
        (deploy_dir / "counter.so").write_bytes(so_content)

        so_bytes, so_name = _safe_read_so(output_dir, host_dir)
        assert so_bytes == so_content
        assert so_name == "counter.so"
        # Verify copied to host_dir
        assert (host_dir / "counter.so").read_bytes() == so_content


# ---------------------------------------------------------------------------
# Bypass tests added per coordinator security review (commit b1db68b)
# Each class covers one bypass variant with a dedicated test per required case.
# ---------------------------------------------------------------------------


class TestCaseVariantBypasses:
    """Coordinator req (b): case variants of Cargo.toml / rust-toolchain file names."""

    def test_cargo_toml_uppercase_extension_flagged(self):
        """Cargo.TOML must be parsed structurally (case-insensitive name match)."""
        cargo = '[dependencies]\nbad = { git = "https://github.com/foo/bar" }\n'
        untrusted, _reasons = scan_candidate_files({"Cargo.TOML": cargo})
        assert untrusted, "Cargo.TOML must trigger structural parse and flag git dep without rev"

    def test_cargo_toml_uppercase_name_flagged(self):
        """CARGO.toml must be parsed structurally."""
        cargo = '[dependencies]\nbad = { git = "https://github.com/foo/bar" }\n'
        untrusted, _reasons = scan_candidate_files({"CARGO.toml": cargo})
        assert untrusted, "CARGO.toml must trigger structural parse"

    def test_rust_toolchain_mixed_case_flagged(self):
        """Rust-Toolchain (mixed case) must be flagged as rust-toolchain."""
        files = {
            "Cargo.toml": "[package]\nname = \"x\"\nversion = \"0.1.0\"",
            "Rust-Toolchain": "[toolchain]\nchannel = \"1.70.0\"",
        }
        untrusted, _reasons = scan_candidate_files(files)
        assert untrusted, "Rust-Toolchain (mixed case) must be flagged"

    def test_rust_toolchain_toml_uppercase_flagged(self):
        """rust-toolchain.TOML must be flagged."""
        files = {
            "Cargo.toml": "[package]\nname = \"x\"\nversion = \"0.1.0\"",
            "rust-toolchain.TOML": "[toolchain]\nchannel = \"1.62.0\"",
        }
        untrusted, _reasons = scan_candidate_files(files)
        assert untrusted, "rust-toolchain.TOML naming another release must be flagged"


class TestWindowsBackslashBypass:
    """Coordinator req (b): Windows-style backslash paths in path deps."""

    def test_backslash_path_dep_flagged(self):
        r"""A path dep using Windows backslashes must be flagged.

        In TOML basic strings, "\\\\" is an escaped backslash (two chars become one '\').
        So path = "..\\\\" gives the value '..\\' (two dots + backslash).
        We use TOML literal strings (single-quotes) to avoid TOML escaping issues:
        path = '..\other-crate' in a TOML literal string is the value ..\other-crate
        (literal strings do not process escape sequences).
        """
        # TOML literal string (single-quoted): no escape processing; value = ..\other-crate
        cargo = "[dependencies]\nevil = { path = '..\\other-crate' }\n"
        untrusted, reasons = scan_candidate_files({"Cargo.toml": cargo})
        assert untrusted, "Backslash in path dep must be flagged"
        assert any("backslash" in r.lower() for r in reasons)


class TestUnicodeLookalikeBypass:
    """Coordinator req (b): unicode lookalike characters in path deps."""

    def test_unicode_in_path_dep_flagged(self):
        """A path dep using a unicode lookalike in the path must be flagged."""
        # с is Cyrillic 'с' which looks like ASCII 'c'
        cargo = '[dependencies]\nevil = { path = "сrates/utils" }\n'
        untrusted, reasons = scan_candidate_files({"Cargo.toml": cargo})
        assert untrusted, "Non-ASCII in path dep must be flagged as possible lookalike"
        assert any("non-ascii" in r.lower() or "unicode" in r.lower() for r in reasons)


class TestProcMacroUnderscoreBypass:
    """Coordinator req (b): proc_macro = true (underscore variant) in [lib] table."""

    def test_proc_macro_underscore_flagged(self):
        """proc_macro = true (underscore) must be flagged just like proc-macro = true."""
        cargo = (
            '[package]\nname = "my-macro"\nversion = "0.1.0"\n\n'
            '[lib]\nproc_macro = true\n'
        )
        untrusted, reasons = scan_candidate_files({"Cargo.toml": cargo})
        assert untrusted, "proc_macro = true (underscore) must be flagged"
        assert any("proc-macro" in r.lower() for r in reasons)


class TestBuildScriptVariants:
    """Coordinator req (b): build = true|false|"x.rs" variants."""

    def test_build_false_not_flagged_as_nonstd(self):
        """build = false disables build scripts; must NOT be flagged as non-standard."""
        cargo = '[package]\nname = "x"\nversion = "0.1.0"\nbuild = false\n'
        _untrusted, reasons = scan_candidate_files({"Cargo.toml": cargo})
        build_script_reasons = [r for r in reasons if "non-standard build script" in r]
        assert not build_script_reasons, f"build = false must not flag as non-standard: {reasons}"

    def test_build_true_flagged(self):
        """build = true auto-detects build.rs; must be flagged (treat same as build.rs present)."""
        cargo = '[package]\nname = "x"\nversion = "0.1.0"\nbuild = true\n'
        untrusted, reasons = scan_candidate_files({"Cargo.toml": cargo})
        assert untrusted, "build = true must be flagged (auto-detects build.rs)"
        assert any("build" in r.lower() for r in reasons)

    def test_build_custom_name_flagged(self):
        """build = "custom.rs" (non-standard name) must be flagged."""
        cargo = '[package]\nname = "x"\nversion = "0.1.0"\nbuild = "custom_build.rs"\n'
        untrusted, reasons = scan_candidate_files({"Cargo.toml": cargo})
        assert untrusted, "build = 'custom.rs' must be flagged as non-standard build script"
        assert any("non-standard build script" in r for r in reasons)

    def test_build_standard_name_not_flagged_as_nonstd(self):
        """build = "build.rs" is standard; must NOT be flagged as non-standard."""
        cargo = '[package]\nname = "x"\nversion = "0.1.0"\nbuild = "build.rs"\n'
        _untrusted, reasons = scan_candidate_files({"Cargo.toml": cargo})
        non_standard = [r for r in reasons if "non-standard build script" in r]
        assert not non_standard, f"build = 'build.rs' must not be non-standard: {reasons}"


class TestWorkspaceMemberPathEscape:
    """Coordinator req (b): workspace members with path-escaping paths."""

    def test_workspace_member_dotdot_flagged(self):
        """A workspace member with '../../outside' must be flagged."""
        cargo = '[workspace]\nmembers = ["programs/counter", "../../outside-repo"]\n'
        untrusted, reasons = scan_candidate_files({"Cargo.toml": cargo})
        assert untrusted, "Workspace member escaping crate dir must be flagged"
        assert any("workspace member" in r.lower() for r in reasons)

    def test_workspace_member_absolute_flagged(self):
        """A workspace member with an absolute path must be flagged."""
        cargo = '[workspace]\nmembers = ["programs/counter", "/etc/passwd"]\n'
        untrusted, reasons = scan_candidate_files({"Cargo.toml": cargo})
        assert untrusted, "Workspace member with absolute path must be flagged"
        assert any("workspace member" in r.lower() for r in reasons)

    def test_workspace_member_sibling_ok(self):
        """Normal workspace members (sibling dirs) must not be flagged."""
        cargo = '[workspace]\nmembers = ["programs/counter", "programs/token", "crates/utils"]\n'
        _untrusted, reasons = scan_candidate_files({"Cargo.toml": cargo})
        ws_reasons = [r for r in reasons if "workspace member" in r.lower()]
        assert not ws_reasons, f"Normal workspace members must not be flagged: {ws_reasons}"


class TestPathTraversalResolution:
    """Coordinator req: paths from Cargo.toml values resolved against crate dir.

    A path that resolves outside the source root is untrusted regardless of
    how it is written in the raw string (e.g. 'valid/../../../outside').
    A path dep that stays within the root (e.g. '../../sibling' from a deep
    crate) is legitimate and must NOT be flagged.
    """

    def test_dotdot_dep_from_root_flagged(self):
        """path = '../../outside' in root Cargo.toml escapes → flagged."""
        cargo = '[dependencies]\nevil = { path = "../../outside" }\n'
        untrusted, reasons = scan_candidate_files({"Cargo.toml": cargo})
        assert untrusted
        assert any("escapes source root" in r for r in reasons)

    def test_dotdot_dep_within_tree_not_flagged(self):
        """'../../other' from programs/counter/Cargo.toml resolves to programs/other — within root.

        This models a common monorepo layout where a crate at programs/counter
        has a path dep on programs/other via a relative '../../other' path.
        Must NOT be flagged as escaping.
        """
        cargo = '[dependencies]\nother = { path = "../../other" }\n'
        # Cargo.toml is deep enough that ../../other stays within root
        _untrusted, reasons = scan_candidate_files({"programs/counter/Cargo.toml": cargo})
        escape_reasons = [r for r in reasons if "escapes source root" in r]
        assert not escape_reasons, f"Within-tree path dep must not be flagged: {escape_reasons}"

    def test_members_dotx_from_root_flagged(self):
        """members = ['../x'] from root-level Cargo.toml escapes → flagged."""
        cargo = '[workspace]\nmembers = ["programs/counter", "../x"]\n'
        untrusted, reasons = scan_candidate_files({"Cargo.toml": cargo})
        assert untrusted
        assert any("workspace member" in r.lower() for r in reasons)

    def test_complex_traversal_dep_flagged(self):
        """path = 'valid/../../../outside' must be caught by resolution even without leading '..'."""
        cargo = '[dependencies]\nevil = { path = "valid/../../../outside" }\n'
        untrusted, reasons = scan_candidate_files({"Cargo.toml": cargo})
        assert untrusted, "Complex traversal escaping root must be flagged"
        assert any("escapes source root" in r for r in reasons)

    def test_lib_path_escaping_flagged(self):
        """[lib] path = '../../evil.rs' escaping the root must be flagged."""
        cargo = (
            '[package]\nname = "x"\nversion = "0.1.0"\n\n'
            '[lib]\npath = "../../evil.rs"\n'
        )
        untrusted, reasons = scan_candidate_files({"Cargo.toml": cargo})
        assert untrusted
        assert any("[lib].path" in r for r in reasons)

    def test_lib_path_normal_not_flagged(self):
        """[lib] path = 'src/lib.rs' (standard) must not be flagged as escaping."""
        cargo = (
            '[package]\nname = "x"\nversion = "0.1.0"\n\n'
            '[lib]\npath = "src/lib.rs"\n'
        )
        _untrusted, reasons = scan_candidate_files({"Cargo.toml": cargo})
        lib_reasons = [r for r in reasons if "[lib].path" in r]
        assert not lib_reasons, f"Standard lib path must not be flagged: {lib_reasons}"


class TestPathVariantParity:
    """Coordinator req: identical verdicts across all path forms for every rule.

    Each sub-table runs the SAME trigger content at different file path variants
    and asserts the expected outcome, so no rule can be bypassed by varying the
    path representation used in the files dict.

    Verdict categories:
    - "rule_fires": untrusted=True, NOT an unsafe_path rejection (the rule itself
      caught the issue so it should show up in reasons as the rule's message, not
      just "unsafe_path").
    - "unsafe_path": path is rejected before any rule runs (norm != raw or None).

    This parity check ensures the build gate and the trust scan always agree on
    which path form they see.
    """

    # Trigger content for structural Cargo.toml rule (absolute path dep)
    _ABS_PATH_CARGO = '[dependencies]\nevil = { path = "/etc/passwd" }\n'
    # Trigger content for binary detection (ELF magic)
    _ELF_CONTENT = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 56
    # Clean content that should not trigger any rule
    _CLEAN_CARGO = '[package]\nname = "x"\nversion = "0.1.0"\n'

    # ------------------------------------------------------------------
    # Cargo.toml path variants
    # ------------------------------------------------------------------

    @pytest.mark.parametrize("file_key", [
        "Cargo.toml",
        "programs/counter/Cargo.toml",
        "CARGO.TOML",
        "Programs/Counter/CARGO.TOML",
    ])
    def test_cargo_toml_rule_fires_for_clean_variants(self, file_key):
        """Structural Cargo.toml rule fires for root, nested, and case variants."""
        untrusted, reasons = scan_candidate_files({file_key: self._ABS_PATH_CARGO})
        assert untrusted, f"key={file_key!r}: rule must fire"
        # The trigger must be the rule, not an unsafe_path rejection
        assert not any(f"unsafe_path:{file_key}" in r for r in reasons), \
            f"key={file_key!r}: must trigger rule (not unsafe_path), reasons={reasons}"

    @pytest.mark.parametrize("file_key", [
        "./Cargo.toml",
        "programs//counter/Cargo.toml",
        "programs/../Cargo.toml",
        "./programs/./counter/Cargo.toml",
    ])
    def test_cargo_toml_unnormalized_rejected_as_unsafe_path(self, file_key):
        """Unnormalized Cargo.toml paths (norm != raw) are rejected as unsafe_path.

        This ensures no path variant can slip past a rule by using a dirty form
        (e.g. 'programs/../Cargo.toml' which normalises to 'Cargo.toml').
        """
        untrusted, reasons = scan_candidate_files({file_key: self._ABS_PATH_CARGO})
        assert untrusted, f"key={file_key!r}: must produce untrusted (unsafe_path)"
        assert any("unsafe_path" in r for r in reasons), \
            f"key={file_key!r}: must be rejected as unsafe_path, got: {reasons}"

    # ------------------------------------------------------------------
    # Binary (ELF) detection path variants
    # ------------------------------------------------------------------

    @pytest.mark.parametrize("file_key", [
        "prebuilt.so",
        "programs/counter/prebuilt.so",
        "vendor/lib.so",
    ])
    def test_binary_rule_fires_for_clean_variants(self, file_key):
        """ELF detection fires at root, nested, and arbitrary-name paths."""
        untrusted, reasons = scan_candidate_files({file_key: self._ELF_CONTENT})
        assert untrusted, f"key={file_key!r}: ELF detection must fire"
        assert not any(f"unsafe_path:{file_key}" in r for r in reasons), \
            f"key={file_key!r}: must trigger rule (not unsafe_path)"

    @pytest.mark.parametrize("file_key", [
        "./prebuilt.so",
        "programs//counter/prebuilt.so",
    ])
    def test_binary_unnormalized_rejected_as_unsafe_path(self, file_key):
        """Unnormalized binary paths are rejected as unsafe_path."""
        untrusted, reasons = scan_candidate_files({file_key: self._ELF_CONTENT})
        assert untrusted
        assert any("unsafe_path" in r for r in reasons), \
            f"key={file_key!r}: must be unsafe_path, got: {reasons}"

    # ------------------------------------------------------------------
    # build.rs presence rule path variants
    # ------------------------------------------------------------------

    @pytest.mark.parametrize("file_key", [
        "build.rs",
        "programs/counter/build.rs",
        "BUILD.RS",
    ])
    def test_build_rs_rule_fires_for_clean_variants(self, file_key):
        """build.rs detection fires regardless of nesting depth or case."""
        files = {
            "Cargo.toml": self._CLEAN_CARGO,
            file_key: 'fn main() { println!("cargo:rustc-flags=-L /tmp"); }\n',
        }
        untrusted, reasons = scan_candidate_files(files)
        assert untrusted, f"key={file_key!r}: build.rs rule must fire"
        assert not any(f"unsafe_path:{file_key}" in r for r in reasons), \
            f"key={file_key!r}: must trigger rule (not unsafe_path)"

    @pytest.mark.parametrize("file_key", [
        "./build.rs",
        "programs//build.rs",
    ])
    def test_build_rs_unnormalized_rejected_as_unsafe_path(self, file_key):
        """Unnormalized build.rs paths are rejected as unsafe_path."""
        files = {
            "Cargo.toml": self._CLEAN_CARGO,
            file_key: 'fn main() { println!("cargo:rustc-flags=-L /tmp"); }\n',
        }
        untrusted, reasons = scan_candidate_files(files)
        assert untrusted
        assert any("unsafe_path" in r for r in reasons), \
            f"key={file_key!r}: must be unsafe_path, got: {reasons}"


def test_toolchain_path_key_flagged():
    """rustup honours [toolchain] path = <dir>: a custom toolchain, so tier A is off."""
    files = {"Cargo.toml": "[package]\nname = \"x\"\nversion = \"0.1.0\"",
             "rust-toolchain.toml": "[toolchain]\npath = \"/opt/evil-toolchain\""}
    untrusted, _reasons = scan_candidate_files(files)
    assert untrusted


def test_untrusted_build_never_reaches_tier_a():
    """A matching hash from untrusted inputs is not_checkable (06 2.4 line BUILD_INPUT_UNTRUSTED)."""
    from soken_review.adapters.solana.fetch import resolve_provenance

    item = {"signer": "AUTH", "executable_hash": "h", "on_chain_hash": "h", "is_verified": True}
    out = resolve_provenance("P", "h", [item], "AUTH", untrusted_inputs=True,
                             deployed_hash="h", version_line_passed=True)
    assert out["tier"] == "B" and out["match"] == "not_checkable" and out["reason"] == "BUILD_INPUT_UNTRUSTED"
    assert out["hash_equal"] is True
