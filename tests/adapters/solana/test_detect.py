"""Tests for detect.py: framework detection, program ID extraction."""

from soken_review.adapters.solana.detect import (
    detect_framework,
    detect_framework_from_files,
    detect_program_id,
    find_declare_id,
    library_name_from_cargo,
)


class TestDetectProgramId:
    def test_valid_address(self):
        assert detect_program_id("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA") is not None

    def test_evm_address_rejected(self):
        assert detect_program_id("0x1234567890abcdef1234567890abcdef12345678") is None

    def test_short_string_rejected(self):
        assert detect_program_id("abc") is None


class TestDetectFramework:
    def test_anchor_detected(self):
        cargo = '[dependencies]\nanchor-lang = "0.30.1"\n'
        assert detect_framework(cargo) == "anchor"

    def test_pinocchio_detected(self):
        cargo = '[dependencies]\npinocchio = "0.5.0"\n'
        assert detect_framework(cargo) == "pinocchio"

    def test_native_fallback(self):
        cargo = '[dependencies]\nsolana-program = "2.1.0"\n'
        assert detect_framework(cargo) == "native"

    def test_empty_is_native(self):
        assert detect_framework("") == "native"


class TestDetectFrameworkFromFiles:
    def test_anchor_from_workspace_cargo(self):
        files = {
            "Cargo.toml": '[workspace]\nmembers = ["programs/*"]\n\n[dependencies]\nanchor-lang = "0.30.1"\n',
            "programs/counter/src/lib.rs": "// counter",
        }
        assert detect_framework_from_files(files) == "anchor"

    def test_native_when_no_anchor(self):
        files = {
            "Cargo.toml": '[package]\nname = "counter"\nversion = "0.1.0"\n\n[dependencies]\nsolana-program = "2.1.0"\n',
        }
        assert detect_framework_from_files(files) == "native"


class TestFindDeclareId:
    def test_anchor_declare_id(self):
        src = 'declare_id!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");\n'
        result = find_declare_id(src)
        assert result == "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"

    def test_no_declare_id(self):
        src = "fn main() {}\n"
        assert find_declare_id(src) is None


class TestLibraryNameFromCargo:
    def test_lib_name(self):
        cargo = "[lib]\nname = \"counter\"\ncrate-type = [\"cdylib\"]\n"
        assert library_name_from_cargo(cargo) == "counter"

    def test_package_name_fallback(self):
        cargo = "[package]\nname = \"my-counter\"\nversion = \"0.1.0\"\n"
        # package name -> replace hyphens with underscores for lib name
        result = library_name_from_cargo(cargo)
        assert result == "my_counter" or result == "my-counter"  # allow either

    def test_empty_cargo(self):
        assert library_name_from_cargo("") is None
