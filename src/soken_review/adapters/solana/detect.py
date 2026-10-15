"""Solana input detection (06 section 3.1).

Detects:
  - Program id: base58 to 32 bytes
  - Framework: anchor-lang -> Anchor; pinocchio -> Pinocchio; else native
  - Several programs: Anchor workspace in a repo input
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

from soken_review.adapters.solana.units import is_solana_address

Framework = Literal["anchor", "pinocchio", "native"]

# Cargo.toml dependency detection
_DEP_ANCHOR = re.compile(r'anchor-lang\s*=', re.MULTILINE)
_DEP_PINOCCHIO = re.compile(r'pinocchio\s*=', re.MULTILINE)
_DEP_SOLANA = re.compile(r'solana-program\s*=|solana-sdk\s*=', re.MULTILINE)


def detect_program_id(value: str) -> str | None:
    """Return the program ID if value is a valid base58 Solana address (32 bytes).

    Returns None for invalid or non-32-byte values.
    """
    value = value.strip()
    if is_solana_address(value):
        return value
    return None


def detect_framework(cargo_toml_content: str) -> Framework:
    """Detect the Solana program framework from Cargo.toml content (06 3.1).

    anchor-lang dep -> anchor
    pinocchio dep -> pinocchio
    else -> native
    """
    if _DEP_ANCHOR.search(cargo_toml_content):
        return "anchor"
    if _DEP_PINOCCHIO.search(cargo_toml_content):
        return "pinocchio"
    return "native"


def detect_framework_from_files(files: dict[str, str]) -> Framework:
    """Detect framework from a set of source files (first Cargo.toml wins)."""
    for path, content in files.items():
        if Path(path).name == "Cargo.toml":
            return detect_framework(content)
    return "native"


def find_cargo_toml_files(root: Path) -> list[Path]:
    """Find all Cargo.toml files under root, sorted by depth."""
    return sorted(root.rglob("Cargo.toml"), key=lambda p: len(p.parts))


def detect_workspace_programs(root: Path) -> list[dict[str, str]]:
    """Detect Anchor workspace programs from Anchor.toml [programs.mainnet] (06 3.1).

    Returns list of {name: str, address: str} dicts.
    This does NOT execute Anchor.toml; we parse it with a simple regex.
    """
    anchor_toml = root / "Anchor.toml"
    if not anchor_toml.exists():
        return []

    content = anchor_toml.read_text(errors="replace")
    # Find [programs.mainnet] section and extract name=address pairs
    section_re = re.compile(r'\[programs\.mainnet\](.*?)(?=\[|$)', re.DOTALL)
    kv_re = re.compile(r'^(\w[\w_-]*)\s*=\s*"([A-Za-z0-9]{32,44})"', re.MULTILINE)

    match = section_re.search(content)
    if not match:
        return []

    programs = []
    for m in kv_re.finditer(match.group(1)):
        name, addr = m.group(1), m.group(2)
        if is_solana_address(addr):
            programs.append({"name": name, "address": addr})
    return programs


def find_declare_id(source: str) -> str | None:
    """Extract program id from declare_id!(...) or address!(...) macro call (06 3.1 U-S16).

    Handles:
      declare_id!("Abc...");
      address!("Abc...");
      solana_program::declare_id!("Abc...");
    """
    pattern = re.compile(
        r'(?:declare_id|address)!\s*\(\s*"([A-Za-z0-9]{32,44})"\s*\)',
        re.MULTILINE,
    )
    m = pattern.search(source)
    if m:
        addr = m.group(1)
        if is_solana_address(addr):
            return addr
    return None


def find_crate_root_id(files: dict[str, str]) -> str | None:
    """Search for declare_id! in lib.rs or main.rs (the crate root)."""
    for path in ("src/lib.rs", "lib.rs", "src/main.rs", "main.rs"):
        if path in files:
            found = find_declare_id(files[path])
            if found:
                return found
    return None


def library_name_from_cargo(cargo_toml_content: str) -> str | None:
    """Extract [lib] name from Cargo.toml content."""
    # [lib] name = "foo"
    m = re.search(r'\[lib\][^\[]*name\s*=\s*"([^"]+)"', cargo_toml_content, re.DOTALL)
    if m:
        return m.group(1)
    # Fallback: [package] name
    m = re.search(r'\[package\][^\[]*name\s*=\s*"([^"]+)"', cargo_toml_content, re.DOTALL)
    if m:
        return m.group(1).replace("-", "_")
    return None
