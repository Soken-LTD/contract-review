"""Adapter contract shared by every chain family (05 sections 3.1 and 3.3).

These types are the seams between fetch, build, analyze, pinning and the job model. Fields
follow the 05 3.3 table; change them only together with the plan text.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

Provider = Literal["sourcify", "eth_bytecode_db", "ipfs", "etherscan", "tronscan", "user", "repo"]


@dataclass
class Target:
    address: str | None                 # 20-byte lowercase hex, internal only
    display_address: str | None         # EIP-55 or base58, the only output form
    unit_label: str | None = None       # <name>_<h6> (05 3.4)
    repo_url: str | None = None
    commit: str | None = None
    files: list[str] = field(default_factory=list)
    discovered_by: str = "input"        # input | chain_state


@dataclass
class Compiler:
    version: str                        # exact release, e.g. "0.8.24+commit.e11b9ed9"
    version_pinned_by: str              # metadata | std_json | pragma | user


@dataclass
class Candidate:
    provider: Provider
    files: dict[str, str]               # store-relative path -> content
    sha256: str                         # over the sorted (path, content sha256) list
    language: str                       # solidity | vyper | ...
    compiler: Compiler | None
    settings: dict[str, Any]            # solc settings (optimizer, evmVersion, remappings, ...)
    std_json_input: dict[str, Any] | None
    entry_contract: str | None          # "path:Name"
    explorer_verified: bool = False
    sourcify_match: str | None = None   # exact_match | match | None
    constructor_args_hex: str | None = None
    source_url: str | None = None
    fetched_at: str | None = None       # ISO 8601 UTC
    untrusted_inputs: bool = False      # 06 3.3.4: never tier A; set by the family trust scan
    refused_paths: list[str] = field(default_factory=list)   # paths refused by safe reader; empty = none
    # Runtime-only: path to the materialized source tree for B4 forge build; never serialised.
    src_tree_dir: str | None = None
    # Runtime-only: full O_NOFOLLOW tree read (all files, not just scope) for B4 source
    # integrity check; never serialised into persisted/public payloads.  Populated only for
    # repo candidates by repo_candidate_from_manifest.  Keys are repo-root-relative paths,
    # values are UTF-8 decoded text (same encoding as safe_read_repo_tree output).
    _full_tree: dict[str, str] | None = field(default=None, repr=False)


@dataclass
class SourceBundle:
    target: Target
    candidates: list[Candidate]
    proxy: dict[str, Any] | None = None     # 05 section 5
    related: list[Target] = field(default_factory=list)


@dataclass
class Artifact:
    contract: str                       # "path:Name"
    creation: str                       # hex
    runtime: str                        # hex
    immutable_refs: dict[str, Any]
    link_refs: dict[str, Any]
    source_map: str
    storage_layout: dict[str, Any] | None


@dataclass
class BuildResult:
    candidate: Candidate
    status: Literal["ok", "failed"]
    artifacts: list[Artifact] = field(default_factory=list)
    auxdata_ranges: dict[str, list[tuple[int, int]]] = field(default_factory=dict)
    compiler_advisories: list[str] = field(default_factory=list)
    nsloc: int = 0
    reason: str | None = None           # not_checkable / failure reason code
    stderr_head: str | None = None      # at most 20 lines (09 4.2)
    work_dir: str | None = None         # job dir holding solc output for analyzers
    build_notes: dict = field(default_factory=dict)  # B4 provenance notes: b4_source, b4_rejected, etc.


@dataclass
class ChainValue:
    value: Any
    read_mode: str                      # e.g. rpc_latest_pinned, block_window
    block: int | None = None
    block_window: tuple[int, int] | None = None


ChainState = dict[str, ChainValue]
Lead = dict[str, Any]                   # one lead.v1 document (contract/rubric/schemas/lead.v1.json)


class ChainAdapter(Protocol):
    family: str
    chains: set[str]

    def fetch_source(self, job: Any, cs: ChainState) -> list[SourceBundle]: ...
    def build(self, c: Candidate) -> BuildResult: ...
    def analyze(self, r: BuildResult) -> tuple[list[Lead], dict[str, Any], dict[str, Any]]: ...
    def map(self, r: BuildResult, s: dict[str, Any], cs: ChainState) -> tuple[dict[str, Any], Any]: ...
    def checklists(self, language: str) -> list[str]: ...
