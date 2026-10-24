"""Tests for server-side project URL discovery from source files (feat/context-related-state)."""

from __future__ import annotations

from pathlib import Path

from soken_review.mapping.project_url import (
    discover_project_urls,
    load_suggested_context,
    write_suggested_context,
)

# ---------------------------------------------------------------------------
# NatSpec @custom:website
# ---------------------------------------------------------------------------

def test_natspec_website_url_is_discovered():
    files = {
        "contracts/Token.sol": (
            "// SPDX-License-Identifier: MIT\n"
            "pragma solidity ^0.8.0;\n"
            "/// @custom:website https://example.com/\n"
            "contract Token {}\n"
        )
    }
    results = discover_project_urls(files)
    assert len(results) == 1
    assert results[0]["url"] == "https://example.com/"
    assert results[0]["kind"] == "website"
    assert results[0]["source_hint"] == "contracts/Token.sol"


def test_natspec_security_contact_url_is_discovered():
    files = {
        "Token.sol": (
            "/// @custom:security-contact https://security.example.com/\n"
            "contract Token {}\n"
        )
    }
    results = discover_project_urls(files)
    assert len(results) == 1
    assert results[0]["url"] == "https://security.example.com/"
    assert results[0]["kind"] == "other"


# ---------------------------------------------------------------------------
# GitHub URLs in comments
# ---------------------------------------------------------------------------

def test_github_url_in_comment_is_discovered():
    files = {
        "Token.sol": (
            "// Source: https://github.com/MyOrg/my-protocol\n"
            "contract Token {}\n"
        )
    }
    results = discover_project_urls(files)
    assert any(r["url"] == "https://github.com/MyOrg/my-protocol" for r in results)
    assert all(r["kind"] == "other" for r in results)


def test_github_url_with_deep_path_is_trimmed_to_repo_root():
    files = {
        "Token.sol": (
            "// https://github.com/OpenZeppelin/openzeppelin-contracts/blob/main/contracts/token/ERC20/ERC20.sol\n"
            "contract Token {}\n"
        )
    }
    results = discover_project_urls(files)
    # Should normalise to repo root: https://github.com/OpenZeppelin/openzeppelin-contracts
    found = [r for r in results if "openzeppelin" in r["url"]]
    assert found, results
    assert found[0]["url"] == "https://github.com/OpenZeppelin/openzeppelin-contracts"


# ---------------------------------------------------------------------------
# Kind detection from URL path
# ---------------------------------------------------------------------------

def test_whitepaper_url_gets_whitepaper_kind():
    files = {"Token.sol": "/// @custom:website https://docs.example.com/whitepaper.pdf\ncontract T {}"}
    results = discover_project_urls(files)
    assert results and results[0]["kind"] == "whitepaper"


def test_docs_url_gets_docs_kind():
    files = {"Token.sol": "/// @custom:website https://docs.example.com/\ncontract T {}"}
    results = discover_project_urls(files)
    assert results and results[0]["kind"] == "docs"


# ---------------------------------------------------------------------------
# Deduplication and capping
# ---------------------------------------------------------------------------

def test_duplicate_urls_are_deduplicated():
    src = "/// @custom:website https://example.com/\n" * 3 + "contract T {}"
    results = discover_project_urls({"Token.sol": src})
    urls = [r["url"] for r in results]
    assert urls.count("https://example.com/") == 1


def test_cap_is_respected():
    files = {
        f"Token{i}.sol": f"/// @custom:website https://example{i}.com/\ncontract T{i} {{}}\n"
        for i in range(20)
    }
    results = discover_project_urls(files)
    assert len(results) <= 6  # MAX_SUGGESTIONS


def test_invalid_url_is_silently_skipped():
    files = {
        "Token.sol": (
            "/// @custom:website not-a-url\n"
            "/// @custom:website http://insecure.example.com/\n"
            "contract T {}\n"
        )
    }
    results = discover_project_urls(files)
    # No valid https URLs: should return empty
    assert results == []


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def test_write_and_load_suggested_context_roundtrip(tmp_path: Path):
    job_id = "job_SUGST00000000000000000000"
    items = [{"url": "https://example.com/", "kind": "website", "source_hint": "Token.sol"}]
    write_suggested_context(tmp_path, job_id, items)
    loaded = load_suggested_context(tmp_path, job_id)
    assert loaded == items


def test_load_suggested_context_returns_empty_when_missing(tmp_path: Path):
    loaded = load_suggested_context(tmp_path, "job_ABSENT0000000000000000000")
    assert loaded == []


def test_suggested_context_is_written_by_run_map_step(tmp_path: Path):
    """run_map_step writes suggested_context.json when NatSpec website is present."""
    from soken_review.mapping.step import run_map_step
    from soken_review.pinning.store import PinnedSource

    job_id = "job_MAPURL0000000000000000000"
    source = (
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.0;\n"
        "/// @custom:website https://example-protocol.com/\n"
        "contract Vault {\n"
        "    uint256 public fee;\n"
        "}\n"
    )
    PinnedSource.from_files({"contracts/Vault.sol": source.encode()}).persist(tmp_path, job_id)
    run_map_step(tmp_path, job_id, solc_output_path=None, build_ok=False, build_detail="no build")

    suggested = load_suggested_context(tmp_path, job_id)
    assert any(s["url"] == "https://example-protocol.com/" for s in suggested), suggested


def test_run_map_step_no_crash_when_no_urls(tmp_path: Path):
    """run_map_step must complete without error even if no URLs are found."""
    from soken_review.mapping.step import run_map_step
    from soken_review.pinning.store import PinnedSource

    job_id = "job_NOURLS0000000000000000000"
    source = "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\ncontract Empty {}\n"
    PinnedSource.from_files({"contracts/Empty.sol": source.encode()}).persist(tmp_path, job_id)
    # Should not raise
    run_map_step(tmp_path, job_id, solc_output_path=None, build_ok=False, build_detail="no build")


# ---------------------------------------------------------------------------
# Security: untrusted URL gates (injection + strict charset)
# ---------------------------------------------------------------------------

def test_javascript_scheme_url_is_dropped():
    """A javascript: URL must be dropped by the strict-charset gate."""
    files = {
        "Token.sol": "/// @custom:website javascript:alert(1)\ncontract T {}\n"
    }
    results = discover_project_urls(files)
    assert results == [], "javascript: scheme must be rejected before injection scan"


def test_query_string_url_is_dropped():
    """A URL with a query string must be dropped (strict charset forbids '?')."""
    files = {
        "Token.sol": "/// @custom:website https://example.com/?ref=hack&x=y\ncontract T {}\n"
    }
    results = discover_project_urls(files)
    assert results == [], "URLs with query strings must be dropped by strict-charset gate"


def test_fragment_url_is_dropped():
    """A URL with a fragment must be dropped (strict charset forbids '#')."""
    files = {
        "Token.sol": "/// @custom:website https://example.com/page#section\ncontract T {}\n"
    }
    results = discover_project_urls(files)
    assert results == [], "URLs with fragments must be dropped by strict-charset gate"


def test_origin_and_status_on_discovered_item():
    """Every discovered item must carry origin='source_code_untrusted' and status='suggested'."""
    files = {
        "Token.sol": "/// @custom:website https://myprotocol.example.com/\ncontract T {}\n"
    }
    results = discover_project_urls(files)
    assert results, "Expected at least one item"
    for item in results:
        assert item.get("origin") == "source_code_untrusted", item
        assert item.get("status") == "suggested", item
