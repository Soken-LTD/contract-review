"""Matrix r5 2026-10-31 (TON multisig v2): a repo job with `ref: main` on a repository whose default
branch is `master` stopped with "Branch or tag main does not exist" and no hint; a deployed TON job
was told to send "a Standard JSON input", an EVM-only artefact."""

from __future__ import annotations

import pytest

from soken_review.errors import ReviewError
from soken_review.tools import git_probe
from soken_review.tools.start_status import _error_texts

SYMREF = "ref: refs/heads/master\tHEAD\n0123456789abcdef0123456789abcdef01234567\tHEAD\n"


def test_pick_default_branch():
    assert git_probe.pick_default_branch(SYMREF) == "master"
    assert git_probe.pick_default_branch("0123456789abcdef0123456789abcdef01234567\tHEAD\n") is None
    assert git_probe.pick_default_branch("ref: refs/heads/../x\tHEAD\n") is None


@pytest.mark.asyncio
async def test_missing_branch_names_the_default_branch(monkeypatch):
    calls: list[tuple] = []

    async def fake_ls_remote(url, patterns, timeout=10.0, options=()):
        calls.append((tuple(patterns), tuple(options)))
        return (0, SYMREF) if options == ("--symref",) else (0, "")

    monkeypatch.setattr(git_probe, "ls_remote", fake_ls_remote)
    with pytest.raises(ReviewError) as exc:
        await git_probe.resolve_ref("https://github.com/ton-blockchain/multisig-contract-v2", "main")
    assert exc.value.code == "E_UNPINNED_REF"
    assert exc.value.fields["default_branch"] == "master"
    assert calls[-1] == (("HEAD",), ("--symref",))
    detail = git_probe.unpinned_ref_detail(exc.value, "main")
    assert detail == {"stage": "repo_ref", "ref": "main", "default_branch": "master", "mode": "default_branch"}
    texts = _error_texts("E_UNPINNED_REF", detail, "repo", "ton")
    assert texts["what"] == ("Branch or tag main does not exist in this repository. "
                             "Its default branch is master.")
    assert "ref set to master" in texts["fix"]


@pytest.mark.asyncio
async def test_missing_branch_without_readable_head_keeps_plain_text(monkeypatch):
    async def fake_ls_remote(url, patterns, timeout=10.0, options=()):
        return (0, "")

    monkeypatch.setattr(git_probe, "ls_remote", fake_ls_remote)
    with pytest.raises(ReviewError) as exc:
        await git_probe.resolve_ref("https://github.com/o/r", "main")
    assert "default_branch" not in exc.value.fields
    detail = git_probe.unpinned_ref_detail(exc.value, "main")
    assert _error_texts("E_UNPINNED_REF", detail, "repo", "evm")["what"] == "Branch or tag main does not exist."


@pytest.mark.asyncio
async def test_ls_remote_refuses_unknown_options():
    assert await git_probe.ls_remote("https://github.com/o/r", ["HEAD"], options=("--upload-pack=x",)) == (2, "")


@pytest.mark.parametrize("chain", ["ton", "solana", "sui", "aptos", "starknet", "tron"])
def test_source_not_found_texts_are_family_specific(chain):
    texts = _error_texts("E_SOURCE_NOT_FOUND", {"reason": "SOURCE_NOT_OWNER_LINKED", "why": "untrusted_inputs"},
                         "deployed", chain)
    assert "fix" in texts
    assert "Standard JSON" not in texts["fix"] and "remappings" not in texts["fix"]
    assert "—" not in texts["fix"] + texts.get("what", "")


def test_ton_why_specific_what():
    texts = _error_texts("E_SOURCE_NOT_FOUND", {"reason": "SOURCE_NOT_OWNER_LINKED", "why": "rebuild_differs"},
                         "deployed", "ton")
    assert texts["what"].startswith("The verified source for this address was rebuilt")
    assert "kind repo" in texts["fix"] and "func, tact or tolk" in texts["fix"]


def test_evm_deployed_keeps_standard_json_hint():
    texts = _error_texts("E_SOURCE_NOT_FOUND", {"providers": "sourcify, etherscan"}, "deployed", "evm")
    assert "Standard JSON" in texts["fix"]
    assert texts["what"] == "Source not found in the automatic sources (sourcify, etherscan)."


def test_repo_jobs_keep_repo_texts():
    texts = _error_texts("E_SOURCE_NOT_FOUND", {"repo_family": "no_ton_sources"}, "repo", "ton")
    assert "FunC, Tact or Tolk" in texts["what"]
