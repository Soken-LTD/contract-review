"""`sui move build` argv at the pinned toolchain (mainnet-v1.81.1): the old
`--skip-fetch-latest-git-deps` flag no longer exists (the new package system rejects it as an
unexpected argument; every Sui repo build on the stand failed with it, 2026-10-23). Offline
operation is the sandbox's `--network=none`, not a CLI flag."""

from __future__ import annotations

import pytest

from soken_review.adapters.sui import build as B


@pytest.mark.parametrize("argv_fn, install", [(B.lint_argv, "/work/out/lint"), (B.build_argv, "/work/out")])
def test_argv_is_the_pinned_cli_surface(argv_fn, install):
    argv = argv_fn("pkg")
    assert argv[:3] == ["sui", "move", "build"]
    assert argv[argv.index("--path") + 1] == "/work/src/pkg"
    assert argv[argv.index("--install-dir") + 1] == install
    assert not any(a.startswith("--skip-fetch") for a in argv)


def test_root_package_path():
    assert B.build_argv(".")[B.build_argv(".").index("--path") + 1] == "/work/src"
    assert B.lint_argv("")[B.lint_argv("").index("--path") + 1] == "/work/src"
