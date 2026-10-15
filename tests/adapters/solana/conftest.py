"""Worktree-local sys.path fix for Solana adapter tests.

The shared venv's soken_review.pth points to the main repo's src/. This conftest
inserts the worktree's src/ directory first so tests import worktree-local code.
"""
from __future__ import annotations

import sys
from pathlib import Path

_WORKTREE_SRC = Path(__file__).resolve().parents[3] / "src"
if str(_WORKTREE_SRC) not in sys.path:
    sys.path.insert(0, str(_WORKTREE_SRC))
