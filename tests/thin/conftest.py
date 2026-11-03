"""Thin flow (SOKEN_FLOW=thin, the production default since migration 022) for every test in this package."""

from __future__ import annotations

import pytest


def _clear_caches() -> None:
    from soken_review import client_refresh, http

    client_refresh.missing.cache_clear()
    http._tool_names.cache_clear()


@pytest.fixture(autouse=True)
def _thin_flow(monkeypatch):
    monkeypatch.setenv("SOKEN_FLOW", "thin")
    _clear_caches()
    yield
    monkeypatch.setenv("SOKEN_FLOW", "legacy")
    _clear_caches()
