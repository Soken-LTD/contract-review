"""Report key versions (08 4.1; road-to-prod item 7): a rotation keeps old links valid, and a real
deployment refuses to start without the current key instead of signing with a random one."""

from __future__ import annotations

import pytest

from soken_review.report import render
from soken_review.tools import report as R

RID = "abcdefghijklmnopqrstuvwxyz"
K1 = "1" * 40
K2 = "2" * 40


def test_current_version_defaults_to_1_and_reads_the_env(monkeypatch):
    monkeypatch.delenv("SOKEN_REPORT_KEY_CURRENT", raising=False)
    assert render.current_key_version() == 1
    monkeypatch.setenv("SOKEN_REPORT_KEY_CURRENT", "2")
    assert render.current_key_version() == 2
    for bad in ("0", "-1", "two"):
        monkeypatch.setenv("SOKEN_REPORT_KEY_CURRENT", bad)
        with pytest.raises(RuntimeError):
            render.current_key_version()


def test_a_v1_report_keeps_its_links_after_rotating_to_v2(monkeypatch):
    monkeypatch.setenv("SOKEN_REPORT_KEY_V1", K1)
    monkeypatch.delenv("SOKEN_REPORT_KEY_CURRENT", raising=False)
    manage_v1 = R.manage_key(RID)                     # issued while V1 was current
    sig_v1 = R.view_signature(RID, 4_000_000_000)
    monkeypatch.setenv("SOKEN_REPORT_KEY_V2", K2)
    monkeypatch.setenv("SOKEN_REPORT_KEY_CURRENT", "2")
    assert R.manage_key(RID, 1) == manage_v1           # the row records key_version 1
    assert R.check_view(RID, 4_000_000_000, sig_v1, 1, now=1.0)
    assert R.manage_key(RID) != manage_v1              # new reports sign with V2
    assert not R.check_view(RID, 4_000_000_000, sig_v1, 2, now=1.0)


def test_startup_requires_the_current_key(monkeypatch):
    monkeypatch.delenv("SOKEN_REPORT_KEY_CURRENT", raising=False)
    monkeypatch.delenv("SOKEN_REPORT_KEY_V1", raising=False)
    with pytest.raises(RuntimeError, match="SOKEN_REPORT_KEY_V1"):
        R.require_report_keys()
    monkeypatch.setenv("SOKEN_REPORT_KEY_V1", "short")
    with pytest.raises(RuntimeError):
        R.require_report_keys()
    monkeypatch.setenv("SOKEN_REPORT_KEY_V1", K1)
    assert R.require_report_keys() == 1
    monkeypatch.setenv("SOKEN_REPORT_KEY_CURRENT", "2")
    with pytest.raises(RuntimeError, match="SOKEN_REPORT_KEY_V2"):
        R.require_report_keys()
