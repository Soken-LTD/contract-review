"""Unit tests for coverage.py fail-closed behavior (item 3, round 4).

Tests:
- Missing enums.yaml → EnumsLoadError raised (not [] returned)
- Unparsable enums.yaml → EnumsLoadError raised
- Valid enums.yaml, family with zero categories → compute_coverage_rows returns
  a synthetic configuration_error row (F5 opens)
- Valid enums.yaml, known family with categories → normal rows returned
"""

from __future__ import annotations

import pytest
import yaml

# Need to invalidate the @cache before each test that patches the path
import soken_review.tools.coverage as cov_mod


def _clear_enums_cache():
    """Clear the @cache on _load_enums so path patches take effect."""
    cov_mod._load_enums.cache_clear()


@pytest.fixture(autouse=True)
def clear_cache():
    _clear_enums_cache()
    yield
    _clear_enums_cache()


# ---------------------------------------------------------------------------
# _load_enums fail-closed tests
# ---------------------------------------------------------------------------


def test_load_enums_missing_file_raises(tmp_path, monkeypatch):
    """Missing enums.yaml raises EnumsLoadError (not returns [])."""
    monkeypatch.setattr(cov_mod, "RUBRIC_DIR", tmp_path)

    with pytest.raises(cov_mod.EnumsLoadError, match="not found"):
        cov_mod._load_enums()


def test_load_enums_corrupt_yaml_raises(tmp_path, monkeypatch):
    """Unparsable enums.yaml raises EnumsLoadError (not returns [])."""
    monkeypatch.setattr(cov_mod, "RUBRIC_DIR", tmp_path)
    (tmp_path / "enums.yaml").write_text("{\nbad: yaml: [unclosed", encoding="utf-8")

    with pytest.raises(cov_mod.EnumsLoadError, match="parse error"):
        cov_mod._load_enums()


def test_load_enums_categories_not_list_raises(tmp_path, monkeypatch):
    """enums.yaml with 'categories' not a list raises EnumsLoadError."""
    monkeypatch.setattr(cov_mod, "RUBRIC_DIR", tmp_path)
    (tmp_path / "enums.yaml").write_text("categories: not-a-list\n", encoding="utf-8")

    with pytest.raises(cov_mod.EnumsLoadError, match="not a list"):
        cov_mod._load_enums()


def test_load_enums_valid_returns_list(tmp_path, monkeypatch):
    """Valid enums.yaml returns the categories list normally."""
    monkeypatch.setattr(cov_mod, "RUBRIC_DIR", tmp_path)
    data = {"categories": [{"id": "evm.reentrancy", "family": "evm"}]}
    (tmp_path / "enums.yaml").write_text(yaml.dump(data), encoding="utf-8")

    result = cov_mod._load_enums()
    assert result == [{"id": "evm.reentrancy", "family": "evm"}]


# ---------------------------------------------------------------------------
# family with zero categories → F5-open synthetic row
# ---------------------------------------------------------------------------


def test_compute_coverage_unknown_family_returns_config_error_row(tmp_path, monkeypatch):
    """A family with zero categories in enums.yaml returns a configuration_error row."""
    monkeypatch.setattr(cov_mod, "RUBRIC_DIR", tmp_path)
    # Valid yaml but no 'evm' categories — only 'solana'
    data = {"categories": [{"id": "solana.ownership", "family": "solana"}]}
    (tmp_path / "enums.yaml").write_text(yaml.dump(data), encoding="utf-8")

    rows = cov_mod.compute_coverage_rows("evm", None, {})
    assert len(rows) == 1
    assert rows[0]["status"] == "configuration_error"
    assert rows[0]["area_id"] == "_no_categories"
    assert "evm" in rows[0]["note"]


def test_compute_coverage_zero_categories_row_triggers_f5_open(tmp_path, monkeypatch):
    """F5 opens when compute_coverage_rows returns a configuration_error row."""
    monkeypatch.setattr(cov_mod, "RUBRIC_DIR", tmp_path)
    data = {"categories": []}
    (tmp_path / "enums.yaml").write_text(yaml.dump(data), encoding="utf-8")

    rows = cov_mod.compute_coverage_rows("evm", None, {})
    # The finalize F5 logic: any(r.get("status") == "configuration_error" ...)
    f5_open = any(r.get("status") == "configuration_error" for r in rows)
    assert f5_open, "F5 must be open when compute_coverage_rows returns configuration_error"


# ---------------------------------------------------------------------------
# Normal path with real enums.yaml
# ---------------------------------------------------------------------------


def test_family_categories_evm_nonempty():
    """family_categories('evm') returns non-empty list with real enums.yaml."""
    cats = cov_mod.family_categories("evm")
    assert len(cats) > 0, "Expected at least one evm category in enums.yaml"
    assert all(isinstance(c, str) for c in cats)


def test_compute_coverage_no_map_returns_not_covered_rows():
    """With no map_doc, all categories are not_covered (no synthetic error row)."""
    cats = cov_mod.family_categories("evm")
    rows = cov_mod.compute_coverage_rows("evm", None, {})
    assert len(rows) == len(cats)
    assert all(r["status"] == "not_covered" for r in rows)
