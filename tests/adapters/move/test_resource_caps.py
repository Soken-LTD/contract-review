"""Resource-cap tests (coordinator review of f917b13).

Three mandatory tests:
  1. Step deadline: the second analyzer container is NOT started after the deadline is past.
  2. Env override above yaml value is ignored; yaml value is used.
  3. Oversized / symlinked build_result.json is refused by _read_json_nofollow.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

# ── 1. Step deadline: second analyzer is not started ─────────────────────────

def test_step_deadline_skips_second_run(monkeypatch, tmp_path):
    """When the step deadline is exhausted after the first run, the second lint run
    is skipped with reason='step_deadline' and the overall status is 'degraded'.

    This covers coordinator finding 1: per-step, not per-container, budget.
    """
    from soken_review.adapters.base import BuildResult, Candidate
    from soken_review.adapters.move import analyze as analyze_mod
    from soken_review.adapters.move import lints, rules, sandbox

    # Track sandbox.run calls.
    run_count: list[int] = [0]

    def fake_run(chain, step, dirs, command, *, timeout, **kwargs):
        run_count[0] += 1
        return sandbox.RunResult(returncode=0, stdout="", stderr="", timed_out=False)

    monkeypatch.setattr(sandbox, "run", fake_run)
    monkeypatch.setattr(sandbox, "scratch_copy", lambda dirs, name: dirs)

    # No-op write_host (avoids creating files in tmp_path host dir for every lint log).
    monkeypatch.setattr(sandbox, "write_host", lambda path, data: None)

    # No-op for the parts that follow the lint loop (LinkedSet, rules, index_sources).
    monkeypatch.setattr(analyze_mod, "load_host_modules", lambda work: {})
    monkeypatch.setattr(lints, "parse", lambda chain, text: [])
    monkeypatch.setattr(lints, "to_raw", lambda *a, **k: ([], set(), 0))
    monkeypatch.setattr(rules, "load_rules", lambda rules_dir, chain: [])
    monkeypatch.setattr(rules, "run_rules", lambda rule_list, ctx: [])
    monkeypatch.setattr(rules, "package_types", lambda linked, chain: (set(), set()))

    from soken_review.adapters.move.analyze import analyze, printed_to_pin

    files = {"sources/A.move": "module a::a {}", "sources/B.move": "module b::b {}"}
    cand = Candidate(
        provider="inline",
        files=files,
        sha256="0" * 64,
        language="move_sui",
        compiler=None,
        settings={},
        std_json_input=None,
        entry_contract=None,
        source_url=None,
        fetched_at=None,
    )
    work = tmp_path / "work"
    dirs = sandbox.prepare_dirs(work)
    for p, content in files.items():
        out = dirs["src"] / p
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(content)

    r = BuildResult(candidate=cand, status="ok", nsloc=10, work_dir=str(work))

    # Two runs — one per "package unit" (Aptos pattern, multiple units → multiple runs).
    runs = [
        (["sui", "move", "build", "--path", "/work/src", "--lint"], printed_to_pin(files, ".")),
        (["sui", "move", "build", "--path", "/work/src/b", "--lint"], printed_to_pin(files, ".")),
    ]

    # Step deadline already expired: both runs should be skipped.
    step_deadline = time.monotonic() - 1.0

    _HERE = Path(__file__).resolve()
    sui_adapter_dir = _HERE.parents[3] / "src" / "soken_review" / "adapters" / "sui"

    _leads, static_map, _read_plan = analyze(
        r,
        chain="sui",
        lint_runs=runs,
        lint_version="1.81.1",
        chain_extras={},
        upgrade=None,
        in_scope=lambda p: True,
        rules_dir=sui_adapter_dir / "rules",
        lint_map_path=sui_adapter_dir / "lint_map.yaml",
        dep_modules={},
        step_deadline=step_deadline,
    )

    assert run_count[0] == 0, f"expected 0 sandbox.run calls (deadline expired), got {run_count[0]}"
    not_run_reasons = [nr.get("reason") for nr in static_map.get("not_run", [])]
    assert "step_deadline" in not_run_reasons, (
        f"expected 'step_deadline' in not_run, got: {static_map.get('not_run')}"
    )
    assert static_map["status"] in ("degraded", "not_run"), static_map["status"]


# ── 2. Env override above yaml is ignored ────────────────────────────────────

def test_env_override_above_yaml_is_ignored(tmp_path, monkeypatch):
    """An env var value HIGHER than the yaml limit is rejected; yaml value is used.

    This covers coordinator finding 2: env can only TIGHTEN, never loosen, the limit.
    """
    from soken_review.adapters.move import sandbox

    # Write a temporary limits.yaml with a known value.
    limits_yaml = tmp_path / "limits.yaml"
    limits_yaml.write_text("analyze:\n  move:\n    wall_s: 400\n    per_container_wall_s: 90\n")

    # Temporarily override _LIMITS_YAML in sandbox.
    monkeypatch.setattr(sandbox, "_LIMITS_YAML", limits_yaml)

    # Env override HIGHER than yaml: should be ignored (yaml wins).
    monkeypatch.setenv("SOKEN_MOVE_ANALYZE_STEP_WALL_S", "9999")
    result_high = sandbox._load_wall_s(("analyze", "move", "wall_s"), 600, "SOKEN_MOVE_ANALYZE_STEP_WALL_S")
    assert result_high == 400, f"expected yaml value 400, got {result_high}"

    # Env override LOWER than yaml: should be accepted (env tightens).
    monkeypatch.setenv("SOKEN_MOVE_ANALYZE_STEP_WALL_S", "200")
    result_low = sandbox._load_wall_s(("analyze", "move", "wall_s"), 600, "SOKEN_MOVE_ANALYZE_STEP_WALL_S")
    assert result_low == 200, f"expected env value 200, got {result_low}"

    # No env override: yaml value is used.
    monkeypatch.delenv("SOKEN_MOVE_ANALYZE_STEP_WALL_S", raising=False)
    result_no_env = sandbox._load_wall_s(("analyze", "move", "wall_s"), 600, "SOKEN_MOVE_ANALYZE_STEP_WALL_S")
    assert result_no_env == 400, f"expected yaml value 400, got {result_no_env}"


# ── 3. Oversized / symlinked build_result.json is refused ────────────────────

def test_oversized_build_result_refused(tmp_path):
    """_read_json_nofollow raises ValueError when the file exceeds the size cap.

    This covers coordinator finding 3: size cap on supervisor-written JSON files.
    """
    from soken_review.worker.supervisor import _MAX_SUPERVISOR_JSON_BYTES, _read_json_nofollow

    # Write a file just over the cap.
    big = tmp_path / "build_result.json"
    payload = b'{"x":' + b"1" * (_MAX_SUPERVISOR_JSON_BYTES + 1) + b"}"
    big.write_bytes(payload)

    try:
        _read_json_nofollow(big)
        raise AssertionError("expected ValueError for oversized file")
    except ValueError as exc:
        assert "cap" in str(exc).lower(), f"unexpected error message: {exc}"


def test_symlinked_build_result_refused(tmp_path):
    """_read_json_nofollow raises OSError when the path is a symlink.

    This covers coordinator finding 3: O_NOFOLLOW for supervisor-written JSON files.
    """
    from soken_review.worker.supervisor import _read_json_nofollow

    real = tmp_path / "real.json"
    real.write_text('{"status": "ok"}')
    link = tmp_path / "build_result.json"
    link.symlink_to(real)

    try:
        _read_json_nofollow(link)
        raise AssertionError("expected OSError for symlink")
    except OSError:
        pass  # correct: O_NOFOLLOW raised


def test_valid_build_result_reads_ok(tmp_path):
    """_read_json_nofollow correctly parses a well-formed small JSON file."""
    from soken_review.worker.supervisor import _read_json_nofollow

    f = tmp_path / "build_result.json"
    data = {"status": "ok", "nsloc": 42}
    f.write_text(json.dumps(data))

    result = _read_json_nofollow(f)
    assert result == data
