"""Two builds fetching the solc list at once must both succeed (client-path e2e 2026-10-31: three
parallel EVM targets shared list.tmp and the second rename raised FileNotFoundError)."""

from __future__ import annotations

import json
import threading
import time

from soken_review.adapters.evm import compiler


def test_parallel_list_fetches_do_not_collide(tmp_path, monkeypatch):
    body = json.dumps({"builds": [{"version": "0.8.24", "path": "solc-0.8.24"}]}).encode()

    def slow_get(url, timeout=60):
        time.sleep(0.05)
        return body

    monkeypatch.setattr(compiler, "_http_get", slow_get)
    errors: list[BaseException] = []

    def fetch():
        try:
            compiler.SolcCache(tmp_path)._fetch_list()
        except BaseException as exc:  # noqa: BLE001 - collected for the assertion
            errors.append(exc)

    threads = [threading.Thread(target=fetch) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    cache = compiler.SolcCache(tmp_path)
    assert json.loads(cache._list_path().read_text()) == json.loads(body)
    assert not list(cache._list_path().parent.glob("list.*.tmp"))
