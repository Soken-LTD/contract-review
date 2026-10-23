"""03 section 11 header and version rules on the HTTP leg (Phase 0, A4 and A16)."""

import pytest
from starlette.testclient import TestClient

from soken_review.server import create_app

H = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
INIT = {
    "jsonrpc": "2.0", "id": 1, "method": "initialize",
    "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}},
}
LIST = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}


@pytest.fixture(scope="module")
def client():
    with TestClient(create_app(), base_url="http://127.0.0.1:8000") as c:
        yield c


def test_initialize_needs_no_header_and_sets_no_session(client):
    r = client.post("/mcp", headers=H, json=INIT)
    assert r.status_code == 200
    assert "mcp-session-id" not in r.headers
    assert r.json()["result"]["protocolVersion"] == "2025-11-25"


def test_later_request_without_version_header_is_400(client):
    r = client.post("/mcp", headers=H, json=LIST)
    assert r.status_code == 400
    assert r.json()["error"]["code"] == -32020


@pytest.mark.parametrize("version", ["2025-11-25", "2025-06-18"])
def test_supported_versions_list_19_tools(client, version):
    r = client.post("/mcp", headers={**H, "MCP-Protocol-Version": version}, json=LIST)
    assert r.status_code == 200
    assert len(r.json()["result"]["tools"]) == 19


def test_2025_03_26_is_not_served(client):
    r = client.post("/mcp", headers={**H, "MCP-Protocol-Version": "2025-03-26"}, json=LIST)
    assert r.status_code == 400
    assert r.json()["error"]["data"]["supported"] == ["2026-07-28", "2025-11-25", "2025-06-18"]


@pytest.mark.parametrize("method", ["GET", "DELETE"])
def test_non_post_is_405(client, method):
    assert client.request(method, "/mcp").status_code == 405


def test_stateless_across_replicas():
    """Two app instances, no stickiness: every call lands on a fresh replica (A4)."""
    apps = [TestClient(create_app(), base_url="http://127.0.0.1:8000") for _ in range(2)]
    with apps[0] as a, apps[1] as b:
        assert a.post("/mcp", headers=H, json=INIT).status_code == 200
        for i in range(200):
            r = (a, b)[i % 2].post("/mcp", headers={**H, "MCP-Protocol-Version": "2025-11-25"}, json=LIST)
            assert r.status_code == 200, r.text
            assert "mcp-session-id" not in r.headers


def test_foreign_host_rejected(client):
    r = client.post("/mcp", headers={**H, "Host": "evil.example"}, json=INIT)
    assert r.status_code == 421
