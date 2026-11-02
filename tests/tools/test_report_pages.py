"""The /r/ report links (tools/report_pages): signature and expiry, the current render, key
versions, deletion through the manage page, escaping of untrusted report text, both hosts.
Until 2026-11-03 only the PDF link worked, through an nginx alias that ignored the signature and
always served render 1; the page and manage links answered 404."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

import httpx
import pytest
import pytest_asyncio

from soken_review.db.job_repo import JobRepo
from soken_review.tools import delete as D
from soken_review.tools import report as R
from soken_review.tools import report_pages as P
from tests.report.fixtures import report as fixture_report

JOB = "job_" + "0" * 24 + "P1"
RID = "pqrstuvwxyzabcdefghijklmn2"
KEY_V1 = "k1-" + "x" * 40
KEY_V2 = "k2-" + "y" * 40
EVIL = "<script>alert(1)</script>\"'&"


class _Ctx:
    def __init__(self, root: Path) -> None:
        self._root = root

    def get_pin_root(self) -> Path:
        return self._root

    def get_job_state(self, job_id: str) -> str | None:  # pragma: no cover
        return None

    def append_read(self, job_id: str, path: str, start: int, end: int) -> None:  # pragma: no cover
        return None


def _h(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


async def _cleanup(pool) -> None:
    async with pool.connection() as conn:
        await conn.execute("delete from reports where report_id = %s", (RID,))
        await conn.execute("delete from jobs where job_id = %s", (JOB,))
        await conn.execute("delete from report_tombstones where ref_hash in (%s, %s)", (_h(JOB), _h(RID)))


async def _seed(pool, store: Path, *, key_version: int = 1, owner: bool = False, days: int = 30) -> None:
    async with pool.connection() as conn:
        await JobRepo(conn).create(job_id=JOB, principal_key="p", surface="connector", state="queued",
                                   requester_role="third_party_public_code", source_kind="repo",
                                   source_args={"repo_url": "https://github.com/x/y", "commit": "ab" * 20},
                                   has_deployment=False)
        await conn.execute("update jobs set state = 'rendered', ownership_proven = %s, report_id = %s where job_id = %s",
                           (owner, RID, JOB))
        await conn.execute(
            """insert into reports (report_id, report_id_short, job_id, profile, object_prefix, out_name, pdf_sha256s,
                                    subject_candidates, key_version, rendered_at, expires_at)
               values (%s, %s, %s, 'public_review', %s, 'Vault_review.pdf', array[%s, %s]::char(64)[], '[]'::jsonb,
                       %s, now(), now() + make_interval(days => %s))""",
            (RID, RID[:10], JOB, f"reports/{RID}/2/", "a" * 64, "b" * 64, key_version, days))
    rep = fixture_report()
    rep["meta"]["subject"] = EVIL
    for n, body in ((1, b"%PDF-render-one"), (2, b"%PDF-render-two")):
        d = store / "reports" / RID / str(n)
        d.mkdir(parents=True, exist_ok=True)
        (d / "report.pdf").write_bytes(body)
        (d / "report.json").write_text(json.dumps(rep), encoding="utf-8")


@pytest_asyncio.fixture(loop_scope="session")
async def stack(db_pool, tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SOKEN_REPORT_KEY_V1", KEY_V1)
    monkeypatch.setenv("SOKEN_REPORT_KEY_V2", KEY_V2)
    monkeypatch.setenv("SOKEN_REPORT_STORE", str(tmp_path / "store"))
    R.set_pool(db_pool)
    D.set_pool(db_pool)
    D.set_context(_Ctx(tmp_path / "pins"))
    await _cleanup(db_pool)
    yield db_pool, tmp_path / "store"
    await _cleanup(db_pool)


def _client(host: str = "soken.dev") -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=P.app), base_url=f"https://{host}")


def _path(url: str) -> str:
    return url.split("soken.dev", 1)[1]


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.parametrize("host", ["soken.dev", "mcp.soken.dev"])
async def test_signed_pdf_serves_the_current_render_inline_uncached(stack, host) -> None:
    pool, store = stack
    await _seed(pool, store)
    lk = R.links(RID, "public_review", 1)
    async with _client(host) as c:
        r = await c.get(_path(lk["pdf_url"]))
    assert r.status_code == 200
    assert r.content == b"%PDF-render-two"          # object_prefix (render 2), not render 1
    assert r.headers["content-type"] == "application/pdf"
    assert r.headers["content-disposition"] == 'inline; filename="Vault_review.pdf"'
    assert r.headers["cache-control"] == "no-store"


@pytest.mark.asyncio(loop_scope="session")
async def test_bad_missing_or_expired_signature_is_403_with_the_hint(stack) -> None:
    pool, store = stack
    await _seed(pool, store)
    lk = R.links(RID, "public_review", 1)
    pdf = _path(lk["pdf_url"])
    sig = pdf.split("s=")[1]
    tampered = pdf.replace(sig, sig[:-1] + ("b" if sig[-1] != "b" else "c"))
    past = int(time.time()) - 10
    expired = f"/r/{RID}.pdf?e={past}&s={R.view_signature(RID, past, 1)}"
    async with _client() as c:
        for url in (tampered, f"/r/{RID}.pdf", f"/r/{RID}.pdf?e=abc&s=x", expired, _path(lk["url"]).replace(sig, "a" * 26)):
            r = await c.get(url)
            assert r.status_code == 403, url
            assert "review_report" in r.text
            assert b"%PDF" not in r.content


@pytest.mark.asyncio(loop_scope="session")
async def test_links_verify_under_the_report_key_version(stack) -> None:
    pool, store = stack
    await _seed(pool, store, key_version=2)
    async with _client() as c:
        assert (await c.get(_path(R.links(RID, "public_review", 2)["pdf_url"]))).status_code == 200
        assert (await c.get(_path(R.links(RID, "public_review", 1)["pdf_url"]))).status_code == 403


@pytest.mark.asyncio(loop_scope="session")
async def test_unknown_and_expired_reports_are_404(stack) -> None:
    pool, store = stack
    other = "a" * 26
    async with _client() as c:
        assert (await c.get(_path(R.links(other, "public_review", 1)["pdf_url"]))).status_code == 404
        assert (await c.get("/r/NOT-AN-ID.pdf")).status_code == 404
        await _seed(pool, store, days=-1)
        assert (await c.get(_path(R.links(RID, "public_review", 1)["pdf_url"]))).status_code == 404
        assert (await c.get(_path(R.links(RID, "public_review", 1)["url"]))).status_code == 404


@pytest.mark.asyncio(loop_scope="session")
async def test_owner_links_carry_no_signature_and_still_work(stack) -> None:
    pool, store = stack
    await _seed(pool, store, owner=True)
    lk = R.links(RID, "owner", 1)
    assert "?" not in lk["pdf_url"]
    async with _client() as c:
        assert (await c.get(_path(lk["pdf_url"]))).status_code == 200
        assert (await c.get(f"/r/{RID}.pdf?e=1&s={'a' * 26}")).status_code == 403   # present means checked


@pytest.mark.asyncio(loop_scope="session")
async def test_view_page_escapes_report_text_and_loads_nothing_external(stack) -> None:
    pool, store = stack
    await _seed(pool, store)
    lk = R.links(RID, "public_review", 1)
    async with _client() as c:
        r = await c.get(_path(lk["url"]))
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/html")
    assert "<script" not in r.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;&quot;&#x27;&amp;" in r.text
    assert "script-src" not in r.headers["content-security-policy"]
    assert "default-src 'none'" in r.headers["content-security-policy"]
    assert "http://" not in r.text and "https://" not in r.text
    query = lk["pdf_url"].split("?", 1)[1].replace("&", "&amp;")
    assert f'href="/r/{RID}.pdf?{query}"' in r.text
    assert r.headers["cache-control"] == "no-store"


@pytest.mark.asyncio(loop_scope="session")
async def test_manage_page_and_delete_through_the_manage_endpoint(stack) -> None:
    pool, store = stack
    await _seed(pool, store)
    lk = R.links(RID, "public_review", 1)
    page, _, frag = _path(lk["manage_url"]).partition("#")
    key = frag.removeprefix("k=")
    async with _client() as c:
        r = await c.get(page)
        assert r.status_code == 200 and "Delete report" in r.text
        nonce = r.headers["content-security-policy"].split("'nonce-")[1].split("'")[0]
        assert f'<script nonce="{nonce}">' in r.text
        assert (await c.post(page, content=f"key={key}&action=delete",
                             headers={"content-type": "application/x-www-form-urlencoded"})).status_code == 415
        assert (await c.post(page, json={"key": "a" * 26, "action": "delete"})).status_code == 403
        assert (await c.post(page, json={"key": key, "action": "nuke"})).status_code == 400
        st = await c.post(page, json={"key": key, "action": "status"})
        assert st.status_code == 200 and st.json()["subject"] == EVIL   # JSON, set via textContent client-side
        assert (await c.get(_path(lk["pdf_url"]))).status_code == 200
        d = await c.post(page, json={"key": key, "action": "delete"})
        assert d.status_code == 200 and d.json()["state"] == "deleted" and "pdf" in d.json()["deleted"]
        assert (await c.get(_path(lk["pdf_url"]))).status_code == 404
        assert (await c.get(_path(lk["url"]))).status_code == 404
        assert (await c.post(page, json={"key": key, "action": "delete"})).status_code == 404
    assert not (store / "reports" / RID).exists()
    async with pool.connection() as conn:
        tomb = await (await conn.execute("select kind, reason from report_tombstones where ref_hash in (%s, %s) order by kind",
                                         (_h(JOB), _h(RID)))).fetchall()
        state = await (await conn.execute("select state from jobs where job_id = %s", (JOB,))).fetchone()
    assert ("job", "user_delete") in tomb and ("report", "user_delete") in tomb
    assert state[0] == "deleted"


@pytest.mark.asyncio(loop_scope="session")
async def test_wrapper_routes_report_paths_ahead_of_the_mcp_app(monkeypatch) -> None:
    from soken_review.tools.context_pg import _LifespanWrapper

    seen: list[str] = []

    async def inner(scope, receive, send):
        seen.append("inner")

    async def pages(scope, receive, send):
        seen.append("pages")

    monkeypatch.setattr(P, "app", pages)
    w = _LifespanWrapper(inner, "postgresql://unused", Path("/tmp"))
    await w({"type": "http", "path": f"/r/{RID}.pdf", "headers": []}, None, None)
    await w({"type": "http", "path": "/mcp", "headers": []}, None, None)
    assert seen == ["pages", "inner"]


def test_review_report_link_shapes_are_unchanged() -> None:
    """outputSchema of review_report is fixed (old cached clients): the links still match it."""
    from soken_review.server import output_violations

    body = {"accepted": True, "report_id": RID, **R.links(RID, "public_review", 1)}
    assert [v for v in output_violations("review_report", body) if v.split(":")[0] in ("url", "pdf_url", "manage_url")] == []
