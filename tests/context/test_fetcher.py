"""soken-doc-fetch (spec section 3): URL checks, streaming cap, redirect cap, content handling,
failure statuses and the bundle scan, with a fake opener standing in for the proxy."""

from __future__ import annotations

import email.message
import io
import json
import time
import urllib.error
from pathlib import Path

import pytest

from soken_review.context import fetcher as f


class _Resp(io.BytesIO):
    def __init__(self, url: str, status: int, headers: dict[str, str], body: bytes) -> None:
        super().__init__(body)
        self._url, self.status = url, status
        self.headers = email.message.Message()
        for k, v in headers.items():
            self.headers[k] = v

    def geturl(self) -> str:
        return self._url


class FakeOpener:
    """url -> ("ok", status, headers, body) | ("redirect", code, location) | ("error", code) | ("raise", exc)."""

    def __init__(self, routes: dict) -> None:
        self.routes = routes
        self.calls: list[str] = []

    def open(self, req, timeout=None):
        url = req.full_url
        self.calls.append(url)
        route = self.routes.get(url)
        if route is None:
            raise urllib.error.URLError("Name or service not known")
        if route[0] == "ok":
            _, status, headers, body = route
            return _Resp(url, status, headers, body)
        if route[0] == "redirect":
            hdrs = email.message.Message()
            hdrs["Location"] = route[2]
            raise urllib.error.HTTPError(url, route[1], "moved", hdrs, io.BytesIO(b""))
        if route[0] == "error":
            raise urllib.error.HTTPError(url, route[1], "err", email.message.Message(), io.BytesIO(b""))
        raise route[1]


@pytest.fixture
def opener(monkeypatch):
    holder: dict = {}

    def install(routes: dict) -> FakeOpener:
        fo = FakeOpener(routes)
        holder["o"] = fo
        monkeypatch.setattr(f, "_opener", lambda: fo)
        return fo

    return install


def _deadline() -> float:
    return time.monotonic() + 30


# ── URL checks ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize("bad", [
    "http://example.org/", "https://user:pw@example.org/", "https://1.2.3.4/", "https://[2001:db8::1]/",
    "https://localhost/", "https://example.org:8443/", "ftp://example.org/x", "https://", "",
    "https://exa mple.org/", "https://example.org/" + "a" * 2100, "https://example.org\x00/",
    "https://-bad-.org/", "https://example.123/",
])
def test_check_url_refuses(bad: str) -> None:
    with pytest.raises(ValueError):
        f.check_url(bad)


@pytest.mark.parametrize("bad", [
    "https://example.org:443/", "https://example.org:8443/", "https://example.org:80/",   # any explicit port
    "https://127.0.0.1/", "https://[::1]/", "https://0x7f000001/", "https://169.254.169.254/latest/meta-data",
    "https://user@example.org/", "https://user:pw@example.org/", "https://example.org@evil.example/",
    "https://localhost/", "https://foo.localhost/", "https://db.internal/", "https://metadata.google.internal/",
    "https://printer.local/", "https://1.0.0.10.in-addr.arpa/", "https://x.home.arpa/", "https://router.lan/",
    "https://metadata/", "https://instance-data/",
])
def test_check_url_refuses_ssrf_shapes(bad: str) -> None:
    # Security review 2026-10-23: http, custom port, IP literal, userinfo, localhost, internal suffixes.
    with pytest.raises(ValueError):
        f.check_url(bad)


def test_check_url_accepts_and_drops_fragment() -> None:
    assert f.check_url("https://docs.sushi.com/a/b?x=1#frag") == "https://docs.sushi.com/a/b?x=1"
    assert f.check_url("https://www.sushi.com") == "https://www.sushi.com/"
    assert f.check_url("https://internal-tools.example.org/p") == "https://internal-tools.example.org/p"
    assert f.check_url("https://localhost.example.org/") == "https://localhost.example.org/"


# ── fetch_url ────────────────────────────────────────────────────────────────

def test_fetch_follows_https_redirects_up_to_three(opener) -> None:
    o = opener({
        "https://a.example/1": ("redirect", 301, "/2"),
        "https://a.example/2": ("redirect", 302, "https://b.example/3"),
        "https://b.example/3": ("redirect", 307, "https://b.example/4"),
        "https://b.example/4": ("ok", 200, {"Content-Type": "text/plain"}, b"done"),
    })
    got = f.fetch_url("https://a.example/1", 1000, _deadline())
    assert got.data == b"done" and got.final_url == "https://b.example/4"
    assert len(o.calls) == 4


def test_fetch_refuses_a_fourth_redirect(opener) -> None:
    opener({f"https://a.example/{i}": ("redirect", 302, f"https://a.example/{i + 1}") for i in range(1, 6)})
    with pytest.raises(f.Refusal) as exc:
        f.fetch_url("https://a.example/1", 1000, _deadline())
    assert exc.value.error == "unreachable" and "redirect" in exc.value.detail


def test_fetch_refuses_redirect_to_http_or_ip(opener) -> None:
    for target in ("http://a.example/plain", "https://10.0.0.1/meta", "https://user:x@a.example/"):
        opener({"https://a.example/r": ("redirect", 302, target)})
        with pytest.raises(f.Refusal) as exc:
            f.fetch_url("https://a.example/r", 1000, _deadline())
        assert exc.value.error == "blocked", target


def test_fetch_caps_bytes_while_streaming(opener) -> None:
    opener({"https://a.example/big": ("ok", 200, {"Content-Type": "text/plain"}, b"x" * 5000)})
    with pytest.raises(f.Refusal) as exc:
        f.fetch_url("https://a.example/big", 4096, _deadline())
    assert exc.value.error == "too_large"
    opener({"https://a.example/len": ("ok", 200, {"Content-Type": "text/plain", "Content-Length": "999999"}, b"x")})
    with pytest.raises(f.Refusal) as exc:
        f.fetch_url("https://a.example/len", 4096, _deadline())
    assert exc.value.error == "too_large"


@pytest.mark.parametrize("code,error", [(404, "unreachable"), (500, "unreachable"), (403, "blocked"), (451, "blocked")])
def test_fetch_maps_http_errors(opener, code: int, error: str) -> None:
    opener({"https://a.example/e": ("error", code)})
    with pytest.raises(f.Refusal) as exc:
        f.fetch_url("https://a.example/e", 1000, _deadline())
    assert exc.value.error == error


def test_fetch_maps_network_failures(opener) -> None:
    opener({"https://a.example/t": ("raise", TimeoutError())})
    with pytest.raises(f.Refusal) as exc:
        f.fetch_url("https://a.example/t", 1000, _deadline())
    assert exc.value.error == "timeout"
    opener({"https://a.example/p": ("raise", urllib.error.URLError("Tunnel connection failed: 403 Forbidden"))})
    with pytest.raises(f.Refusal) as exc:
        f.fetch_url("https://a.example/p", 1000, _deadline())
    assert exc.value.error == "blocked"
    opener({})
    with pytest.raises(f.Refusal) as exc:
        f.fetch_url("https://nowhere.example/", 1000, _deadline())
    assert exc.value.error == "unreachable"


def test_fetch_refuses_when_the_wall_is_spent(opener) -> None:
    opener({"https://a.example/": ("ok", 200, {}, b"x")})
    with pytest.raises(f.Refusal) as exc:
        f.fetch_url("https://a.example/", 1000, time.monotonic())
    assert exc.value.error == "timeout"


# ── content handling ─────────────────────────────────────────────────────────

def test_classify_and_decode() -> None:
    assert f.classify("text/html; charset=utf-8", b"<p>") == "html"
    assert f.classify("application/octet-stream", b"<!DOCTYPE html>") == "html"
    assert f.classify("application/pdf", b"junk") == "pdf"
    assert f.classify("", b"%PDF-1.7") == "pdf"
    assert f.classify("text/markdown", b"# x") == "text"
    assert f.classify("image/png", b"\x89PNG") == "unsupported"
    assert f.classify("application/octet-stream", b"\x00\x01") == "unsupported"
    assert f.decode_bytes("caf\xe9".encode("latin-1"), "text/html; charset=iso-8859-1") == "caf\xe9"
    assert f.decode_bytes(b"ok", "") == "ok"


def test_extract_html_title_and_text(fixtures: Path) -> None:
    title, text = f.extract_html((fixtures / "page.html").read_text())
    assert title == "Sample Protocol — Home"
    assert "Sample Protocol is a decentralised exchange" in text
    assert "0xC2EdaD668740f1aA35E4D8f227fB8E17dcA888Cd" in text
    assert "color: #333" not in text and "cdn.example.org" not in text


def test_extract_html_fallback_without_trafilatura(monkeypatch) -> None:
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name == "trafilatura":
            raise ImportError(name)
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    title, text = f.extract_html("<html><head><title>T</title><script>x()</script></head>"
                                 "<body><h1>Head</h1><p>One</p><p>Two</p></body></html>")
    assert title == "T" and text == "Head\n\nOne\n\nTwo"


def test_extract_pdf_two_pages(pdf_two_pages: bytes) -> None:
    pytest.importorskip("pdfminer")
    text = f.extract_pdf(pdf_two_pages)
    assert "Total supply: 21,000,000 tokens." in text and "fee of 1% on transfers" in text
    assert text.index("Total supply") < text.index("Page two")


def test_extract_pdf_refuses_garbage() -> None:
    pytest.importorskip("pdfminer")
    with pytest.raises(f.Refusal) as exc:
        f.extract_pdf(b"%PDF-1.4\nnot a pdf")
    assert exc.value.error == "unsupported_type"


def test_normalize_text_caps_and_strips_controls() -> None:
    assert f.normalize_text("a\r\nb\rc\x00d\n\n\n\ne  ") == "a\nb\ncd\n\ne"
    assert len(f.normalize_text("x" * (f.MAX_TEXT_CHARS + 10))) == f.MAX_TEXT_CHARS


def test_script_bundles_same_origin_only(fixtures: Path) -> None:
    markup = (fixtures / "app" / "index.html").read_text()
    assert f.script_bundles(markup, "https://app.example/") == ["https://app.example/static/main.js",
                                                                "https://app.example/static/vendor.js"]
    many = "".join(f'<script src="/b{i}.js"></script>' for i in range(9))
    assert len(f.script_bundles(many, "https://app.example/")) == f.MAX_BUNDLES


def test_find_addresses_and_chain_ids() -> None:
    text = ("router 0xC2EdaD668740f1aA35E4D8f227fB8E17dcA888Cd felt 0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7 "
            "sol 7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU ton EQDtFpEwcFAEcRe5mLVh2N6C0x-_hJEM7W61_JLnpTkIfBMZ "
            "raw 0:83dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8 chainId: 56 chain_id = \"0x1\" "
            "sha 0123456789abcdef0123456789abcdef01234567 notanaddress")
    hits = f.find_addresses(text)
    assert hits["evm"] == ["0xc2edad668740f1aa35e4d8f227fb8e17dca888cd"]
    assert hits["felt"] == ["0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7"]
    assert hits["solana"] == ["7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"]
    assert hits["ton"] == ["EQDtFpEwcFAEcRe5mLVh2N6C0x-_hJEM7W61_JLnpTkIfBMZ",
                           "0:83dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8"]
    assert f.find_chain_ids(text) == [56, 1]
    assert f.find_addresses("0x" + "a" * 40 + "b") == {}          # part of a longer token


# ── one document end to end ──────────────────────────────────────────────────

def test_fetch_document_html_app_scans_bundles(opener, fixtures: Path) -> None:
    o = opener({
        "https://app.example/": ("ok", 200, {"Content-Type": "text/html"}, (fixtures / "app" / "index.html").read_bytes()),
        "https://app.example/static/main.js": ("ok", 200, {"Content-Type": "application/javascript"},
                                               (fixtures / "app" / "static" / "main.js").read_bytes()),
        "https://app.example/static/vendor.js": ("ok", 200, {"Content-Type": "text/javascript"},
                                                 (fixtures / "app" / "static" / "vendor.js").read_bytes()),
    })
    out = f.fetch_document("app", "https://app.example/", _deadline())
    assert out["status"] == "ok" and out["error"] is None and out["title"] == "Sample App"
    assert set(out) >= {"kind", "url", "final_url", "status", "content_type", "bytes", "sha256_raw", "fetched_at",
                        "title", "text", "bundle_hits"}
    hits = out["bundle_hits"]
    assert [b["url"] for b in hits["bundles"]] == ["https://app.example/static/main.js", "https://app.example/static/vendor.js"]
    assert all(b["status"] == "ok" for b in hits["bundles"])
    assert hits["addresses"]["evm"] == ["0xc2edad668740f1aa35e4d8f227fb8e17dca888cd",
                                        "0xc0aee478e3658e2610c5f7a4a2e1777ce9e4f2ac",
                                        "0x3ee18b2214aff97000d974cf647e7c347e8fa585"]
    assert hits["chain_ids"] == [1, 56]
    assert "https://cdn.example.org/analytics.js" not in o.calls


def test_fetch_document_docs_kind_does_not_fetch_bundles(opener, fixtures: Path) -> None:
    o = opener({"https://d.example/": ("ok", 200, {"Content-Type": "text/html"}, (fixtures / "app" / "index.html").read_bytes())})
    out = f.fetch_document("docs", "https://d.example/", _deadline())
    assert out["status"] == "ok" and out["bundle_hits"] == {} and o.calls == ["https://d.example/"]


def test_fetch_document_records_failures_per_document(opener) -> None:
    opener({"https://x.example/img": ("ok", 200, {"Content-Type": "image/png"}, b"\x89PNG\x00\x00")})
    out = f.fetch_document("docs", "https://x.example/img", _deadline())
    assert out["status"] == "failed" and out["error"] == "unsupported_type" and out["text"] == ""
    assert out["sha256_raw"] is not None                     # the bytes were received and hashed
    opener({"https://x.example/gone": ("error", 404)})
    out = f.fetch_document("docs", "https://x.example/gone", _deadline())
    assert out["status"] == "failed" and out["error"] == "unreachable"
    assert out["error"] in f.ERRORS


def test_fetch_document_pdf(opener, pdf_two_pages: bytes) -> None:
    pytest.importorskip("pdfminer")
    opener({"https://x.example/wp.pdf": ("ok", 200, {"Content-Type": "application/pdf"}, pdf_two_pages)})
    out = f.fetch_document("whitepaper", "https://x.example/wp.pdf", _deadline())
    assert out["status"] == "ok" and "21,000,000" in out["text"] and out["bytes"] == len(pdf_two_pages)


def test_main_writes_json_and_exit_codes(opener, tmp_path: Path, capsys) -> None:
    opener({"https://x.example/t.md": ("ok", 200, {"Content-Type": "text/markdown"}, b"# Hello\n\nBody")})
    out = tmp_path / "0.json"
    assert f.main(["--kind", "docs", "--url", "https://x.example/t.md", "--out", str(out), "--wall", "10"]) == 0
    data = json.loads(out.read_text())
    assert data["status"] == "ok" and data["text"] == "# Hello\n\nBody" and data["kind"] == "docs"
    assert json.loads(capsys.readouterr().err.strip().splitlines()[-1])["status"] == "ok"
    assert f.main(["--kind", "docs", "--url", "http://x.example/", "--out", str(tmp_path / "1.json")]) == f.EXIT_INVALID
    assert f.main(["--kind", "Bad Kind", "--url", "https://x.example/", "--out", str(tmp_path / "2.json")]) == f.EXIT_INVALID


def test_bundle_redirect_to_another_origin_is_refused(opener) -> None:
    opener({"https://a.example/app.js": ("redirect", 302, "https://b.example/payload.js")})
    with pytest.raises(f.Refusal) as exc:
        f.fetch_url("https://a.example/app.js", 1000, _deadline(), same_origin_as="https://a.example/")
    assert exc.value.error == "blocked" and "origin" in exc.value.detail


def test_page_redirect_to_another_origin_is_still_followed(opener) -> None:
    opener({"https://a.example/": ("redirect", 302, "https://www.a.example/"),
            "https://www.a.example/": ("ok", 200, {"Content-Type": "text/html"}, b"<html>hi</html>")})
    got = f.fetch_url("https://a.example/", 1000, _deadline())
    assert got.final_url == "https://www.a.example/"
