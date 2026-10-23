"""soken-doc-fetch: sandboxed document fetcher of the context ingestion spec (2026-10-23, section 3).

Runs inside the `doc-fetch` image (Debian slim, python3, trafilatura, pdfminer.six,
charset-normalizer; no browser, no JS execution) on the `docs` egress network as uid 10001 with a
read-only root. Everything it is given is untrusted: the URL is re-checked here, every byte is
counted while it streams, redirects are followed at most three times and only to https, and the
output file name comes from the supervisor, never from the document.

    soken-doc-fetch --kind KIND --url URL --out /work/out/context/<n>.json [--wall 50]

Writes one JSON object: `{kind, url, final_url, status, content_type, bytes, sha256_raw,
fetched_at, title, text, bundle_hits, error}`. `status` is `ok` or `failed`; a failure never
raises, it is recorded in `error` as one of `unreachable, too_large, unsupported_type, blocked,
timeout`. For `kind: app` and `kind: website` up to five same-origin script bundles named by the
HTML are fetched (5 MiB each) and scanned for addresses and chain ids (`bundle_hits`).

Standard library plus the three extractors; the host side (`sandbox/doc_fetch.py`) imports this
module only for `check_url`, `find_addresses` and the regexes, which need nothing else. The
extractors are imported lazily so the module imports on any host.
"""

from __future__ import annotations

import argparse
import hashlib
import html as _html
import ipaddress
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from html.parser import HTMLParser

EXIT_OK, EXIT_INVALID, EXIT_INTERNAL = 0, 25, 26

MAX_URL_LEN = 2048
MAX_REDIRECTS = 3
MAX_DOC_BYTES = 10 * 1024 * 1024        # 10 MiB response cap, counted while streaming
MAX_BUNDLE_BYTES = 5 * 1024 * 1024      # 5 MiB per script bundle
MAX_BUNDLES = 5
MAX_TEXT_CHARS = 400_000
MIN_MAIN_TEXT_CHARS = 1000                # below this, trafilatura's article text is compared with the plain text
MAX_TITLE_CHARS = 200
MAX_HITS_PER_SHAPE = 100
WALL_S = 50                             # the supervisor kills the container at 60 s
ACCEPT = "text/html, application/pdf, text/plain, text/markdown"
USER_AGENT = "soken-doc-fetch/1 (+https://soken.dev)"
ERRORS = ("unreachable", "too_large", "unsupported_type", "blocked", "timeout")
BUNDLE_KINDS = ("app", "website")

# Address shapes the adapters recognise (one place for every regex of the feature):
#   evm      0x + 40 hex (EVM, HyperEVM; TRON base58 is left out: too close to Solana's shape)
#   solana   32 to 44 base58 characters, mixed case with a digit (a bare hash or a word never is)
#   ton      user-friendly 48-char base64url with the EQ/UQ/kQ/0Q tag, or raw `wc:hex64`
#   felt     0x + 50 to 64 hex: Starknet contract addresses, Aptos and Sui object ids
ADDRESS_SHAPES: dict[str, re.Pattern[str]] = {
    "evm": re.compile(r"(?<![0-9A-Za-z])0x[0-9a-fA-F]{40}(?![0-9A-Za-z])"),
    "solana": re.compile(r"(?<![0-9A-Za-z])(?=[1-9A-HJ-NP-Za-km-z]*[0-9])(?=[1-9A-HJ-NP-Za-km-z]*[a-z])"
                         r"(?=[1-9A-HJ-NP-Za-km-z]*[A-Z])[1-9A-HJ-NP-Za-km-z]{32,44}(?![0-9A-Za-z])"),
    "ton": re.compile(r"(?<![0-9A-Za-z_-])(?:[EUk0]Q[A-Za-z0-9_-]{46}|-?[0-9]:[0-9a-fA-F]{64})(?![0-9A-Za-z_-])"),
    "felt": re.compile(r"(?<![0-9A-Za-z])0x[0-9a-fA-F]{50,64}(?![0-9A-Za-z])"),
}
CHAIN_ID_RE = re.compile(r"""chain_?[iI]d\s*["']?\s*[:=]\s*["']?(0x[0-9a-fA-F]{1,8}|[0-9]{1,10})""")
_SCRIPT_SRC_RE = re.compile(r"""<script\b[^>]*?\ssrc\s*=\s*["']?([^"'\s>]+)""", re.IGNORECASE)
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_CHARSET_RE = re.compile(r"charset=\"?([A-Za-z0-9._-]{1,40})", re.IGNORECASE)
_HTML_SNIFF_RE = re.compile(rb"<!doctype\s+html|<html[\s>]|<head[\s>]|<body[\s>]", re.IGNORECASE)
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class Refusal(Exception):
    def __init__(self, error: str, detail: str = "") -> None:
        super().__init__(error)
        self.error, self.detail = error, detail


# ---------------------------------------------------------------------------------------------
# URL checks (repeated on the host; the container trusts nothing it is given)
# ---------------------------------------------------------------------------------------------

# Host names the fetcher never connects to, whatever the proxy says (mirrors the proxy's
# global_deny_list in sandbox/egress.py): loopback, link-local, mDNS, private DNS suffixes,
# reverse zones and the cloud metadata hosts. Suffix entries match the name and every subdomain.
DENIED_HOSTS = ("localhost", "metadata", "instance-data", "metadata.google.internal", "169.254.169.254")
DENIED_SUFFIXES = (".localhost", ".internal", ".local", ".arpa", ".lan", ".intranet", ".corp", ".private")


def check_url(url: str) -> str:
    """`https://` only, no explicit port (443 implied), at most 2048 chars, no credentials, no IP
    literal, a dotted public host name outside DENIED_HOSTS / DENIED_SUFFIXES.

    Returns the URL without its fragment. Raises ValueError with a short reason otherwise. The
    proxy re-checks the resolved address at connect time (smokescreen deny ranges), which covers
    DNS rebinding; this check keeps the obvious cases from ever leaving the container.
    """
    if not isinstance(url, str) or not url or len(url) > MAX_URL_LEN:
        raise ValueError("length")
    if any(ord(c) < 0x21 or ord(c) == 0x7F for c in url):
        raise ValueError("control character")
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError as exc:
        raise ValueError("parse") from exc
    if parts.scheme != "https":
        raise ValueError("scheme")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise ValueError("credentials")
    host = (parts.hostname or "").rstrip(".")
    if not host or not host.isascii() or len(host) > 253:
        raise ValueError("host")
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        pass
    else:
        raise ValueError("ip literal")
    labels = host.split(".")
    if len(labels) < 2 or not all(re.fullmatch(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?", lb, re.IGNORECASE) for lb in labels):
        raise ValueError("host")
    if not re.fullmatch(r"[a-z]{2,63}", labels[-1], re.IGNORECASE):
        raise ValueError("host")
    lower = host.lower()
    if lower in DENIED_HOSTS or any(lower.endswith(sfx) for sfx in DENIED_SUFFIXES):
        raise ValueError("denied host")
    if ":" in parts.netloc:            # any explicit port, 443 included: the only port is the implied 443
        raise ValueError("port")
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))


def same_origin(a: str, b: str) -> bool:
    pa, pb = urllib.parse.urlsplit(a), urllib.parse.urlsplit(b)
    return (pa.scheme, (pa.hostname or "").lower(), pa.port or 443) == (pb.scheme, (pb.hostname or "").lower(), pb.port or 443)


# ---------------------------------------------------------------------------------------------
# Address and chain id scan (shared with the host-side facts extractor)
# ---------------------------------------------------------------------------------------------

def find_addresses(text: str) -> dict[str, list[str]]:
    """{shape: [address, ...]} deduplicated in order of first appearance, at most 100 per shape.

    A felt (0x + 50..64 hex) is never also reported as an EVM address; the EVM regex cannot match
    inside it because of the look-arounds.
    """
    out: dict[str, list[str]] = {}
    for shape, rx in ADDRESS_SHAPES.items():
        seen: dict[str, None] = {}
        for m in rx.finditer(text):
            value = m.group(0)
            if shape == "evm":
                value = value.lower()
            if value not in seen:
                seen[value] = None
                if len(seen) >= MAX_HITS_PER_SHAPE:
                    break
        if seen:
            out[shape] = list(seen)
    return out


def find_chain_ids(text: str) -> list[int]:
    seen: dict[int, None] = {}
    for m in CHAIN_ID_RE.finditer(text):
        raw = m.group(1)
        try:
            value = int(raw, 16) if raw.lower().startswith("0x") else int(raw)
        except ValueError:
            continue
        if 0 < value < 2**53 and value not in seen:
            seen[value] = None
        if len(seen) >= MAX_HITS_PER_SHAPE:
            break
    return list(seen)


# ---------------------------------------------------------------------------------------------
# HTTP (urllib through the proxy of the environment; the smokescreen is the only route out)
# ---------------------------------------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Fetched:
    __slots__ = ("content_type", "data", "final_url", "status", "truncated")

    def __init__(self, final_url: str, status: int, content_type: str, data: bytes, truncated: bool) -> None:
        self.final_url, self.status, self.content_type, self.data, self.truncated = (
            final_url, status, content_type, data, truncated)


def _opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(urllib.request.ProxyHandler(), _NoRedirect())


def _read_capped(resp, cap: int) -> tuple[bytes, bool]:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = resp.read(min(65536, cap + 1 - total))
        if not chunk:
            return b"".join(chunks), False
        chunks.append(chunk)
        total += len(chunk)
        if total > cap:
            return b"".join(chunks), True


def fetch_url(url: str, cap: int, deadline: float, accept: str = ACCEPT, same_origin_as: str | None = None) -> Fetched:
    """GET `url` with at most three https redirects and `cap` bytes. Raises Refusal. With
    `same_origin_as`, every redirect hop must stay on that origin (script bundles: a bundle the
    page names may not bounce the fetcher to an arbitrary site)."""
    current = check_url(url)
    opener = _opener()
    for _hop in range(MAX_REDIRECTS + 1):
        remaining = deadline - time.monotonic()
        if remaining <= 1:
            raise Refusal("timeout", "wall")
        req = urllib.request.Request(current, headers={"Accept": accept, "User-Agent": USER_AGENT,
                                                       "Accept-Encoding": "identity"})
        try:
            resp = opener.open(req, timeout=min(20.0, remaining))
        except urllib.error.HTTPError as exc:
            if exc.code in (301, 302, 303, 307, 308):
                location = exc.headers.get("Location") or ""
                exc.close()
                if not location:
                    raise Refusal("unreachable", "redirect without location") from None
                target = urllib.parse.urljoin(current, location)
                try:
                    current = check_url(target)
                except ValueError as why:
                    raise Refusal("blocked", f"redirect refused: {why}") from None
                if same_origin_as is not None and not same_origin(current, same_origin_as):
                    raise Refusal("blocked", "redirect refused: leaves the page origin")
                continue
            code = exc.code
            exc.close()
            if code in (401, 403, 407, 451):
                raise Refusal("blocked", f"http {code}") from None
            raise Refusal("unreachable", f"http {code}") from None
        except TimeoutError:
            raise Refusal("timeout", "socket") from None
        except urllib.error.URLError as exc:
            reason = str(exc.reason)
            if "Tunnel connection failed" in reason or "403" in reason or "denied" in reason.lower():
                raise Refusal("blocked", reason[:120]) from None
            if "timed out" in reason:
                raise Refusal("timeout", reason[:120]) from None
            raise Refusal("unreachable", reason[:120]) from None
        except (OSError, ValueError) as exc:
            raise Refusal("unreachable", str(exc)[:120]) from None
        with resp:
            length = resp.headers.get("Content-Length")
            if length and length.isdigit() and int(length) > cap:
                raise Refusal("too_large", f"content-length {length}")
            try:
                data, truncated = _read_capped(resp, cap)
            except TimeoutError:
                raise Refusal("timeout", "read") from None
            except OSError as exc:
                raise Refusal("unreachable", str(exc)[:120]) from None
            content_type = (resp.headers.get("Content-Type") or "").strip()
            final_url = resp.geturl() or current
        if truncated:
            raise Refusal("too_large", f"over {cap} bytes")
        return Fetched(final_url, resp.status, content_type, data, False)
    raise Refusal("unreachable", "too many redirects")


# ---------------------------------------------------------------------------------------------
# Content handling
# ---------------------------------------------------------------------------------------------

def classify(content_type: str, data: bytes) -> str:
    """`html`, `pdf`, `text` or `unsupported`, from the header first and the bytes second."""
    main = content_type.split(";", 1)[0].strip().lower()
    head = data[:2048]
    if data.startswith(b"%PDF-"):
        return "pdf"
    if main in ("text/html", "application/xhtml+xml") or _HTML_SNIFF_RE.search(head):
        return "html"
    if main == "application/pdf":
        return "pdf"
    if main in ("text/plain", "text/markdown", "text/x-markdown", "application/json", "text/csv"):
        return "text"
    if (main == "application/octet-stream" or not main) and b"\x00" not in head:
        return "text"
    return "unsupported"


def decode_bytes(data: bytes, content_type: str) -> str:
    m = _CHARSET_RE.search(content_type or "")
    if m:
        try:
            return data.decode(m.group(1), errors="replace")
        except LookupError:
            pass
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        pass
    try:
        from charset_normalizer import from_bytes  # type: ignore[import-not-found]

        best = from_bytes(data).best()
        if best is not None:
            return str(best)
    except ImportError:
        pass
    return data.decode("utf-8", errors="replace")


class _TextHTMLParser(HTMLParser):
    """Fallback extractor: visible text with block breaks; scripts and styles dropped."""

    _BLOCKS = frozenset({"p", "div", "br", "li", "h1", "h2", "h3", "h4", "h5", "h6", "tr", "section", "article",
                         "header", "footer", "table", "ul", "ol", "pre", "blockquote", "td", "th", "nav", "main"})
    _SKIP = frozenset({"script", "style", "noscript", "template", "svg", "head", "title"})

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag in self._SKIP:
            self._skip += 1
        elif tag in self._BLOCKS:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in self._SKIP and self._skip:
            self._skip -= 1
        elif tag in self._BLOCKS:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self._skip:
            self.parts.append(data)


def html_title(markup: str) -> str:
    m = _TITLE_RE.search(markup)
    return clean_title(_html.unescape(m.group(1))) if m else ""


def clean_title(title: str) -> str:
    title = _CONTROL_RE.sub("", title.replace("\r", " ").replace("\n", " ").replace("\t", " "))
    return re.sub(r"\s+", " ", title).strip()[:MAX_TITLE_CHARS]


def extract_html(markup: str) -> tuple[str, str]:
    """(title, text). trafilatura when installed (the image), the stdlib parser otherwise."""
    title = html_title(markup)
    text = None
    try:
        import trafilatura  # type: ignore[import-not-found]

        text = trafilatura.extract(markup, include_links=False, include_tables=True, include_comments=False,
                                   favor_recall=True, output_format="txt")
    except ImportError:
        text = None
    except Exception:  # noqa: BLE001  # a parser failure on hostile markup is a fallback, not a crash
        text = None
    if not text or len(text) < MIN_MAIN_TEXT_CHARS:
        # No article body (a client-rendered app shell, a consent banner only): the plain visible
        # text of the page is the better record when it says more.
        parser = _TextHTMLParser()
        try:
            parser.feed(markup)
            parser.close()
        except Exception:  # noqa: BLE001, S110  # hostile markup: keep whatever text was collected
            pass
        plain = "".join(parser.parts)
        if len(normalize_text(plain)) > len(normalize_text(text or "")):
            text = plain
    return title, normalize_text(text or "")


def extract_pdf(data: bytes) -> str:
    try:
        from pdfminer.high_level import extract_text  # type: ignore[import-not-found]
    except ImportError as exc:
        raise Refusal("unsupported_type", "pdf extractor missing") from exc
    import io

    try:
        text = extract_text(io.BytesIO(data), maxpages=400)
    except Exception as exc:  # pdfminer raises many types on hostile input
        raise Refusal("unsupported_type", f"pdf: {type(exc).__name__}") from exc
    return normalize_text(text or "")


def normalize_text(text: str) -> str:
    """LF line endings, control characters dropped, trailing blanks trimmed, hard cap on length."""
    text = text.replace("\r\n", "\n").replace("\r", "\n").replace("\x0c", "\n")
    text = _CONTROL_RE.sub("", text)
    lines = [ln.rstrip() for ln in text.split("\n")]
    out: list[str] = []
    blank = 0
    for ln in lines:
        if ln == "":
            blank += 1
            if blank > 1:
                continue
        else:
            blank = 0
        out.append(ln)
    text = "\n".join(out).strip("\n")
    return text[:MAX_TEXT_CHARS]


def script_bundles(markup: str, base_url: str) -> list[str]:
    """Same-origin script URLs named by the HTML, in order, at most MAX_BUNDLES, each a valid https URL."""
    out: list[str] = []
    for m in _SCRIPT_SRC_RE.finditer(markup):
        src = _html.unescape(m.group(1)).strip()
        if not src or src.startswith(("data:", "javascript:", "blob:")):
            continue
        target = urllib.parse.urljoin(base_url, src)
        try:
            target = check_url(target)
        except ValueError:
            continue
        if not same_origin(target, base_url) or target in out:
            continue
        out.append(target)
        if len(out) >= MAX_BUNDLES:
            break
    return out


# ---------------------------------------------------------------------------------------------
# One document
# ---------------------------------------------------------------------------------------------

def fetch_document(kind: str, url: str, deadline: float) -> dict:
    out: dict = {"kind": kind, "url": url, "final_url": None, "status": "failed", "content_type": None,
                 "bytes": 0, "sha256_raw": None, "fetched_at": datetime.now(UTC).isoformat(timespec="seconds"),
                 "title": "", "text": "", "bundle_hits": {}, "error": None}
    try:
        got = fetch_url(url, MAX_DOC_BYTES, deadline)
        out.update(final_url=got.final_url, content_type=got.content_type, bytes=len(got.data),
                   sha256_raw=hashlib.sha256(got.data).hexdigest())
        family = classify(got.content_type, got.data)
        if family == "unsupported":
            raise Refusal("unsupported_type", got.content_type[:80])
        if family == "pdf":
            text = extract_pdf(got.data)
            title = ""
            markup = ""
        elif family == "html":
            markup = decode_bytes(got.data, got.content_type)
            title, text = extract_html(markup)
        else:
            markup = ""
            text = normalize_text(decode_bytes(got.data, got.content_type))
            title = ""
        hits: dict = {}
        if kind in BUNDLE_KINDS and markup:
            hits = scan_bundles(markup, got.final_url, deadline)
        out.update(status="ok", title=title, text=text, bundle_hits=hits)
    except Refusal as r:
        out.update(error=r.error, error_detail=r.detail[:200])
    except Exception as exc:  # noqa: BLE001  # anything else is still a per-document failure
        out.update(error="unreachable", error_detail=type(exc).__name__)
    return out


def scan_bundles(markup: str, page_url: str, deadline: float) -> dict:
    """Addresses and chain ids in the page markup plus up to five same-origin script bundles."""
    hits: dict = {"addresses": {}, "chain_ids": [], "bundles": []}
    sources = [("page", markup)]
    for bundle_url in script_bundles(markup, page_url):
        row = {"url": bundle_url, "bytes": 0, "status": "failed"}
        try:
            got = fetch_url(bundle_url, MAX_BUNDLE_BYTES, deadline, accept="*/*", same_origin_as=page_url)
            row.update(bytes=len(got.data), status="ok")
            sources.append((bundle_url, decode_bytes(got.data, got.content_type)))
        except Refusal as r:
            row["error"] = r.error
        hits["bundles"].append(row)
    seen_ids: dict[int, None] = {}
    for _name, text in sources:
        for shape, values in find_addresses(text).items():
            bucket = hits["addresses"].setdefault(shape, [])
            for v in values:
                if v not in bucket and len(bucket) < MAX_HITS_PER_SHAPE:
                    bucket.append(v)
        for cid in find_chain_ids(text):
            seen_ids.setdefault(cid, None)
    hits["chain_ids"] = list(seen_ids)[:MAX_HITS_PER_SHAPE]
    return hits


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="soken-doc-fetch")
    p.add_argument("--kind", required=True)
    p.add_argument("--url", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--wall", type=float, default=WALL_S)
    args = p.parse_args(argv)
    if not re.fullmatch(r"[a-z]{1,20}", args.kind):
        print(json.dumps({"exit": EXIT_INVALID, "error": "kind"}), file=sys.stderr)
        return EXIT_INVALID
    try:
        check_url(args.url)
    except ValueError as exc:
        print(json.dumps({"exit": EXIT_INVALID, "error": f"url: {exc}"}), file=sys.stderr)
        return EXIT_INVALID
    deadline = time.monotonic() + min(float(args.wall), WALL_S)
    doc = fetch_document(args.kind, args.url, deadline)
    try:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, ensure_ascii=False)
    except OSError as exc:
        print(json.dumps({"exit": EXIT_INTERNAL, "error": type(exc).__name__}), file=sys.stderr)
        return EXIT_INTERNAL
    print(json.dumps({"exit": EXIT_OK, "status": doc["status"], "error": doc.get("error"),
                      "bytes": doc["bytes"], "chars": len(doc["text"])}), file=sys.stderr)
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
