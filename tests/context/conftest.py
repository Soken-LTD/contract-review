"""Shared fixtures of the context ingestion tests: fixture documents and a hand-written PDF."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "context"
JOB_ID = "job_CTX0000000000000000000000A"


def make_pdf(pages: list[str]) -> bytes:
    """A minimal uncompressed PDF (Helvetica, one text line per page) with a correct xref table.

    reportlab is not installed; pdfminer reads this shape (one content stream per page).
    """
    objs: list[bytes] = []

    def add(body: bytes) -> int:
        objs.append(body)
        return len(objs)

    font = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    page_ids: list[int] = []
    pages_id = len(objs) + 1 + 2 * len(pages)   # the Pages object comes after every page and stream
    for text in pages:
        esc = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        stream = f"BT /F1 12 Tf 72 720 Td ({esc}) Tj ET".encode("latin-1")
        content = add(b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream")
        page = add(f"<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 612 792] /Contents {content} 0 R "
                   f"/Resources << /Font << /F1 {font} 0 R >> >> >>".encode())
        page_ids.append(page)
    kids = " ".join(f"{p} 0 R" for p in page_ids)
    real_pages = add(f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>".encode())
    assert real_pages == pages_id
    catalog = add(f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode())
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for i, body in enumerate(objs, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + body + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objs) + 1}\n".encode() + b"0000000000 65535 f \n"
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += f"trailer\n<< /Size {len(objs) + 1} /Root {catalog} 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return bytes(out)


def doc(kind: str, url: str | None, text: str, *, title: str = "", status: str = "ok", error: str | None = None,
        bundle_hits: dict | None = None, inline_path: str | None = None, fetched_at: str = "2026-10-23T10:00:00+00:00",
        content_type: str = "text/markdown") -> dict:
    """A fetcher-shaped document record for ContextStore.add."""
    raw = text.encode("utf-8")
    return {"kind": kind, "url": url, "final_url": url, "status": status, "content_type": content_type,
            "bytes": len(raw), "sha256_raw": hashlib.sha256(raw).hexdigest(), "fetched_at": fetched_at,
            "title": title, "text": text if status == "ok" else "", "bundle_hits": bundle_hits or {},
            "error": error, "inline_path": inline_path}


@pytest.fixture
def fixtures() -> Path:
    return FIXTURES


@pytest.fixture
def pdf_two_pages() -> bytes:
    return make_pdf(["Total supply: 21,000,000 tokens.", "Page two: fee of 1% on transfers."])
