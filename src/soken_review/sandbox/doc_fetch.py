"""Supervisor side of the `context` step (context ingestion spec 2026-10-23, section 3): run
soken-doc-fetch in the sandbox, one container per document.

Mirrors `repo_fetch.py`: the `doc-fetch` image (digest from images.lock.json, `SOKEN_IMAGE_DOC_FETCH`
on a stand) runs on the `docs` family egress network with `out/` as its only writable mount, the
supervisor measures the job dir while it runs and removes the named container at the 60 s wall or
on a disk breach. The container's output is data: it is read with the fd-based `read_output_files`
(no symlink, no special file, byte cap), parsed, and every field is re-checked here; `kind` and
`url` come from the request, never from the file, and the file name is the supervisor's. A failure
of any sort is a per-document record (`status: failed`, `error` in the spec's set), never an
exception to the step.
"""

from __future__ import annotations

import json
import logging
import os
import re
import secrets
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from soken_review.context.fetcher import ADDRESS_SHAPES, ERRORS, MAX_TEXT_CHARS, MAX_TITLE_CHARS, check_url, clean_title
from soken_review.sandbox.egress import network_name
from soken_review.sandbox.profile import StepLimits, docker_argv, locked_image, sandbox_writable_dir
from soken_review.sandbox.repo_fetch import _tail_from_fh, run_watched

logger = logging.getLogger(__name__)

DOC_LIMITS = StepLimits(cpus=1.0, memory="1g", pids=64, max_file=16 * 1024 * 1024)
DOC_WALL_S = 60                          # per document (spec 3)
DOC_MAX_BYTES = 64 * 1024 * 1024         # job dir while the container runs
DOC_MAX_INODES = 500
OUTPUT_MAX_BYTES = 4 * 1024 * 1024       # the JSON the fetcher writes (400k chars of text plus hits)
FAMILY = "docs"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_MAX_HITS = 100


def failed_doc(kind: str, url: str, error: str, detail: str = "") -> dict[str, Any]:
    """A failed document record in the fetcher's shape (what the store receives)."""
    return {"kind": kind, "url": url, "final_url": None, "status": "failed", "content_type": None, "bytes": 0,
            "sha256_raw": None, "fetched_at": datetime.now(UTC).isoformat(timespec="seconds"), "title": "",
            "text": "", "bundle_hits": {}, "error": error if error in ERRORS else "unreachable",
            "error_detail": detail[:200]}


def fetch_document(kind: str, url: str, job_dir: Path, n: int, *, image: str | None = None,
                   runtime: str | None = None, wall_s: int = DOC_WALL_S) -> dict[str, Any]:
    """Fetch one document into a record for `ContextStore.add`. Never raises for a document failure."""
    try:
        url = check_url(url)
    except ValueError as exc:
        return failed_doc(kind, url, "blocked", f"url: {exc}")
    image = image or locked_image("doc-fetch")
    if image is None:
        logger.error("doc-fetch image not pinned; document %s recorded as unreachable", url[:80])
        return failed_doc(kind, url, "unreachable", "doc-fetch image not pinned")
    work = job_dir.resolve() / f"doc-{n}"      # bind mounts need absolute host paths
    if work.exists():
        shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True, exist_ok=True)
    out = sandbox_writable_dir(work / "out")
    sandbox_writable_dir(out / "context")
    name = f"soken-docfetch-{secrets.token_hex(6)}"
    command = ["soken-doc-fetch", "--kind", kind, "--url", url, "--out", f"/work/out/context/{n}.json",
               "--wall", str(max(wall_s - 10, 10))]
    argv = docker_argv(
        step="fetch", image=image, work_dir=work, cache_dir=None, limits=DOC_LIMITS, env={"HOME": "/tmp"},
        command=command, family_network=network_name(FAMILY),
        runtime=runtime or os.environ.get("SOKEN_SANDBOX_RUNTIME"), name=name,
        mounts=[(out, "/work/out", False)],
    )

    def kill() -> None:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False, timeout=60)

    # Host-only stderr in the per-document work root (only out/ is mounted), read back from the same
    # descriptor: the same hardening as repo_fetch (never re-opened by path).
    stderr_path = work / "fetch.stderr"
    try:
        with open(stderr_path, "w+b") as err_fh:
            code, killed_by = run_watched(argv, work, wall_s, kill, max_bytes=DOC_MAX_BYTES,
                                          max_inodes=DOC_MAX_INODES, stderr=err_fh)
            tail = _tail_from_fh(err_fh)
        doc = _read_output(out / "context", n, kind, url, code, killed_by, tail)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return doc


def _read_output(context_dir: Path, n: int, kind: str, url: str, code: int | None, killed_by: str | None,
                 tail: str) -> dict[str, Any]:
    from soken_review.sandbox.output import UnsafeOutput, read_output_files

    if killed_by == "wall":
        return failed_doc(kind, url, "timeout", "wall")
    if killed_by == "disk":
        return failed_doc(kind, url, "too_large", "disk")
    try:
        files = read_output_files(context_dir, f"{n}.json", 1, OUTPUT_MAX_BYTES)
    except FileNotFoundError:
        return failed_doc(kind, url, "unreachable", f"no output (exit {code}): {tail[-160:]}")
    except UnsafeOutput as exc:
        return failed_doc(kind, url, "unreachable", f"unsafe output: {exc}")
    raw = files.get(f"{n}.json")
    if raw is None:
        return failed_doc(kind, url, "unreachable", f"no output (exit {code}): {tail[-160:]}")
    try:
        data = json.loads(raw)
    except ValueError:
        return failed_doc(kind, url, "unreachable", "output not json")
    return sanitize_doc(data, kind, url)


def sanitize_doc(data: Any, kind: str, url: str) -> dict[str, Any]:
    """Re-check every field of the container's record; `kind` and `url` are the request's."""
    if not isinstance(data, dict):
        return failed_doc(kind, url, "unreachable", "output not an object")
    status = "ok" if data.get("status") == "ok" else "failed"
    doc: dict[str, Any] = failed_doc(kind, url, str(data.get("error") or "unreachable"),
                                     str(data.get("error_detail") or ""))
    final_url = data.get("final_url")
    if isinstance(final_url, str):
        try:
            doc["final_url"] = check_url(final_url)
        except ValueError:
            doc["final_url"] = None
    ct = data.get("content_type")
    doc["content_type"] = re.sub(r"[^\x20-\x7e]", "", ct)[:120] if isinstance(ct, str) else None
    size = data.get("bytes")
    doc["bytes"] = int(size) if isinstance(size, int) and 0 <= size < 2**40 else 0
    sha = data.get("sha256_raw")
    doc["sha256_raw"] = sha if isinstance(sha, str) and _HEX64.match(sha) else None
    at = data.get("fetched_at")
    if isinstance(at, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}T[0-9:.+\-]{8,24}", at):
        doc["fetched_at"] = at
    if status != "ok":
        return doc
    title = data.get("title")
    doc["title"] = clean_title(title)[:MAX_TITLE_CHARS] if isinstance(title, str) else ""
    text = data.get("text")
    doc["text"] = text[:MAX_TEXT_CHARS] if isinstance(text, str) else ""
    doc["bundle_hits"] = _sanitize_hits(data.get("bundle_hits"))
    doc.update(status="ok", error=None, error_detail="")
    return doc


def _sanitize_hits(hits: Any) -> dict[str, Any]:
    if not isinstance(hits, dict) or not hits:
        return {}
    out: dict[str, Any] = {"addresses": {}, "chain_ids": [], "bundles": []}
    addresses = hits.get("addresses")
    if isinstance(addresses, dict):
        for shape, rx in ADDRESS_SHAPES.items():
            values = addresses.get(shape)
            if not isinstance(values, list):
                continue
            keep = [v for v in values[:_MAX_HITS] if isinstance(v, str) and rx.fullmatch(v)]
            if keep:
                out["addresses"][shape] = keep
    ids = hits.get("chain_ids")
    if isinstance(ids, list):
        out["chain_ids"] = [int(i) for i in ids[:_MAX_HITS] if isinstance(i, int) and 0 < i < 2**53]
    bundles = hits.get("bundles")
    if isinstance(bundles, list):
        for b in bundles[:10]:
            if not isinstance(b, dict) or not isinstance(b.get("url"), str):
                continue
            try:
                b_url = check_url(b["url"])
            except ValueError:
                continue
            row = {"url": b_url, "bytes": int(b["bytes"]) if isinstance(b.get("bytes"), int) and b["bytes"] >= 0 else 0,
                   "status": "ok" if b.get("status") == "ok" else "failed"}
            if row["status"] == "failed" and b.get("error") in ERRORS:
                row["error"] = b["error"]
            out["bundles"].append(row)
    return out
