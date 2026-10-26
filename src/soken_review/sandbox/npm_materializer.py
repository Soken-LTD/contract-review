"""soken-npm-fetch: npm registry downloader for the EVM deps step. Standard library only.

Runs inside the `git-fetch` image on the `evm` egress network (09 4.3), as uid 10001 with a
read-only root. It is a plain downloader: the supervisor decides WHAT to fetch (package names,
exact versions, lockfile integrity) and checks every byte that comes back (sha512 integrity,
tar members, paths, caps) on the host. This process only performs HTTPS GETs on
`https://registry.npmjs.org/...` through the family proxy and writes each body to one file.

    soken-npm-fetch --plan /work/in/plan.json --out /work/out [--wall S]

plan.json: {"requests": [{"id": "r0", "url": "https://registry.npmjs.org/...",
                          "kind": "tarball" | "metadata", "max_bytes": 20971520}, ...]}
Output: /work/out/<id>.bin per successful request and /work/out/manifest.json with one result row
per request: {"id", "status": ok | not_found | http_error | too_large | refused_url | network,
"bytes", "http_status"}.

Never followed: redirects (a registry answer that points elsewhere is refused), non-https URLs,
any other host. No package code runs here or anywhere else (no install scripts, no npm).

Exit codes: 0 manifest written (per-request failures are rows, not exits); 20 every request
failed on the network (transient, the supervisor may retry); 25 invalid plan; 26 internal.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

EXIT_OK, EXIT_TRANSIENT, EXIT_INVALID, EXIT_INTERNAL = 0, 20, 25, 26

REGISTRY = "https://registry.npmjs.org/"
# Path characters npm uses in package and tarball URLs ("%2f" encodes the scope slash).
URL_RE = re.compile(r"^https://registry\.npmjs\.org/[A-Za-z0-9@%._~+/-]{1,400}$")
ID_RE = re.compile(r"^r[0-9]{1,4}$")
MAX_REQUESTS = 400
MAX_BYTES_PER_REQUEST = 64 * 1024 * 1024
MAX_BYTES_TOTAL = 512 * 1024 * 1024
REQUEST_TIMEOUT_S = 30
WALL_S = 110
CHUNK = 64 * 1024
ACCEPT = {
    # Abbreviated packument: versions, dist.integrity, dependencies (npm registry API).
    "metadata": "application/vnd.npm.install-v1+json",
    "tarball": "application/octet-stream",
}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)


def valid_url(url: object) -> bool:
    """True for an https URL on registry.npmjs.org with plain path characters and no dot segment."""
    if not isinstance(url, str) or not URL_RE.fullmatch(url):
        return False
    path = url[len(REGISTRY):]
    return all(seg not in ("", ".", "..") for seg in path.split("/"))


def load_plan(path: str) -> list[dict]:
    """Read and validate the plan. Raises ValueError on any malformed row."""
    with open(path, "rb") as fh:
        raw = fh.read(4 * 1024 * 1024 + 1)
    if len(raw) > 4 * 1024 * 1024:
        raise ValueError("plan too large")
    data = json.loads(raw)
    reqs = data.get("requests") if isinstance(data, dict) else None
    if not isinstance(reqs, list) or len(reqs) > MAX_REQUESTS:
        raise ValueError(f"requests must be a list of at most {MAX_REQUESTS} rows")
    seen: set[str] = set()
    out: list[dict] = []
    for row in reqs:
        if not isinstance(row, dict):
            raise ValueError("request row is not an object")  # noqa: TRY004 - one error type for a bad plan
        rid, kind, max_bytes = row.get("id"), row.get("kind"), row.get("max_bytes")
        if not isinstance(rid, str) or not ID_RE.fullmatch(rid) or rid in seen:
            raise ValueError("bad request id")
        if kind not in ACCEPT:
            raise ValueError("bad request kind")
        if not isinstance(max_bytes, int) or not 0 < max_bytes <= MAX_BYTES_PER_REQUEST:
            raise ValueError("bad max_bytes")
        seen.add(rid)
        out.append({"id": rid, "url": row.get("url"), "kind": kind, "max_bytes": max_bytes})
    return out


def fetch_one(opener: urllib.request.OpenerDirector, req: dict, out_dir: str, deadline: float,
              budget: list[int]) -> dict:
    """GET one URL into out_dir/<id>.bin with size caps. Returns the manifest row."""
    row = {"id": req["id"], "status": "network", "bytes": 0, "http_status": None}
    if not valid_url(req["url"]):
        row["status"] = "refused_url"
        return row
    remaining = deadline - time.monotonic()
    if remaining <= 1:
        return row
    request = urllib.request.Request(req["url"], headers={
        "Accept": ACCEPT[req["kind"]], "User-Agent": "soken-npm-fetch/1"})
    cap = min(req["max_bytes"], budget[0])
    path = os.path.join(out_dir, req["id"] + ".bin")
    try:
        with opener.open(request, timeout=min(REQUEST_TIMEOUT_S, remaining)) as resp:
            row["http_status"] = resp.status
            length = resp.headers.get("Content-Length")
            if length is not None and length.isdigit() and int(length) > cap:
                row["status"] = "too_large"
                return row
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
            total = 0
            with os.fdopen(fd, "wb") as fh:
                while True:
                    if time.monotonic() > deadline:
                        raise TimeoutError("wall")
                    chunk = resp.read(CHUNK)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > cap:
                        row["status"] = "too_large"
                        break
                    fh.write(chunk)
            if row["status"] == "too_large":
                os.unlink(path)
                return row
            budget[0] -= total
            row.update(status="ok", bytes=total)
            return row
    except urllib.error.HTTPError as exc:
        row["http_status"] = exc.code
        row["status"] = "not_found" if exc.code == 404 else "http_error"
    except (urllib.error.URLError, OSError, TimeoutError, ValueError):
        row["status"] = "network"
    if os.path.lexists(path):
        os.unlink(path)
    return row


def run(plan_path: str, out_dir: str, wall_s: float) -> tuple[int, dict]:
    try:
        reqs = load_plan(plan_path)
    except (OSError, ValueError) as exc:
        return EXIT_INVALID, {"error": f"invalid plan: {type(exc).__name__}", "results": []}
    deadline = time.monotonic() + max(5.0, min(wall_s, WALL_S))
    # ProxyHandler() reads HTTPS_PROXY from the environment: the family smokescreen (09 4.3).
    opener = urllib.request.build_opener(urllib.request.ProxyHandler(), _NoRedirect())
    budget = [MAX_BYTES_TOTAL]
    results = [fetch_one(opener, r, out_dir, deadline, budget) for r in reqs]
    code = EXIT_OK
    if results and all(r["status"] == "network" for r in results):
        code = EXIT_TRANSIENT
    return code, {"results": results}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="soken-npm-fetch")
    p.add_argument("--plan", default="/work/in/plan.json")
    p.add_argument("--out", default="/work/out")
    p.add_argument("--wall", type=float, default=WALL_S)
    args = p.parse_args(argv)
    try:
        code, manifest = run(args.plan, args.out, args.wall)
    except Exception as exc:  # noqa: BLE001 - one internal row instead of a traceback on stdout
        code, manifest = EXIT_INTERNAL, {"error": type(exc).__name__, "results": []}
    manifest["exit"] = code
    with open(os.path.join(args.out, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh)
    ok = sum(1 for r in manifest.get("results", []) if r.get("status") == "ok")
    print(json.dumps({"exit": code, "ok": ok, "requests": len(manifest.get("results", []))}),
          file=sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main())
