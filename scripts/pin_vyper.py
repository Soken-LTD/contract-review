#!/usr/bin/env python3
"""Pin Vyper compiler releases and Vyper security advisories (05 sections 6.1, 6.2, 15).

    uv run python scripts/pin_vyper.py [--download=0.2.4,0.3.10,...]

Writes src/soken_review/adapters/vyper/data/:
  vyper_releases.json    every non-pre-release with a linux asset: url, sha256 and its source.
                         sha256 comes from the GitHub release asset `digest` when GitHub has one;
                         otherwise only for versions in --download, by downloading the asset once
                         (trust on first use, labelled `first_download`). A release with no sha256
                         is never run: the build reads it as compiler_binary_missing.
  vyper_advisories.json  published GHSA advisories of vyperlang/vyper (id, severity, ranges).

Read-only public GitHub API calls; GITHUB_TOKEN is used when set (rate limit).
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import sys
from pathlib import Path

import httpx

_API = "https://api.github.com/repos/vyperlang/vyper"
_DATA = Path(__file__).parents[1] / "src" / "soken_review" / "adapters" / "vyper" / "data"


def _get(client: httpx.Client, url: str) -> list | dict:
    r = client.get(url, timeout=60)
    r.raise_for_status()
    return r.json()


def main() -> int:
    download = set()
    for arg in sys.argv[1:]:
        if arg.startswith("--download="):
            download = {v.strip() for v in arg.split("=", 1)[1].split(",") if v.strip()}
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "soken-review"}
    if os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    today = dt.datetime.now(dt.UTC).date().isoformat()
    old = {}
    if (_DATA / "vyper_releases.json").exists():
        old = {r["version"]: r for r in json.loads((_DATA / "vyper_releases.json").read_text())["releases"]}

    rows = []
    with httpx.Client(headers=headers, follow_redirects=True) as client:
        releases = _get(client, f"{_API}/releases?per_page=100")
        for rel in releases:
            if rel.get("prerelease") or rel.get("draft"):
                continue
            asset = next((a for a in rel.get("assets", []) if a["name"].endswith(".linux")), None)
            if asset is None:
                continue
            version = rel["tag_name"].removeprefix("v")
            long_version = asset["name"].removeprefix("vyper.").removesuffix(".linux")
            row = {
                "version": version,
                "long_version": long_version,
                "asset": asset["name"],
                "url": asset["browser_download_url"],
                "sha256": None,
                "sha256_source": None,
            }
            digest = asset.get("digest") or ""
            if digest.startswith("sha256:"):
                row["sha256"], row["sha256_source"] = digest.removeprefix("sha256:"), "github_asset_digest"
            elif old.get(version, {}).get("sha256"):
                row["sha256"], row["sha256_source"] = old[version]["sha256"], old[version]["sha256_source"]
            elif version in download:
                data = client.get(asset["browser_download_url"], timeout=300).content
                row["sha256"], row["sha256_source"] = hashlib.sha256(data).hexdigest(), f"first_download {today}"
            rows.append(row)
            print(f"{version:10} {row['sha256_source'] or 'not pinned'}")

        advisories = []
        for adv in _get(client, f"{_API}/security-advisories?per_page=100&state=published"):
            advisories.append({
                "ghsa_id": adv["ghsa_id"],
                "severity": adv.get("severity"),
                "published_at": (adv.get("published_at") or "")[:10],
                "summary": adv.get("summary"),
                "url": adv.get("html_url"),
                "ranges": [
                    {"vulnerable": v.get("vulnerable_version_range"), "patched": v.get("patched_versions")}
                    for v in adv.get("vulnerabilities") or []
                ],
            })

    _DATA.mkdir(parents=True, exist_ok=True)
    (_DATA / "vyper_releases.json").write_text(json.dumps({
        "_note": "Vyper compiler releases (05 6.1, 15). sha256 null = not pinned: never run. Refresh: scripts/pin_vyper.py",
        "source_url": f"{_API}/releases",
        "checked_at": today,
        "releases": rows,
    }, indent=2) + "\n")
    (_DATA / "vyper_advisories.json").write_text(json.dumps({
        "_note": "Published vyperlang/vyper security advisories (05 6.2, F30). Reference data. Refresh: scripts/pin_vyper.py",
        "source_url": f"{_API}/security-advisories",
        "checked_at": today,
        "advisories": sorted(advisories, key=lambda a: a["ghsa_id"]),
    }, indent=2) + "\n")
    print(f"{len(rows)} releases, {sum(1 for r in rows if r['sha256'])} pinned; {len(advisories)} advisories")
    return 0


if __name__ == "__main__":
    sys.exit(main())
