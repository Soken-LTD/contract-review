#!/usr/bin/env python3
"""Rewrite the relay CIDR file the daily quota reads (soken_review.quota, SOKEN_RELAY_CIDRS_FILE).

Relays are AI products whose servers call MCP servers for their users from shared, rotating
egress IPs, so the quota keys their traffic by reviewed target instead of by IP:
  - Anthropic (claude.ai custom connectors): 160.79.104.0/21, fixed (SOKEN_RELAY_CIDRS default).
  - OpenAI (ChatGPT connectors and apps): https://openai.com/chatgpt-connectors.json, which
    OpenAI says changes and should be fetched regularly.
On any fetch or parse error the old file is kept (exit 1), so a bad day never empties the list.

Usage: refresh_relay_cidrs.py /etc/soken/relay-cidrs.txt   (soken-relay-cidrs.timer, daily)
"""

from __future__ import annotations

import ipaddress
import json
import os
import sys
import tempfile
import urllib.request
from datetime import UTC, datetime

SOURCES = {"openai": "https://openai.com/chatgpt-connectors.json"}
STATIC = {"anthropic": ["160.79.104.0/21"]}
MIN_OPENAI = 20   # a list this short is a broken response, not a real shrink


def fetch_openai(url: str) -> list[str]:
    req = urllib.request.Request(url, headers={"User-Agent": "soken-relay-cidrs/1"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        doc = json.loads(resp.read(2_000_000))
    out = []
    for item in doc.get("prefixes", []):
        for key in ("ipv4Prefix", "ipv6Prefix"):
            if key in item:
                out.append(str(ipaddress.ip_network(item[key], strict=False)))
    return out


def main(path: str) -> int:
    try:
        openai = fetch_openai(SOURCES["openai"])
    except Exception as exc:  # noqa: BLE001 - any failure keeps the old file
        print(f"openai fetch failed, keeping {path}: {exc}", file=sys.stderr)
        return 1
    if len(openai) < MIN_OPENAI:
        print(f"openai list has {len(openai)} prefixes, keeping {path}", file=sys.stderr)
        return 1
    lines = [f"# written {datetime.now(UTC).isoformat(timespec='seconds')} by refresh_relay_cidrs.py"]
    for name, nets in (("anthropic", STATIC["anthropic"]), ("openai", openai)):
        lines.append(f"# {name}: {len(nets)}")
        lines.extend(sorted(set(nets)))
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or ".", prefix=".relay-cidrs-")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)
    print(f"wrote {path}: anthropic {len(STATIC['anthropic'])}, openai {len(openai)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "/etc/soken/relay-cidrs.txt"))
