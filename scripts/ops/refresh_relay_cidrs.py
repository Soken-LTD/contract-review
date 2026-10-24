#!/usr/bin/env python3
"""Rewrite the relay CIDR file the daily quota reads (soken_review.quota, SOKEN_RELAY_CIDRS_FILE).

Relays are AI products whose servers call MCP servers for their users from shared, rotating
egress IPs, so the quota keys their traffic by reviewed target (with one daily cap per provider)
instead of by IP. Sources are the providers' own published lists:
  - anthropic   claude.ai connectors: 160.79.104.0/21 (fixed, also the SOKEN_RELAY_CIDRS default)
  - openai      ChatGPT connectors and apps: https://openai.com/chatgpt-connectors.json
  - microsoft   Copilot Studio: Azure service tags PowerPlatformInfra, PowerPlatformPlex and
                AzureConnectors (Microsoft Learn, "Use IP firewalls ... Copilot Studio"), from the
                weekly ServiceTags_Public JSON
  - google      Gemini: Google user-triggered fetchers and Google-owned ranges (goog.json minus
                cloud.json, so Google Cloud customers' machines are not counted as a relay)
  - perplexity  https://www.perplexity.com/perplexity-user.json
A provider whose source fails, or returns implausibly few prefixes, keeps its section from the
previous file; the run exits 1 so the failure shows in the timer status.

Usage: refresh_relay_cidrs.py /etc/soken/relay-cidrs.txt   (soken-relay-cidrs.timer, daily)
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import sys
import tempfile
import urllib.request
from collections.abc import Callable
from datetime import UTC, datetime

UA = {"User-Agent": "Mozilla/5.0 (compatible; soken-relay-cidrs/1)"}
AZURE_PAGE = "https://www.microsoft.com/en-us/download/details.aspx?id=56519"
AZURE_TAGS = ("PowerPlatformInfra", "PowerPlatformPlex", "AzureConnectors")


def _get(url: str, limit: int = 60_000_000) -> bytes:
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=60) as resp:
        return resp.read(limit)


def _prefixes(doc: dict) -> list[str]:
    out = []
    for item in doc.get("prefixes", []):
        for key in ("ipv4Prefix", "ipv6Prefix"):
            if key in item:
                out.append(str(ipaddress.ip_network(item[key], strict=False)))
    return out


def anthropic() -> list[str]:
    return ["160.79.104.0/21"]


def openai() -> list[str]:
    return _prefixes(json.loads(_get("https://openai.com/chatgpt-connectors.json")))


def perplexity() -> list[str]:
    return _prefixes(json.loads(_get("https://www.perplexity.com/perplexity-user.json")))


def google() -> list[str]:
    base = "https://developers.google.com/static/search/apis/ipranges/"
    nets = set()
    for name in ("user-triggered-fetchers-google.json", "user-triggered-fetchers.json"):
        nets.update(_prefixes(json.loads(_get(base + name))))
    goog = {ipaddress.ip_network(n) for n in _prefixes(json.loads(_get("https://www.gstatic.com/ipranges/goog.json")))}
    cloud = [ipaddress.ip_network(n) for n in _prefixes(json.loads(_get("https://www.gstatic.com/ipranges/cloud.json")))]
    for net in goog:
        rest = [net]
        for c in cloud:
            if c.version != net.version:
                continue
            nxt = []
            for r in rest:
                if c.subnet_of(r):
                    nxt.extend(r.address_exclude(c))
                elif r.subnet_of(c):
                    continue
                else:
                    nxt.append(r)
            rest = nxt
        nets.update(str(r) for r in rest)
    return sorted(nets)


def microsoft() -> list[str]:
    page = _get(AZURE_PAGE, 5_000_000).decode("utf-8", "replace")
    m = re.search(r"https://download\.microsoft\.com/[^\"'\\\s]*ServiceTags_Public[^\"'\\\s]*\.json", page)
    if not m:
        raise RuntimeError("service tags download link not found")
    doc = json.loads(_get(m.group(0)))
    out = []
    for value in doc.get("values", []):
        if value.get("name") in AZURE_TAGS:
            out.extend(str(ipaddress.ip_network(p, strict=False)) for p in value["properties"]["addressPrefixes"])
    return out


SOURCES: dict[str, tuple[Callable[[], list[str]], int]] = {
    # provider: (fetch, minimum plausible prefix count)
    "anthropic": (anthropic, 1),
    "openai": (openai, 20),
    "microsoft": (microsoft, 200),
    "google": (google, 50),
    "perplexity": (perplexity, 1),
}
_HEADER = re.compile(r"^#\s*([a-z0-9_-]+)\s*:")


def _previous(path: str) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {}
    current = None
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                m = _HEADER.match(line.strip())
                if m:
                    current = m.group(1)
                    sections.setdefault(current, [])
                elif current and line.strip() and not line.startswith("#"):
                    sections[current].append(line.strip())
    except OSError:
        pass
    return sections


def main(path: str) -> int:
    old = _previous(path)
    failed = []
    sections: dict[str, list[str]] = {}
    for provider, (fetch, minimum) in SOURCES.items():
        try:
            nets = sorted(set(fetch()))
            if len(nets) < minimum:
                raise RuntimeError(f"{len(nets)} prefixes, expected at least {minimum}")
            sections[provider] = nets
        except Exception as exc:  # noqa: BLE001 - any failure keeps that provider's old list
            failed.append(provider)
            print(f"{provider}: {exc}; keeping {len(old.get(provider, []))} old prefixes", file=sys.stderr)
            if old.get(provider):
                sections[provider] = old[provider]
    lines = [f"# written {datetime.now(UTC).isoformat(timespec='seconds')} by refresh_relay_cidrs.py"]
    for provider, nets in sections.items():
        lines.append(f"# {provider}: {len(nets)}")
        lines.extend(nets)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or ".", prefix=".relay-cidrs-")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)
    print(f"wrote {path}: " + ", ".join(f"{p} {len(n)}" for p, n in sections.items()))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "/etc/soken/relay-cidrs.txt"))
