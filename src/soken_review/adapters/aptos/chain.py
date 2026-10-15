"""Aptos `chain_state` (plan v4 07 sections 4 and 7.1): supervisor-only, read-only REST reads.

Reads at one pinned ledger version: the account `0x1::code::PackageRegistry` (sources, manifest,
deps, `upgrade_policy`, `upgrade_number`), the account's module bytecode (U-07), dependency
registries to depth 6 (7.1.4) and the publisher kind (7.1.6, U-06).

`source` and `manifest` are hex of gzip (U-05, confirmed live 2026-10-10 on PancakeSwap and 0x1).
"""

from __future__ import annotations

import gzip
import zlib
from typing import Any

from soken_review.adapters.move import net
from soken_review.adapters.move.units import IDENT_RE, normalize_address

MAX_DEP_DEPTH = 6                       # 07 7.1.4
FRAMEWORK_ACCOUNTS = {normalize_address(a) for a in ("0x1", "0x3", "0x4")}
# Framework packages come from the image (07 7.1.4), at /opt/aptos-framework/<dir> (docker/aptos-build).
FRAMEWORK_PACKAGES = {
    "MoveStdlib": "move-stdlib", "AptosStdlib": "aptos-stdlib", "AptosFramework": "aptos-framework",
    "AptosToken": "aptos-token", "AptosTokenObjects": "aptos-token-objects",
}
POLICY = {0: "arbitrary", 1: "compatible", 2: "immutable"}   # code.move upgrade_policy_*
_MAX_SOURCE = 4 * 1024 * 1024


class PackageUnreadable(net.ChainReadError):
    """A registry package (or its source) cannot be read or decoded."""


def _gunzip_hex(value: str) -> str | None:
    """Decode the registry `0x<hex of gzip>` encoding; '' or '0x' is None (published without source)."""
    if not isinstance(value, str) or value in ("", "0x"):
        return None
    try:
        raw = bytes.fromhex(value.removeprefix("0x"))
        dec = zlib.decompressobj(16 + zlib.MAX_WBITS)
        out = dec.decompress(raw, _MAX_SOURCE + 1)
        if len(out) > _MAX_SOURCE or not dec.eof:
            raise PackageUnreadable("source over size cap or truncated")
        return out.decode("utf-8")
    except (ValueError, zlib.error, gzip.BadGzipFile, UnicodeDecodeError) as exc:
        raise PackageUnreadable(f"source not gzip hex: {exc}") from exc


def ledger_version() -> int:
    info = net.get_json(net.APTOS_REST)
    try:
        return int(info["ledger_version"])
    except (KeyError, TypeError, ValueError) as exc:
        raise net.ChainReadError("ledger info without ledger_version") from exc


def _registry(address: str, ledger: int) -> list[dict[str, Any]]:
    url = f"{net.APTOS_REST}/accounts/{address}/resource/0x1::code::PackageRegistry?ledger_version={ledger}"
    try:
        res = net.get_json(url)
    except net.NotFound:
        return []
    packages = (res.get("data") or {}).get("packages") if isinstance(res, dict) else None
    if not isinstance(packages, list):
        raise net.ChainReadError("PackageRegistry without packages")
    return packages


def decode_package(raw: dict[str, Any], account: str) -> dict[str, Any]:
    """Registry `PackageMetadata` -> plain dict with decoded manifest and sources."""
    name = raw.get("name")
    if not isinstance(name, str) or not IDENT_RE.match(name.replace("-", "_")):
        raise PackageUnreadable(f"bad package name {name!r}")
    policy_raw = (raw.get("upgrade_policy") or {}).get("policy")
    try:
        policy = int(policy_raw)
    except (TypeError, ValueError) as exc:
        raise PackageUnreadable("bad upgrade_policy") from exc
    modules = []
    for m in raw.get("modules") or []:
        mname = m.get("name")
        if not isinstance(mname, str) or not IDENT_RE.match(mname):
            raise PackageUnreadable(f"bad module name {mname!r}")
        modules.append({"name": mname, "source": _gunzip_hex(m.get("source", ""))})
    deps = []
    for d in raw.get("deps") or []:
        acct = normalize_address(str(d.get("account", "")))
        dname = d.get("package_name")
        if acct is None or not isinstance(dname, str) or not IDENT_RE.match(dname.replace("-", "_")):
            raise PackageUnreadable("bad dependency entry")
        deps.append({"account": acct, "package_name": dname})
    return {
        "account": account,
        "name": name,
        "upgrade_policy": policy,
        "upgrade_policy_name": POLICY.get(policy, "unknown"),
        "upgrade_number": int(raw.get("upgrade_number") or 0),
        "source_digest": str(raw.get("source_digest") or ""),
        "manifest": _gunzip_hex(raw.get("manifest", "")),
        "modules": modules,
        "deps": deps,
    }


def _modules_bytecode(address: str, ledger: int) -> dict[str, str]:
    """name -> bytecode hex for every module at the account (U-07, bulk endpoint).

    One page of up to 1000 modules; the REST cursor is a response header, so a fuller account
    is refused rather than read partially."""
    page = net.get_json(f"{net.APTOS_REST}/accounts/{address}/modules?ledger_version={ledger}&limit=1000")
    if not isinstance(page, list):
        raise net.ChainReadError("modules page is not a list")
    if len(page) >= 1000:
        raise net.ChainReadError("module listing too long for the bulk endpoint")
    out: dict[str, str] = {}
    for item in page:
        abi = item.get("abi") or {}
        name, code = abi.get("name"), item.get("bytecode")
        if isinstance(name, str) and isinstance(code, str) and code.startswith("0x"):
            out[name] = code
    return out


def _resource(address: str, type_tag: str, ledger: int) -> dict[str, Any] | None:
    try:
        res = net.get_json(f"{net.APTOS_REST}/accounts/{address}/resource/{type_tag}?ledger_version={ledger}")
    except net.NotFound:
        return None
    return res if isinstance(res, dict) else None


def publisher_kind(address: str, ledger: int) -> str:
    """object | multisig | resource_account | plain | unknown (07 7.1.6, U-06).

    One resource read per kind (an account listing can be very large)."""
    if _resource(address, "0x1::object::ObjectCore", ledger) is not None:
        return "object"
    if _resource(address, "0x1::multisig_account::MultisigAccount", ledger) is not None:
        return "multisig"
    account = _resource(address, "0x1::account::Account", ledger)
    if account is None:
        return "unknown"
    auth = str((account.get("data") or {}).get("authentication_key", ""))
    # create_resource_account rotates the authentication key to ZERO_AUTH_KEY (account.move).
    if auth and set(auth.removeprefix("0x")) == {"0"}:
        return "resource_account"
    return "plain" if auth else "unknown"


def read_chain_state(address: str, ledger: int | None = None) -> dict[str, Any]:
    """chain_state for an Aptos account at a pinned ledger version (07 4, 7.1)."""
    addr = normalize_address(address)
    if addr is None:
        raise net.ChainReadError("bad address")
    ledger = ledger if ledger is not None else ledger_version()
    packages = [decode_package(p, addr) for p in _registry(addr, ledger)]
    bytecode = _modules_bytecode(addr, ledger) if packages else {}
    deps: dict[str, dict[str, Any]] = {}
    unreachable: list[str] = []
    frontier = [(d["account"], d["package_name"], 1) for p in packages for d in p["deps"]]
    cache: dict[str, list[dict[str, Any]]] = {addr: packages}
    while frontier:
        acct, name, depth = frontier.pop(0)
        key = f"{acct}/{name}"
        if key in deps or (acct in FRAMEWORK_ACCOUNTS and name in FRAMEWORK_PACKAGES):
            continue
        if depth > MAX_DEP_DEPTH:
            unreachable.append(key)
            continue
        if acct not in cache:
            try:
                cache[acct] = [decode_package(p, acct) for p in _registry(acct, ledger)]
            except PackageUnreadable:
                cache[acct] = []
        found = next((p for p in cache[acct] if p["name"] == name), None)
        if found is None or found["manifest"] is None or any(m["source"] is None for m in found["modules"]):
            unreachable.append(key)
            continue
        deps[key] = found
        frontier += [(d["account"], d["package_name"], depth + 1) for d in found["deps"]]
    # On-chain bytecode of every non-framework dependency account at the same ledger version:
    # the facts layer links these, never the rebuilt dependency modules (07 10: closed over
    # linked bytecode that is the deployed one).
    # Framework accounts (FRAMEWORK_ACCOUNTS: 0x1, 0x3, 0x4) are excluded because their
    # bytecode is already in the build image at /opt/aptos-framework/ and storing it in
    # chain_state.json would push the file over the supervisor 1-MiB read cap.
    dep_accounts = {d["account"] for p in packages for d in p["deps"]}
    dep_accounts |= {d["account"] for dep in deps.values() for d in dep["deps"]}
    dep_accounts.discard(addr)
    dep_accounts -= FRAMEWORK_ACCOUNTS
    dep_bytecode = {acct: _modules_bytecode(acct, ledger) for acct in sorted(dep_accounts)}
    return {
        "chain": "aptos",
        "address": addr,
        "ledger_version": ledger,
        "packages": packages,
        "module_bytecode": bytecode,
        "deps": deps,
        "deps_unreachable": sorted(set(unreachable)),
        "dep_module_bytecode": dep_bytecode,
        "publisher_kind": publisher_kind(addr, ledger),
    }
