"""Method policy of the chain proxy (chain access design 2026-10-27, section 3.3).

Default deny. Every request that leaves the server for a chain provider passes `check_*` first;
a method or path outside the read allowlist raises `ProxyDenied` (JSON-RPC code -32601), so no
send or broadcast method can be reached, whatever the caller asks for. Batches are unpacked and
every element is checked. Block tags are bounded by `max_block` when one is set (a read can never
see state after the block it is pinned to, and never the mempool).

Pure: no I/O. The deny lists below are not used to decide (the allowlist decides); they name the
families the tests fire at the proxy so a future allowlist edit cannot let one through unnoticed.
"""

from __future__ import annotations

import re
from typing import Any

DENIED_CODE = -32601

# ── EVM (also HyperEVM and the TRON /jsonrpc read set) ────────────────────
EVM_ALLOWED = frozenset({
    "eth_chainId", "net_version", "eth_blockNumber", "eth_getBlockByNumber", "eth_getBlockByHash",
    "eth_getBalance", "eth_getCode", "eth_getStorageAt", "eth_getTransactionCount", "eth_call",
    "eth_estimateGas", "eth_getProof", "eth_getTransactionByHash", "eth_getTransactionReceipt",
    "eth_getLogs", "eth_feeHistory", "eth_gasPrice",
})
# Index of the block tag argument per method, for the block bound.
_EVM_BLOCK_ARG = {
    "eth_getBalance": 1, "eth_getCode": 1, "eth_getTransactionCount": 1, "eth_call": 1,
    "eth_estimateGas": 1, "eth_getStorageAt": 2, "eth_getProof": 2, "eth_getBlockByNumber": 0,
}
EVM_DENIED_EXAMPLES = (
    "eth_sendRawTransaction", "eth_sendTransaction", "eth_sendBundle", "eth_sendPrivateTransaction",
    "eth_sendRawTransactionConditional", "eth_sign", "eth_signTransaction", "eth_signTypedData_v4",
    "personal_sign", "personal_sendTransaction", "personal_unlockAccount", "wallet_sendCalls",
    "admin_addPeer", "miner_start", "txpool_content", "eth_subscribe", "eth_newPendingTransactionFilter",
    "anvil_setBalance", "hardhat_impersonateAccount", "evm_mine", "debug_setHead", "engine_newPayloadV3",
)
MAX_LOG_RANGE = 50_000
MAX_BATCH = 50

# ── TRON native HTTP API ───────────────────────────────────────────────────
TRON_ALLOWED_POST = frozenset({
    "/wallet/triggerconstantcontract", "/wallet/getcontract", "/wallet/getcontractinfo", "/wallet/getaccount",
    "/wallet/getnowblock", "/wallet/getblockbynum", "/wallet/getaccountresource",
})
TRON_ALLOWED_GET = (re.compile(r"^/wallet/getnowblock$"), re.compile(r"^/wallet/getchainparameters$"),
                    re.compile(r"^/v1/accounts/[1-9A-HJ-NP-Za-km-z]{34}(/[a-z0-9_/-]{0,40})?$"),
                    re.compile(r"^/v1/contracts/[1-9A-HJ-NP-Za-km-z]{34}(/[a-z0-9_/-]{0,40})?$"))
TRON_DENIED_EXAMPLES = (
    "/wallet/broadcasttransaction", "/wallet/broadcasthex", "/wallet/createtransaction",
    "/wallet/triggersmartcontract", "/wallet/deploycontract", "/wallet/freezebalancev2",
    "/wallet/easytransferbyprivate", "/wallet/gettransactionsign", "/walletsolidity/broadcasttransaction",
)

# ── Solana JSON-RPC ────────────────────────────────────────────────────────
SOLANA_ALLOWED = frozenset({
    "getAccountInfo", "getMultipleAccounts", "getSlot", "getBlockHeight", "getBlockTime", "getBalance",
    "getTokenLargestAccounts", "getTokenAccountsByOwner", "getTokenAccountBalance", "getTokenSupply",
    "getSignaturesForAddress", "getTransaction", "getGenesisHash",
})
SOLANA_DENIED_EXAMPLES = ("sendTransaction", "requestAirdrop", "simulateTransaction", "sendBundle")

# ── TON (toncenter v2 HTTP and its jsonRPC endpoint) ──────────────────────
TON_ALLOWED = frozenset({
    "runGetMethod", "runGetMethodStd", "getAddressInformation", "getExtendedAddressInformation",
    "getMasterchainInfo", "getAddressBalance", "getAddressState", "getTransactions", "getBlockHeader",
})
TON_DENIED_EXAMPLES = ("sendBoc", "sendBocReturnHash", "sendQuery", "sendQuerySimple", "estimateFee",
                       "sendBocReturnHashNoError")


class ProxyDenied(Exception):
    """The request is outside the read allowlist; nothing was sent upstream."""

    def __init__(self, family: str, method: str, why: str = "not on the read allowlist") -> None:
        super().__init__(f"{family} {method[:80]}: {why}")
        self.family = family
        self.method = method[:80]
        self.why = why
        self.code = DENIED_CODE

    def rpc_error(self, req_id: Any = None) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": self.code, "message": str(self)}}


def _block_value(tag: Any) -> int | str | None:
    """An int for a numeric tag, the tag word for latest/pending/earliest/safe/finalized, else None."""
    if isinstance(tag, dict):   # EIP-1898 {"blockNumber": ...} or {"blockHash": ...}
        if "blockNumber" in tag:
            return _block_value(tag["blockNumber"])
        return "hash" if "blockHash" in tag else None
    if isinstance(tag, int) and not isinstance(tag, bool):
        return tag
    if isinstance(tag, str):
        if re.fullmatch(r"0x[0-9a-fA-F]{1,16}", tag):
            return int(tag, 16)
        if tag in ("latest", "pending", "earliest", "safe", "finalized"):
            return tag
    return None


def _bound(method: str, tag: Any, max_block: int | None) -> None:
    if max_block is None:
        return
    value = _block_value(tag)
    if value in ("latest", "pending", "safe", "finalized", "hash") or value is None:
        raise ProxyDenied("evm", method, f"block tag {str(tag)[:20]!r} is not a block at or before {max_block}")
    if isinstance(value, int) and value > max_block:
        raise ProxyDenied("evm", method, f"block {value} is after the pinned block {max_block}")


def check_evm(method: Any, params: Any, *, max_block: int | None = None) -> None:
    """Raise ProxyDenied unless (method, params) is an allowed read."""
    if not isinstance(method, str) or method not in EVM_ALLOWED:
        raise ProxyDenied("evm", str(method))
    if params is None:
        params = []
    if not isinstance(params, list):
        raise ProxyDenied("evm", method, "params must be a list")
    if method == "eth_getLogs":
        flt = params[0] if params and isinstance(params[0], dict) else None
        if flt is None or not flt.get("address"):
            raise ProxyDenied("evm", method, "a log filter needs an address")
        if "blockHash" not in flt:
            lo, hi = _block_value(flt.get("fromBlock", "latest")), _block_value(flt.get("toBlock", "latest"))
            if not isinstance(lo, int) or not isinstance(hi, int):
                raise ProxyDenied("evm", method, "fromBlock and toBlock must be numbers")
            if hi < lo or hi - lo > MAX_LOG_RANGE:
                raise ProxyDenied("evm", method, f"log range over {MAX_LOG_RANGE} blocks")
            if max_block is not None and hi > max_block:
                raise ProxyDenied("evm", method, f"block {hi} is after the pinned block {max_block}")
        return
    idx = _EVM_BLOCK_ARG.get(method)
    if idx is not None:
        _bound(method, params[idx] if len(params) > idx else "latest", max_block)


def check_evm_payload(payload: Any, *, max_block: int | None = None) -> None:
    """A JSON-RPC request object or batch; every element is checked (a batch of one send fails whole)."""
    items = payload if isinstance(payload, list) else [payload]
    if not items or len(items) > MAX_BATCH:
        raise ProxyDenied("evm", "batch", f"a batch holds 1 to {MAX_BATCH} requests")
    for item in items:
        if not isinstance(item, dict):
            raise ProxyDenied("evm", "batch", "a request must be an object")
        check_evm(item.get("method"), item.get("params"), max_block=max_block)


def check_tron(path: str, http_method: str = "POST", body: Any = None) -> None:
    norm = "/" + path.strip().lstrip("/").split("?", 1)[0].rstrip("/").lower() if path else ""
    if norm == "/jsonrpc":
        check_evm_payload(body)
        return
    if http_method.upper() == "POST" and norm in TRON_ALLOWED_POST:
        return
    if http_method.upper() == "GET" and any(rx.match("/" + path.strip().lstrip("/").split("?", 1)[0])
                                           for rx in TRON_ALLOWED_GET):
        return
    raise ProxyDenied("tron", path)


def check_solana(method: Any, params: Any = None) -> None:
    if not isinstance(method, str) or method not in SOLANA_ALLOWED:
        raise ProxyDenied("solana", str(method))
    del params   # no Solana read here takes a block bound (no historical slots in JSON-RPC)


def check_solana_payload(payload: Any) -> None:
    items = payload if isinstance(payload, list) else [payload]
    if not items or len(items) > MAX_BATCH:
        raise ProxyDenied("solana", "batch", f"a batch holds 1 to {MAX_BATCH} requests")
    for item in items:
        if not isinstance(item, dict):
            raise ProxyDenied("solana", "batch", "a request must be an object")
        check_solana(item.get("method"), item.get("params"))


def check_ton(method: str, body: Any = None) -> None:
    """`method` is the toncenter v2 path segment (`runGetMethodStd`) or `jsonRPC`, whose body names
    the method; a jsonRPC body is checked like a direct call."""
    if method == "jsonRPC":
        inner = body.get("method") if isinstance(body, dict) else None
        if not isinstance(inner, str) or inner == "jsonRPC":
            raise ProxyDenied("ton", "jsonRPC", "the body must name one allowed method")
        check_ton(inner)
        return
    if method not in TON_ALLOWED:
        raise ProxyDenied("ton", method)


# ── Sourcify (deployment record of a verified contract; GET only, fixed path) ──
SOURCIFY_DEPLOYMENT = re.compile(r"^/server/v2/contract/\d{1,12}/0x[0-9a-fA-F]{40}\?fields=deployment$")


def check_sourcify(path: str, http_method: str = "GET") -> None:
    if http_method.upper() != "GET" or not SOURCIFY_DEPLOYMENT.match(path):
        raise ProxyDenied("sourcify", path)
