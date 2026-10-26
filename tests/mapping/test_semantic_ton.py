"""Parsed TON map (mapping/semantic_ton.py): spans and semantic layer without a compiler AST.

Matrix run 2026-10-25 (Forton, Tact 1.6.5 missing from the image): the map had 0 spans and no
semantic layer, so challenge scopes were lexical, coverage was empty and `map.admin_recovery`
could not run. The parse below is checked on small Tact, FunC and Tolk sources.
"""

from __future__ import annotations

from soken_review.mapping.build import build_map
from soken_review.mapping.step import family_categories

TACT = """import "@stdlib/ownable";

trait Fees {
    fee: Int;

    fun takeFee(v: Int): Int {
        self.fee += v / 100;
        return v - v / 100;
    }
}

contract Master with Ownable, Fees {
    owner: Address;
    price: Int as coins = ton("1.0");
    fee: Int = 0;
    users: map<Int, Address>;

    init() {
        self.owner = sender();
    }

    receive(msg: SetPrice) {
        self.requireOwner();
        self.price = msg.price;
        self.reply("ok".asComment());
    }

    receive(msg: Drain) {
        self.drain(msg.to);
    }

    receive(msg: Register) {
        self.onlyMaster();
        self.users.set(msg.id, msg.who);
    }

    receive("withdraw") {
        nativeThrowUnless(132, sender() == self.owner);
        nativeReserve(ton("0.01"), 0);
        send(SendParameters{ to: self.owner, value: 0, mode: SendRemainingBalance });
    }

    bounced(msg: bounced<Drain>) {
        self.price = 0;
    }

    fun drain(to: Address) {
        send(SendParameters{ to: to, value: 0, mode: SendRemainingBalance | SendIgnoreErrors });
    }

    fun onlyMaster() {
        require(sender() == self.owner, "only master");
    }

    get fun price(): Int {
        return self.price;
    }
}

contract Other {
    fun onlyMaster() {
        let x: Int = 1;
    }

    receive(msg: Register) {
        self.onlyMaster();
    }
}
"""

FUNC = """#include "stdlib.fc";

global int counter;

(int, slice) load_data() inline {
    var ds = get_data().begin_parse();
    return (ds~load_uint(64), ds~load_msg_addr());
}

() recv_internal(int my_balance, int msg_value, cell in_msg_full, slice in_msg_body) impure {
    slice cs = in_msg_full.begin_parse();
    slice sender_address = cs~load_msg_addr();
    (int total, slice owner) = load_data();
    throw_unless(401, equal_slices(sender_address, owner));
    send_raw_message(begin_cell().end_cell(), 64);
    set_data(begin_cell().store_uint(total + 1, 64).end_cell());
}

int get_total() method_id {
    (int total, _) = load_data();
    return total;
}
"""

TOLK = """tolk 0.12

fun onInternalMessage(myBalance: int, msgValue: int, msgFull: cell, msgBody: slice) {
    var cs = msgFull.beginParse();
    assert (cs.loadAddress() == getOwner()) throw 401;
    setContractData(beginCell().endCell());
}

get fun owner(): slice {
    return getOwner();
}

fun getOwner(): slice {
    return getContractData().beginParse();
}
"""


def _map(files: dict[str, str], build_ok: bool) -> tuple[dict, str]:
    art = build_map(files, None, list(family_categories("ton", "ton")), build_ok=build_ok)
    return art.doc, art.status


def _fn(doc: dict, span: str) -> dict:
    return next(f for f in doc["semantic"]["functions"] if f["span"] == span)


def test_tact_units_handlers_and_spans() -> None:
    doc, status = _map({"c/master.tact": TACT}, build_ok=False)
    assert status == "partial"                        # parsed without a build: never `failed`, never `full`
    sem = doc["semantic"]
    assert [u["name"] for u in sem["units"]] == ["Master", "Other"]   # traits are not units
    spans = {s["id"]: s for s in doc["spans"]}
    assert spans["Master.receive(SetPrice)"]["kind"] == "handler"
    assert spans["Master.receive(SetPrice)"]["unit"] == "c/master.tact:Master"
    assert spans["Master.receive(text_withdraw)"]["start"] == 37
    assert "Master.bounced(Drain)" in spans
    assert "Master.price()" in spans and "Master.init()" in spans
    assert "Fees.takeFee(Int)" in spans
    entries = {f["span"] for f in sem["functions"] if f["is_entry"]}
    assert "Master.receive(SetPrice)" in entries and "Master.bounced(Drain)" in entries
    assert "Master.price()" not in entries and "Master.init()" not in entries
    names = {v["name"] for v in sem["state_vars"] if v["unit"] == "c/master.tact:Master"}
    assert names == {"owner", "price", "fee", "users"}


def test_tact_guards_writes_sends_and_internal_edges() -> None:
    doc, _ = _map({"c/master.tact": TACT}, build_ok=True)
    set_price = _fn(doc, "Master.receive(SetPrice)")
    assert set_price["guards"] == [{"class": "caller_check", "line": "c/master.tact:23"}]
    assert {"var": "price", "line": "c/master.tact:24"} in set_price["writes"]
    assert any(c["kind"] == "message" and c["target"] == "reply" for c in set_price["calls"])
    # guard through an internal function is listed with the line where it executes
    register = _fn(doc, "Master.receive(Register)")
    assert {"class": "caller_check", "line": "c/master.tact:52"} in register["guards"]
    assert {"var": "users", "line": "c/master.tact:34"} in register["writes"]
    # a same-named helper in another contract never lends its (absent) guard or takes this one
    assert _fn(doc, "Other.receive(Register)")["guards"] == []
    drain = _fn(doc, "Master.receive(Drain)")
    assert {"kind": "internal", "target": "drain", "line": "c/master.tact:29"} in drain["calls"]
    cats = doc["semantic"]["category_to_functions"]
    assert "Master.receive(Drain)" in cats["ton.send_mode_drain"]           # reached through drain()
    assert "Master.receive(Drain)" in cats["ton.unrecoverable_send"]
    assert "Master.receive(text_withdraw)" in cats["ton.send_mode_reserve"]
    assert "Master.bounced(Drain)" in cats["ton.bounce_body"]
    assert "Master.receive(Register)" in cats["ton.gas_storage"]            # map write
    roles = {r["name"]: r["gated_functions"] for r in doc["semantic"]["roles"]}
    assert "Master.receive(SetPrice)" in roles["owner"]
    assert "Master.receive(text_withdraw)" in roles["owner"]
    bases = doc["semantic"]["chain_extras"]["ton"]["units"]["c/master.tact:Master"]["bases"]
    assert bases == ["Master", "Ownable", "Fees"]


def test_tact_status_full_only_with_build() -> None:
    _, status = _map({"c/master.tact": TACT}, build_ok=True)
    assert status == "full"
    _, status = _map({"c/master.tact": TACT.rsplit("}", 1)[0]}, build_ok=True)   # unbalanced
    assert status == "partial"


def test_func_entry_guard_send_and_storage() -> None:
    doc, _ = _map({"src/wallet.fc": FUNC}, build_ok=True)
    sem = doc["semantic"]
    assert [u["name"] for u in sem["units"]] == ["wallet"]
    recv = _fn(doc, "wallet.recv_internal(int,int,cell,slice)")
    assert recv["is_entry"]
    assert recv["guards"] == [{"class": "caller_check", "line": "src/wallet.fc:14"}]
    assert {"kind": "message", "target": "send_raw_message", "line": "src/wallet.fc:15",
            "value_bearing": True} in recv["calls"]
    assert {"var": "storage", "line": "src/wallet.fc:16"} in recv["writes"]
    assert {"kind": "internal", "target": "load_data", "line": "src/wallet.fc:13"} in recv["calls"]
    getter = _fn(doc, "wallet.get_total()")
    assert getter["visibility"] == "get" and not getter["is_entry"]
    assert "wallet.recv_internal(int,int,cell,slice)" in sem["category_to_functions"]["ton.excess_return"]
    assert {v["name"] for v in sem["state_vars"]} == {"counter"}


def test_tolk_entry_and_getter() -> None:
    doc, _ = _map({"src/main.tolk": TOLK}, build_ok=False)
    entry = _fn(doc, "main.onInternalMessage(int,int,cell,slice)")
    assert entry["is_entry"]
    assert {"var": "storage", "line": "src/main.tolk:6"} in entry["writes"]
    assert _fn(doc, "main.owner()")["visibility"] == "get"


def test_receiver_text_never_enters_the_map_as_free_text() -> None:
    src = 'contract C {\n    receive("drain all; now!") {\n    }\n}\n'
    doc, _ = _map({"c.tact": src}, build_ok=True)
    ids = [s["id"] for s in doc["spans"]]
    assert len(ids) == 1 and ids[0].startswith("C.receive(text_id_")
    assert "drain" not in ids[0]


def test_solidity_maps_unchanged() -> None:
    art = build_map({"A.sol": "contract A { function f() public {} }\n"}, None,
                    list(family_categories("evm", None)), build_ok=False)
    assert art.status == "failed" and "semantic" not in art.doc
