"""Security review 2026-10-10: masks must not reach code (05 13.1, 13.2).

Each test is a crafted runtime that the first version of compare.py accepted as a match.
"""

from __future__ import annotations

from soken_review.adapters.evm.compare import cbor_trailer, compare_runtime, enclosing_cbor
from tests.adapters.evm.test_compare import CODE, IMM, auxdata, local_runtime, onchain_runtime, x2_for


def test_fake_cbor_block_in_code_is_not_widened() -> None:
    """A source can place bytes that parse as a CBOR map with a length suffix around a value that
    varies between compiles; widening to that "block" would mask 64 bytes of code."""
    inner = bytes(range(101, 165))  # 64 bytes of "code"
    fake = b"\xa1\x61x\x58\x40" + inner
    fake += len(fake).to_bytes(2, "big")
    loc = CODE[:20] + fake + CODE[20:] + auxdata(0xAA)
    start = 20 + 5 + 10
    x2 = [(start, start + 4)] + x2_for(loc)
    chain = bytearray(loc)
    chain[20 + 5:20 + 5 + 64] = b"\x5b" * 64  # rewrite the "code" inside the fake block
    cmp = compare_runtime(loc.hex(), bytes(chain).hex(), immutable_refs={}, x2_ranges=x2)
    assert cmp.outcome == "differs"
    assert cmp.auxdata_source == "x2_partial"


def test_loose_x2_range_in_code_is_not_masked() -> None:
    """X2 bytes outside any metadata block (e.g. a folded keccak of child creationCode) are
    code-reachable constants; masking them would let any value through."""
    loc = local_runtime()
    chain = bytearray(onchain_runtime())
    chain[50:54] = b"\xde\xad\xbe\xef"
    cmp = compare_runtime(loc.hex(), bytes(chain).hex(), immutable_refs=IMM,
                          x2_ranges=[(50, 54)] + x2_for(loc))
    assert cmp.outcome == "differs"
    assert cmp.auxdata_source == "x2_partial"


def test_onchain_auxdata_must_parse_as_metadata() -> None:
    loc = local_runtime()
    chain = bytearray(onchain_runtime())
    chain[100:] = b"\x5b" * (len(chain) - 100)  # same length, not metadata
    cmp = compare_runtime(loc.hex(), bytes(chain).hex(), immutable_refs=IMM, x2_ranges=x2_for(loc))
    assert cmp.outcome == "differs"


def test_onchain_auxdata_must_have_same_structure() -> None:
    """Same span, but `solc` as a 3-char text instead of 3 bytes: not the block we compiled."""
    loc = local_runtime()
    chain = bytearray(onchain_runtime(hash_byte=0xBB))
    pos = len(chain) - 2 - 4  # the `solc` value head (0x43 + 3 bytes)
    assert chain[pos] == 0x43
    chain[pos] = 0x63
    chain[pos + 1:pos + 4] = b"0.8"
    cmp = compare_runtime(loc.hex(), bytes(chain).hex(), immutable_refs=IMM, x2_ranges=x2_for(loc))
    assert cmp.outcome == "differs"


def test_unknown_metadata_key_is_not_a_block() -> None:
    m = b"\xa1\x64evil\x58\x22" + b"\x12\x20" + b"\xaa" * 32
    block = m + len(m).to_bytes(2, "big")
    assert enclosing_cbor(CODE + block, 110, 140) is None
    assert cbor_trailer(CODE + block) is None


def test_known_metadata_shapes_parse() -> None:
    for m in (b"\xa1\x65bzzr0\x58\x20" + b"\x01" * 32,
              b"\xa2\x64tron\x58\x22\x12\x20" + b"\x01" * 32 + b"\x64solc\x43\x00\x08\x17",
              b"\xa1\x64solc\x43\x00\x07\x06",
              b"\xa3\x64ipfs\x58\x22\x12\x20" + b"\x01" * 32 + b"\x6cexperimental\xf5\x64solc\x43\x00\x08\x17"):
        assert cbor_trailer(CODE + m + len(m).to_bytes(2, "big")) is not None, m


def test_one_immutable_has_one_value() -> None:
    """All references of one immutable carry the same on-chain word; code where they differ
    cannot come from this source."""
    code = bytearray(CODE)
    code[10:42] = b"\x00" * 32
    code[50:82] = b"\x00" * 32
    loc = bytes(code) + auxdata(0xAA)
    chain = bytearray(loc)
    chain[10:42] = b"\x11" * 32
    chain[50:82] = b"\x22" * 32
    refs = {"7": [{"start": 10, "length": 32}, {"start": 50, "length": 32}]}
    cmp = compare_runtime(loc.hex(), bytes(chain).hex(), immutable_refs=refs, x2_ranges=x2_for(loc))
    assert cmp.outcome == "differs"
    chain[50:82] = b"\x11" * 32
    cmp = compare_runtime(loc.hex(), bytes(chain).hex(), immutable_refs=refs, x2_ranges=x2_for(loc))
    assert cmp.outcome == "exact"


def test_link_reference_must_be_a_placeholder() -> None:
    loc = local_runtime()
    chain = bytearray(onchain_runtime())
    chain[60:80] = b"\x42" * 20
    links = {"L.sol": {"L": [{"start": 60, "length": 20}]}}
    cmp = compare_runtime(loc.hex(), bytes(chain).hex(), immutable_refs=IMM, link_refs=links,
                          x2_ranges=x2_for(loc))
    assert cmp.outcome == "invalid_refs"


def test_library_self_address_needs_address_eq() -> None:
    loc = b"\x73" + b"\x00" * 20 + b"\x01\x02" + CODE + auxdata(0xAA)
    chain = b"\x73" + b"\x99" * 20 + b"\x01\x02" + CODE + auxdata(0xAA)
    cmp = compare_runtime(loc.hex(), chain.hex(), immutable_refs={}, x2_ranges=x2_for(loc))
    assert cmp.outcome == "differs"


def test_masked_bytes_reported() -> None:
    loc = local_runtime()
    cmp = compare_runtime(loc.hex(), onchain_runtime(hash_byte=0xBB).hex(), immutable_refs=IMM,
                          x2_ranges=x2_for(loc))
    assert cmp.as_dict()["masked_bytes"] == {"immutables": 32, "links": 0, "auxdata": len(loc) - 100}
