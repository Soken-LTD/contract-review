"""05 13.1 / 13.2 masked runtime comparison (adapters/evm/compare.py)."""

from __future__ import annotations

from soken_review.adapters.evm.compare import auxdata_mask, cbor_trailer, compare_runtime, enclosing_cbor


def auxdata(hash_byte: int, solc: bytes = b"\x00\x08\x17") -> bytes:
    """solc auxdata: {ipfs: 34 bytes, solc: 3 bytes} + 2-byte length (51)."""
    m = b"\xa2\x64ipfs\x58\x22\x12\x20" + bytes([hash_byte]) * 32 + b"\x64solc\x43" + solc
    return m + len(m).to_bytes(2, "big")


CODE = bytes(range(1, 101))  # 100 bytes of "code", no zero bytes
IMM = {"7": [{"start": 10, "length": 32}]}


def local_runtime(child: bytes = b"") -> bytes:
    code = bytearray(CODE)
    code[10:42] = b"\x00" * 32
    return bytes(code) + child + auxdata(0xAA)


def onchain_runtime(child: bytes = b"", hash_byte: int = 0xAA, imm: bytes = b"\x11" * 32) -> bytes:
    code = bytearray(CODE)
    code[10:42] = imm
    return bytes(code) + child + auxdata(hash_byte)


def x2_for(local: bytes) -> list[tuple[int, int]]:
    start = local.rfind(b"\x12\x20") + 2
    return [(start, start + 32)]


class TestCompare:
    def test_immutables_masked_exact(self) -> None:
        loc = local_runtime()
        cmp = compare_runtime(loc.hex(), "0x" + onchain_runtime().hex(), immutable_refs=IMM, x2_ranges=x2_for(loc))
        assert cmp.outcome == "exact"
        assert cmp.immutable_ranges == [(10, 42)]

    def test_without_immutable_mask_differs(self) -> None:
        loc = local_runtime()
        cmp = compare_runtime(loc.hex(), onchain_runtime().hex(), immutable_refs={}, x2_ranges=x2_for(loc))
        assert cmp.outcome == "differs"
        assert cmp.differing == [(10, 42)]

    def test_metadata_hash_differs_is_metadata_only(self) -> None:
        loc = local_runtime()
        cmp = compare_runtime(loc.hex(), onchain_runtime(hash_byte=0xBB).hex(), immutable_refs=IMM,
                              x2_ranges=x2_for(loc))
        assert cmp.outcome == "metadata_only"
        assert cmp.auxdata_source == "x2"
        assert cmp.auxdata_ranges == [(100, len(loc))]  # whole CBOR map + length

    def test_x2_range_missing_an_equal_byte_is_widened(self) -> None:
        """A hash byte equal in both local compiles is not in the X2 diff; widening covers it."""
        loc = local_runtime()
        start, end = x2_for(loc)[0]
        cmp = compare_runtime(loc.hex(), onchain_runtime(hash_byte=0xBB).hex(), immutable_refs=IMM,
                              x2_ranges=[(start + 1, end - 1)])
        assert cmp.outcome == "metadata_only"

    def test_factory_child_auxdata_masked(self) -> None:
        child_local = b"\x60\x80" + auxdata(0xC1) + b"\x60\x80"
        child_chain = b"\x60\x80" + auxdata(0xC2) + b"\x60\x80"
        loc = local_runtime(child_local)
        cs = 100 + 2 + len(b"\xa2\x64ipfs\x58\x22\x12\x20")
        ranges = [(cs, cs + 32)] + x2_for(loc)
        cmp = compare_runtime(loc.hex(), onchain_runtime(child_chain, hash_byte=0xBB).hex(),
                              immutable_refs=IMM, x2_ranges=ranges)
        assert cmp.outcome == "metadata_only"
        assert len(cmp.auxdata_ranges) == 2

    def test_tampered_byte_outside_masks_differs(self) -> None:
        loc = local_runtime()
        bad = bytearray(onchain_runtime(hash_byte=0xBB))
        bad[60] ^= 1
        cmp = compare_runtime(loc.hex(), bytes(bad).hex(), immutable_refs=IMM, x2_ranges=x2_for(loc))
        assert cmp.outcome == "differs"
        assert cmp.differing == [(60, 61)]

    def test_tampered_byte_in_auxdata_is_metadata_only_not_exact(self) -> None:
        loc = local_runtime()
        cmp = compare_runtime(loc.hex(), onchain_runtime(hash_byte=0xAB).hex(), immutable_refs=IMM,
                              x2_ranges=x2_for(loc))
        assert cmp.outcome == "metadata_only"

    def test_length_differs(self) -> None:
        loc = local_runtime()
        cmp = compare_runtime(loc.hex(), (onchain_runtime() + b"\x00").hex(), immutable_refs=IMM,
                              x2_ranges=x2_for(loc))
        assert cmp.outcome == "differs"
        assert cmp.detail == "length differs"

    def test_immutable_ref_over_nonzero_local_bytes_is_invalid(self) -> None:
        loc = local_runtime()
        cmp = compare_runtime(loc.hex(), onchain_runtime().hex(),
                              immutable_refs={"1": [{"start": 50, "length": 32}]}, x2_ranges=x2_for(loc))
        assert cmp.outcome == "invalid_refs"

    def test_immutable_ref_wrong_length_is_invalid(self) -> None:
        """A reference that is not one 32-byte slot could mask arbitrary code."""
        loc = local_runtime()
        cmp = compare_runtime(loc.hex(), onchain_runtime().hex(),
                              immutable_refs={"1": [{"start": 10, "length": 90}]}, x2_ranges=x2_for(loc))
        assert cmp.outcome == "invalid_refs"

    def test_link_placeholder_masked(self) -> None:
        loc = bytearray(local_runtime())
        hex_local = loc.hex()
        placeholder = "__$" + "a" * 34 + "$__"
        hex_local = hex_local[:2 * 60] + placeholder + hex_local[2 * 80:]
        chain = bytearray(onchain_runtime())
        chain[60:80] = b"\x42" * 20
        links = {"L.sol": {"L": [{"start": 60, "length": 20}]}}
        cmp = compare_runtime(hex_local, bytes(chain).hex(), immutable_refs=IMM, link_refs=links,
                              x2_ranges=x2_for(bytes(loc)))
        assert cmp.outcome == "exact"
        assert cmp.link_ranges == [(60, 80)]

    def test_library_self_address_masked(self) -> None:
        loc = b"\x73" + b"\x00" * 20 + b"\x30\x14" + CODE + auxdata(0xAA)
        chain = b"\x73" + b"\x99" * 20 + b"\x30\x14" + CODE + auxdata(0xAA)
        cmp = compare_runtime(loc.hex(), chain.hex(), immutable_refs={}, x2_ranges=x2_for(loc),
                              self_address="0x" + "99" * 20)
        assert cmp.outcome == "exact"

    def test_no_auxdata_rule_x3(self) -> None:
        loc = CODE
        cmp = compare_runtime(loc.hex(), CODE.hex(), immutable_refs={}, no_auxdata=True)
        assert cmp.outcome == "exact"
        assert cmp.auxdata_source == "none"


class TestAuxdataRanges:
    def test_trailer_parsed(self) -> None:
        loc = local_runtime()
        assert cbor_trailer(loc) == (100, len(loc))
        assert cbor_trailer(CODE) is None

    def test_no_x2_falls_back_to_trailer(self) -> None:
        loc = local_runtime()
        assert auxdata_mask(loc, None) == ([(100, len(loc))], [], "trailer")
        assert auxdata_mask(CODE, None) == ([], [], "unknown")

    def test_x2_ran_with_no_difference_uses_trailer(self) -> None:
        loc = local_runtime()
        assert auxdata_mask(loc, []) == ([(100, len(loc))], [], "x2")

    def test_x2_out_of_bounds_is_unknown(self) -> None:
        assert auxdata_mask(CODE, [(90, 500)]) == ([], [], "unknown")

    def test_enclosing_cbor_needs_length_suffix(self) -> None:
        block = auxdata(0xAA)
        code = CODE + block[:-2] + b"\x00\x00"
        assert enclosing_cbor(code, 110, 140) is None
        assert enclosing_cbor(CODE + block, 110, 140) == (100, 100 + len(block))
