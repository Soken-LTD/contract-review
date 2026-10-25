"""Local CIDv0 recomputation for TON registry sources (content from any gateway is bound to its CID)."""

from __future__ import annotations

import json
from pathlib import Path

from soken_review.adapters.ton.fetch import cid_matches, cidv0_of_file

FIX = Path(__file__).resolve().parents[2] / "fixtures" / "ton"


def test_known_ipfs_vectors():
    # `ipfs add` of an empty file and of "hello\n" (well-known values).
    assert cidv0_of_file(b"") == "QmbFMke1KXqnYyBBWxB74N4c5SBnJMVAiMNRcGu6x1AwQH"
    assert cidv0_of_file(b"hello\n") == "QmZULkCELmmk5XNfCgTnCyFgAVxBRBXyDHGGMVoLFLiXEN"


def test_real_registry_manifest_matches_its_cid():
    # Saved byte-for-byte from an IPFS gateway for QmdCXc6... (the pretty-printed .json fixture is not).
    raw = (FIX / "registry_ipfs_manifest.raw").read_bytes()
    manifest = json.loads(raw)
    assert isinstance(manifest, dict)
    assert cid_matches("QmdCXc6dyEJnjepkoydT4a15JJttKatLhSrR7dPqaZkAwo", raw)


def test_tampered_content_or_unsupported_cid_is_rejected():
    raw = b"contract X {}"
    good = cidv0_of_file(raw)
    assert cid_matches(good, raw)
    assert not cid_matches(good, raw + b" ")
    assert not cid_matches("bafkreigh2akiscaildc7example", raw)      # CIDv1: not checkable
    assert not cid_matches(good, b"x" * (256 * 1024 + 1))           # multi-block: not checkable
