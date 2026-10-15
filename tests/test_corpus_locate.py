from soken_review.evals import locate

SRC = """pragma solidity 0.8.20;
contract V {
  function _burn(address o, uint256 s) internal {
    tw.burn(o, uint96(s));
    _update();
  }
}
"""

PATCH = """diff --git a/src/V.sol b/src/V.sol
--- a/src/V.sol
+++ b/src/V.sol
@@ -3,4 +3,4 @@ contract V {
   function _burn(address o, uint256 s) internal {
-    tw.burn(o, uint96(s));
+    tw.burn(o, s.toUint96());
     _update();
   }
"""


def _tree(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "V.sol").write_text(SRC)
    (tmp_path / "test").mkdir()
    (tmp_path / "test" / "V.t.sol").write_text(SRC)
    return tmp_path


def test_patch_removed_lines_verified(tmp_path):
    spans = locate.from_patch(PATCH, _tree(tmp_path))
    assert [(s.file, s.start, s.end) for s in spans] == [("src/V.sol", 4, 4)]


def test_patch_line_text_mismatch_dropped(tmp_path):
    tree = _tree(tmp_path)
    (tree / "src" / "V.sol").write_text(SRC.replace("uint96(s)", "uint128(s)"))
    assert locate.from_patch(PATCH, tree) == []


def test_marker_unique_in_scope_only(tmp_path):
    tree = _tree(tmp_path)
    text = "```solidity\n@>    tw.burn(o, uint96(s));\n```\n"
    spans = locate.from_markers(text, tree, locate.source_files(tree))
    assert [(s.file, s.start) for s in spans] == [("src/V.sol", 4)]


def test_link_located_by_block_text(tmp_path, monkeypatch):
    tree = _tree(tmp_path)
    linked = "x\n" * 10 + "    tw.burn(o, uint96(s));\n    _update();\n"
    monkeypatch.setattr(locate.RawCache, "get", lambda self, r, s, p: linked)
    text = "see https://github.com/acme/vault/blob/" + "a" * 40 + "/contracts/V.sol#L11-L12"
    spans = locate.from_links(text, tree, locate.source_files(tree), locate.RawCache(tmp_path / "c"))
    assert [(s.file, s.start, s.end) for s in spans] == [("src/V.sol", 4, 5)]


def test_merge_adjacent():
    spans = [locate.Span("a.sol", 4, 4, "patch"), locate.Span("a.sol", 5, 6, "link"), locate.Span("a.sol", 20, 20, "x")]
    assert locate.merge(spans) == [{"file": "a.sol", "start": 4, "end": 6}, {"file": "a.sol", "start": 20, "end": 20}]
