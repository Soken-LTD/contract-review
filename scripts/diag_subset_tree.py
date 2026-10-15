"""U-S1 diagnosis only: write the tree our build sees (walker subset, blocked files dropped).

    uv run python scripts/diag_subset_tree.py <checkout> <out_dir>
"""

import sys
from pathlib import Path

from soken_review.adapters.solana.build import _write_source_tree
from soken_review.adapters.solana.fetch import _walk_source_files

files = _walk_source_files(Path(sys.argv[1]))
out = Path(sys.argv[2])
out.mkdir(parents=True, exist_ok=True)
print("skipped:", _write_source_tree(files, out), "unread:", files.unread_paths[:5])
