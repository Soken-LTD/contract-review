"""Pinning subpackage: immutable source store and quote-match (04 sections 5.1 and 5.2)."""

from .quote_match import QuoteMatchError, normalize_line, normalize_lines, quote_match
from .store import FileEntry, PinnedSource

__all__ = [
    "FileEntry",
    "PinnedSource",
    "QuoteMatchError",
    "normalize_line",
    "normalize_lines",
    "quote_match",
]
