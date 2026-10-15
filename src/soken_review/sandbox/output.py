"""Read files a sandbox container wrote, without following anything it planted (09 3.5).

The container owns its output dir, so every name in it is untrusted: the dir itself, any subdir
and any file may be a symlink to a host path, a FIFO or a device. `read_output_files` opens the
dir with O_NOFOLLOW|O_DIRECTORY, walks it with `os.scandir` on dir fds (never following links),
rejects every symlink at any level, opens files relative to the dir fd with O_NOFOLLOW|O_NONBLOCK,
and keeps only regular files (fstat) under the size cap.
"""

from __future__ import annotations

import fnmatch
import os
import stat
from pathlib import Path

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
MAX_DEPTH = 8


class UnsafeOutput(ValueError):
    """The output tree holds a symlink, a non-regular file, or exceeds a cap."""


def read_output_files(directory: Path, pattern: str, max_files: int, max_bytes: int) -> dict[str, bytes]:
    """{relative path: bytes} for regular files whose name matches `pattern` (fnmatch).

    Raises UnsafeOutput on any symlink, special file, oversize file or too many matches;
    FileNotFoundError when `directory` is missing.
    """
    try:
        root = os.open(directory, _DIR_FLAGS)
    except OSError as exc:
        if isinstance(exc, FileNotFoundError):
            raise
        raise UnsafeOutput(f"{directory.name}: not a plain directory") from exc
    out: dict[str, bytes] = {}
    try:
        _walk(root, "", pattern, max_files, max_bytes, out, 0)
    finally:
        os.close(root)
    return out


def _walk(dfd: int, prefix: str, pattern: str, max_files: int, max_bytes: int,
          out: dict[str, bytes], depth: int) -> None:
    if depth > MAX_DEPTH:
        raise UnsafeOutput("output tree too deep")
    with os.scandir(dfd) as it:
        entries = sorted(it, key=lambda e: e.name)
    for e in entries:
        rel = f"{prefix}{e.name}"
        if e.is_symlink():
            raise UnsafeOutput(f"{rel}: symlink in sandbox output")
        if e.is_dir(follow_symlinks=False):
            sub = os.open(e.name, _DIR_FLAGS, dir_fd=dfd)
            try:
                _walk(sub, rel + "/", pattern, max_files, max_bytes, out, depth + 1)
            finally:
                os.close(sub)
            continue
        if not e.is_file(follow_symlinks=False):
            raise UnsafeOutput(f"{rel}: not a regular file")
        if not fnmatch.fnmatch(e.name, pattern):
            continue
        if len(out) >= max_files:
            raise UnsafeOutput("too many output files")
        fd = os.open(e.name, _FILE_FLAGS, dir_fd=dfd)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise UnsafeOutput(f"{rel}: not a regular file")
            if st.st_size > max_bytes:
                raise UnsafeOutput(f"{rel}: {st.st_size} bytes over the cap")
            with os.fdopen(fd, "rb", closefd=False) as fh:
                data = fh.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise UnsafeOutput(f"{rel}: over the cap")
            out[rel] = data
        finally:
            os.close(fd)
