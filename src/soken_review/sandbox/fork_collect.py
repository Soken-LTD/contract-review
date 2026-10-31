"""Runs inside the fork container (python3 -I, standard library only, mounted read-only): runs forge,
then reads from forge's output directory on the container tmpfs only the artifacts of the pinned
source files the finding cites, and prints one JSON object on stdout:

    {"forge": "<forge --json stdout>", "forge_exit": 0, "artifacts": [{path, contract, code, ranges}], "dropped": n}

Nothing is written outside the size-limited tmpfs, so a test cannot fill the host disk through the
build output. Caps: forge stdout, artifact file size, artifact count and total code bytes; build-info
and every symlink are skipped. The supervisor re-validates everything it reads back.

    python3 -I fork_collect.py --out /tmp/forge-out --cited '["src/Vault.sol"]' -- forge test ...
"""

import json
import os
import stat
import subprocess
import sys

STDOUT_CAP = 6 * 1024 * 1024
FILE_CAP = 4 * 1024 * 1024
MAX_FILES = 16
TOTAL_CAP = 32 * 1024 * 1024
MAX_SCANNED = 4000


def collect(out_dir, cited):
    wanted = {"pinned/" + c for c in cited}
    arts, total, dropped, scanned = [], 0, 0, 0
    if not wanted:
        return arts, dropped
    for root, dirs, files in os.walk(out_dir, followlinks=False):
        dirs[:] = [d for d in dirs if d != "build-info" and not os.path.islink(os.path.join(root, d))]
        for name in sorted(files):
            scanned += 1
            if scanned > MAX_SCANNED:
                return arts, dropped + 1
            if not name.endswith(".json"):
                continue
            path = os.path.join(root, name)
            try:
                st = os.lstat(path)
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode) or st.st_size > FILE_CAP:
                dropped += 1
                continue
            try:
                with open(path, "rb") as fh:
                    doc = json.loads(fh.read(FILE_CAP + 1))
            except (OSError, ValueError):
                continue
            meta = doc.get("metadata") if isinstance(doc, dict) else None
            target = ((meta or {}).get("settings") or {}).get("compilationTarget") if isinstance(meta, dict) else None
            dep = doc.get("deployedBytecode") if isinstance(doc, dict) else None
            if not isinstance(target, dict) or len(target) != 1 or not isinstance(dep, dict):
                continue
            (src, contract), = target.items()
            if src not in wanted:
                continue
            code = str(dep.get("object") or "")
            if len(arts) >= MAX_FILES or total + len(code) > TOTAL_CAP:
                dropped += 1
                continue
            ranges = [[int(x.get("start", 0)), int(x.get("length", 0))]
                      for refs in (dep.get("immutableReferences") or {}).values() for x in refs if isinstance(x, dict)]
            arts.append({"path": src[len("pinned/"):], "contract": str(contract)[:80], "code": code, "ranges": ranges[:256]})
            total += len(code)
    return arts, dropped


def main(argv):
    i = argv.index("--")
    opts, cmd = argv[1:i], argv[i + 1:]
    out_dir = opts[opts.index("--out") + 1]
    cited = json.loads(opts[opts.index("--cited") + 1])
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    buf, over = bytearray(), False
    while True:
        chunk = proc.stdout.read(65536)
        if not chunk:
            break
        if len(buf) + len(chunk) > STDOUT_CAP:
            over = True
            proc.kill()
            break
        buf += chunk
    rc = proc.wait()
    arts, dropped = ([], 0) if over else collect(out_dir, [c for c in cited if isinstance(c, str)][:20])
    sys.stdout.write(json.dumps({"forge": "" if over else buf.decode("utf-8", "replace"), "forge_exit": rc,
                                 "output_cap": over, "artifacts": arts, "dropped": dropped}))
    sys.stdout.flush()
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
