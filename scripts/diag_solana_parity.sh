#!/usr/bin/env bash
# U-S1 diagnosis only (solana-e2e mode=reference): which difference between `solana-verify build` and our
# sandbox build changes the program hash. Not part of the adapter path; never used for a decision.
#   diag_solana_parity.sh <repo_dir> <library_name> <upstream_image> <derived_image> <subset_dir>
set -uo pipefail
repo=$1 lib=$2 up=$3 derived=$4 subset=$5
manifest="$(cd "$repo" && grep -rl --include=Cargo.toml -E "^name = \"($lib|${lib//_/-})\"" . | sort | head -n1)"
mdir="$(dirname "${manifest#./}")"
echo "manifest: $manifest"
sv=(--config 'registries.crates-io.protocol="sparse"' --locked --manifest-path "/build/$mdir/Cargo.toml")
ours=("${sv[@]}" --config 'build.rustc-wrapper=""' --config 'build.rustc-workspace-wrapper=""' --offline -v)

hash_of() { local f="$1/target/deploy/$lib.so"; [ -f "$f" ] && python3 -c "import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],'rb').read().rstrip(b'\0')).hexdigest())" "$f" || echo none; }
fresh() { rm -rf "$1"; cp -a "$2" "$1"; rm -rf "$1/target"; }
tc() { docker run --rm --entrypoint rustup "$1" show active-toolchain | cut -d' ' -f1; }

w=$(mktemp -d)
T_UP=$(tc "$up")
# 1 upstream image, root, full tree rw, solana-verify command
fresh "$w/a" "$repo"
docker run --rm -v "$w/a:/build" -w "/build/$mdir" -e RUSTUP_TOOLCHAIN="$T_UP" "$up" cargo build-sbf -- "${sv[@]}" > "$w/a.log" 2>&1
echo "CASE1 upstream-root-full-sv $(hash_of "$w/a")"
# 2 upstream image, root, full tree, fetch then our flags (offline, -v, wrapper configs)
fresh "$w/b" "$repo"
docker run --rm -v "$w/b:/build" -w "/build/$mdir" -e RUSTUP_TOOLCHAIN="$T_UP" --entrypoint bash "$up" -c \
  "cargo fetch --locked --manifest-path /build/$mdir/Cargo.toml && cargo build-sbf -- $(printf '%q ' "${ours[@]}")" > "$w/b.log" 2>&1
echo "CASE2 upstream-root-full-ourflags $(hash_of "$w/b")"
# 3 upstream image, root, walker subset tree, solana-verify command
fresh "$w/c" "$subset"
docker run --rm -v "$w/c:/build" -w "/build/$mdir" -e RUSTUP_TOOLCHAIN="$T_UP" "$up" cargo build-sbf -- "${sv[@]}" > "$w/c.log" 2>&1
echo "CASE3 upstream-root-subset-sv $(hash_of "$w/c")"
# 4 derived image, root, full tree, solana-verify command
fresh "$w/d" "$repo"
docker run --rm --user 0 -e HOME=/root -v "$w/d:/build" -w "/build/$mdir" -e RUSTUP_TOOLCHAIN="$T_UP" "$derived" cargo build-sbf -- "${sv[@]}" > "$w/d.log" 2>&1
echo "CASE4 derived-root-full-sv $(hash_of "$w/d")"
# 5 derived image, uid 10001, empty CARGO_HOME mount, full tree rw, solana-verify command (online)
fresh "$w/e" "$repo"; mkdir -p "$w/ch"; chmod 777 "$w/ch" "$w/e"; chmod -R a+rwX "$w/e"
docker run --rm --user 10001:10001 -e HOME=/root -e CARGO_HOME=/usr/local/cargo -v "$w/ch:/usr/local/cargo" \
  -v "$w/e:/build" -w "/build/$mdir" -e RUSTUP_TOOLCHAIN="$T_UP" "$derived" cargo build-sbf -- "${sv[@]}" > "$w/e.log" 2>&1
echo "CASE5 derived-10001-chmount-full-sv $(hash_of "$w/e")"
for c in a b c d e; do echo "== $c"; grep -E "error|warning: unused|Finished" "$w/$c.log" | tail -3; done
grep -m3 -oE "Running \`rustc --crate-name $lib [^\`]{0,600}" "$w/b.log" || true
