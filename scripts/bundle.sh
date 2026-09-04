#!/bin/sh
# Build an XP handoff directory. F4 may name an f4 checkout with the shim import.
# Paths may be relative, absolute, or contain spaces; source checkouts stay untouched.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
mkdir -p "${1:-bundle-xp}"
out=$(CDPATH= cd -- "${1:-bundle-xp}" && pwd)
if [ -n "${F4:-}" ]; then F4=$(CDPATH= cd -- "$F4" && pwd); fi
cd "$root"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
prof="$root/profiles/xp.json"
go build -o "$tmp/go2xp" ./cmd/go2xp
build_patch() {
    name=$1
    shift
    GOOS=windows GOARCH=386 CGO_ENABLED=0 go build -trimpath -ldflags=-w -o "$out/$name.exe" "$@"
    "$tmp/go2xp" patch -profile "$prof" "$out/$name.exe" "$out/$name-xp.exe" >"$out/$name-patch.txt"
    "$tmp/go2xp" verify -profile "$prof" "$out/$name-xp.exe"
    "$tmp/go2xp" audit -profile "$prof" "$out/$name-xp.exe" >"$out/$name-audit.txt"
}
for dir in probes/*/; do
    build_patch "$(basename "$dir")" "./$dir"
done
build_patch go2xp ./cmd/go2xp
if [ -n "${F4:-}" ]; then
    f4=$(CDPATH= cd -- "$F4" && pwd)
    # Reuse f4's pinned dependencies, replacing only go2xp with this exact source.
    cp "$f4/go.mod" "$tmp/f4.mod"
    cp "$f4/go.sum" "$tmp/f4.sum"
    go mod edit -modfile="$tmp/f4.mod" -require=github.com/unxed/go2xp@v0.0.0 -replace="github.com/unxed/go2xp=$root"
    (cd "$f4" && build_patch f4 -modfile="$tmp/f4.mod" -tags=go2xp ./cmd/f4)
fi
mkdir -p "$out/profiles"
cp "$prof" profiles/kernel32-exports.tsv "$out/profiles/"
cp docs/xp-test-plan.md docs/reference-review.md "$out/"
cp scripts/test-xp.cmd "$out/test-xp.cmd"
# A manifest identifies the source and toolchain without claiming XP execution.
{
    go version
    git rev-parse HEAD
    git status --short
    if [ -n "${F4:-}" ]; then git -C "$F4" rev-parse HEAD; git -C "$F4" status --short; fi
} > "$out/build-info.txt"
(cd "$out" && sha256sum ./*.exe > SHA256SUMS)
printf 'XP bundle: %s\n' "$out"
