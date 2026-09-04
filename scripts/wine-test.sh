#!/bin/sh
# Native Wine runs validate ABI and control flow, not the XP export set or kernel.
set -eu
PROFILE=${1:-profiles/xp.json}
WINVER=${2:-winxp}
export WINEDEBUG=${WINEDEBUG:--all}
command -v wine >/dev/null
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT HUP INT TERM
WINEPREFIX=${WINEPREFIX:-$out/prefix}
export WINEPREFIX
logs=${GO2XP_WINE_LOGS:-$out/logs}
mkdir -p "$logs"
logs=$(CDPATH= cd -- "$logs" && pwd)
esc=$(printf '\033')
# Keep the child's exit status before filtering terminal escape sequences.
run() {
    label=$1
    shift
    rc=0
    if command -v script >/dev/null; then
        timeout -k 5 90 script -qec "wine $*" /dev/null >"$logs/$label.raw" 2>&1 || rc=$?
    else
        timeout -k 5 90 wine "$@" >"$logs/$label.raw" 2>&1 || rc=$?
    fi
    tr -d '\r' <"$logs/$label.raw" | sed "s/${esc}\[[0-9;?]*[a-zA-Z]//g" >"$logs/$label.log"
    # script/timeout often exit non-zero with "Session terminated, killing shell"
    # after the Windows process already printed OK/SKIP. Treat that as success.
    if [ "$rc" -ne 0 ] &&
        ! grep -Eq '^FAIL |^panic:|^fatal error:' "$logs/$label.log" &&
        grep -Eq '^(OK|SKIP) ' "$logs/$label.log"; then
        rc=0
    fi
    return "$rc"
}
check() {
    label=$1
    expected=$2
    shift 2
    if (cd "$out" && run "$label" "$@") &&
        ! grep -Eq '^FAIL |^panic:|^fatal error:' "$logs/$label.log" &&
        grep -Eq "^(OK|SKIP) $expected(:| |$)" "$logs/$label.log"; then
        printf 'PASS %s\n' "$label"
    else
        cat "$logs/$label.log"
        printf 'FAIL %s\n' "$label"
        fail=1
    fi
}
go build -o "$out/go2xp" ./cmd/go2xp
# Headless prefix init + version pin. Do not let a non-zero exit from winecfg
# kill the whole script under set -e; log the output so CI failures are visible.
{
    wineboot --init
    wine winecfg /v "$WINVER"
} >"$logs/wine-setup.raw" 2>&1 || {
    tr -d '\r' <"$logs/wine-setup.raw" | sed "s/${esc}\[[0-9;?]*[a-zA-Z]//g" >"$logs/wine-setup.log" || true
    cat "$logs/wine-setup.log" 2>/dev/null || cat "$logs/wine-setup.raw"
    echo "WARN: wine setup exited non-zero; continuing (prefix may still be usable)"
}
# Avoid a full wineserver restart between short probes.
wineserver -p60 2>/dev/null || true
fail=0
for dir in probes/*/; do
    name=$(basename "$dir")
    GOOS=windows GOARCH=386 CGO_ENABLED=0 go build -o "$out/$name.exe" "./$dir"
    "$out/go2xp" patch -profile "$PROFILE" "$out/$name.exe" "$out/$name-patched.exe" >/dev/null
    "$out/go2xp" verify -profile "$PROFILE" "$out/$name-patched.exe" >/dev/null
    check "$name-native" "$name" "$name.exe"
    check "$name-patched" "$name" "$name-patched.exe"
    GO2XP_FORCE_POLYFILLS=1 check "$name-forced" "$name" "$name-patched.exe"
done
# Build and run the actual Windows shim tests; an exit failure is always fatal.
GOOS=windows GOARCH=386 CGO_ENABLED=0 go test -vet=off -c -o "$out/shim.test.exe" ./shim
"$out/go2xp" patch -profile "$PROFILE" "$out/shim.test.exe" "$out/shim.test-patched.exe" >/dev/null
if ! (cd "$out" && run shim-tests shim.test-patched.exe -test.v -test.timeout=60s); then
    cat "$logs/shim-tests.log"
    fail=1
fi
# Exercise the Windows patcher on itself, not just the cross-built Linux patcher.
GOOS=windows GOARCH=386 CGO_ENABLED=0 go build -o "$out/go2xp.exe" ./cmd/go2xp
"$out/go2xp" patch -profile "$PROFILE" "$out/go2xp.exe" "$out/go2xp-patched.exe" >/dev/null
cp "$PROFILE" "$out/profile.json"
for command in 'inspect hello-patched.exe' 'exports C:/windows/system32/kernel32.dll' 'patch -profile profile.json hello.exe hello-self.exe' 'verify -profile profile.json hello-self.exe'; do
    # Words are fixed above; no user input is interpreted as a command.
    set -- $command
    label=$1
    if ! (cd "$out" && run "patcher-$label" go2xp-patched.exe "$@"); then
        cat "$logs/patcher-$label.log"
        fail=1
    fi
done
exit "$fail"
