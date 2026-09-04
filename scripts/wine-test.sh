#!/bin/sh
# Build the probes for windows/386, patch them for a profile and run both the
# original and the patched binary under Wine with the Windows version set to the
# target. Wine is much more permissive than a real XP loader, so a pass here only
# rules out the crude mistakes - a malformed import table, a broken section, a
# polyfill that corrupts the stack - and is not a substitute for the real thing.
# A failure here, on the other hand, is always a genuine bug.
#
# Requires wine plus 32-bit support (on Debian/Ubuntu: dpkg --add-architecture
# i386 && apt-get install wine wine32).
#
# Usage: scripts/wine-test.sh [profile] [winver]
set -eu

PROFILE=${1:-profiles/xp.json}
WINVER=${2:-winxp}
export WINEDEBUG=${WINEDEBUG:--all}

command -v wine >/dev/null || { echo "wine not found"; exit 1; }

out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT

# Wine refuses to create a prefix whose parent directory it does not own, and /tmp is
# root's on GitHub runners, so the default prefix lives inside our own scratch dir.
WINEPREFIX=${WINEPREFIX:-$out/prefix}
export WINEPREFIX

# The console and signal probes need a real console, which Wine only provides when its
# stdio is a terminal. script(1) supplies one; without it those probes report SKIP.
esc=$(printf '\033')
if command -v script >/dev/null; then
	run() { script -qec "timeout 120 wine $1" /dev/null 2>/dev/null | tr -d '\r' | sed "s/${esc}\[[0-9;?]*[a-zA-Z]//g"; }
else
	run() { timeout 120 wine "$1" 2>/dev/null; }
fi

# A probe reports its own verdict, which survives the terminal wrapper better than an
# exit status does.
check() {
	case "$2" in
	*"OK "*|*SKIP*) echo "PASS $1: $(echo "$2" | tr -s "\n" " ")" ;;
	*) echo "FAIL $1: $(echo "$2" | tr -s "\n" " ")"; fail=1 ;;
	esac
}

go build -o "$out/go2xp" ./cmd/go2xp
wine winecfg /v "$WINVER" >/dev/null 2>&1 || true

fail=0
for dir in probes/*/; do
	name=$(basename "$dir")
	GOOS=windows GOARCH=386 CGO_ENABLED=0 go build -o "$out/$name.exe" "./$dir"
	"$out/go2xp" patch -profile "$PROFILE" "$out/$name.exe" "$out/$name-patched.exe" >/dev/null
	"$out/go2xp" verify -profile "$PROFILE" "$out/$name-patched.exe" >/dev/null

	# The patched binary is run twice. The plain run is what a user gets: the hooks
	# prefer whatever the OS really exports, so on Wine almost nothing is emulated.
	# GO2XP_FORCE_POLYFILLS makes the table win instead, which is the only way to
	# exercise the polyfills themselves without a real XP.
	for exe in "$name.exe" "$name-patched.exe"; do
		check "$exe" "$(cd "$out" && run "$exe")"
	done
	check "$name-patched.exe [forced polyfills]" \
		"$(cd "$out" && GO2XP_FORCE_POLYFILLS=1 run "$name-patched.exe")"
done
exit $fail
