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
WINEPREFIX=${WINEPREFIX:-/tmp/go2xp-wine}
export WINEPREFIX
export WINEDEBUG=${WINEDEBUG:--all}

command -v wine >/dev/null || { echo "wine not found"; exit 1; }

out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT

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
		if result=$(cd "$out" && timeout 120 wine "$exe" 2>/dev/null); then
			echo "PASS $exe: $result"
		else
			echo "FAIL $exe (exit $?)"
			fail=1
		fi
	done
	if result=$(cd "$out" && GO2XP_FORCE_POLYFILLS=1 timeout 120 wine "$name-patched.exe" 2>/dev/null); then
		echo "PASS $name-patched.exe [forced polyfills]: $result"
	else
		echo "FAIL $name-patched.exe [forced polyfills] (exit $?)"
		fail=1
	fi
done
exit $fail
