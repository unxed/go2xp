# Adding an XP build to f4

Two changes on the f4 side, plus the console backend f4 needs regardless.

1. In `cmd/f4/main.go`:

       import _ "github.com/unxed/go2xp/shim"

   The package is empty on anything but windows/386, so the import is harmless for every
   other target. `go get github.com/unxed/go2xp@main` (or a tag once there is one).

2. A `build-xp` job. The binary must be built with stock Go for windows/386, without cgo,
   and must not be stripped with `-s` if you want `go2xp audit` to see the lazy imports
   (`-w` alone is fine):

       - run: GOOS=windows GOARCH=386 CGO_ENABLED=0 go build -trimpath -ldflags="$APP_LDFLAGS" -o build/f4.exe ./cmd/f4
       - uses: unxed/go2xp/action@main
         with:
           input: build/f4.exe
           profile: xp
       - uses: actions/upload-artifact@v4
         with:
           name: f4-xp
           path: build/f4-xp.exe

   The action patches, verifies and prints the audit. The patched exe is a separate file;
   the unpatched one still runs on modern Windows and the patched one runs there too (the
   hooks prefer real exports), so shipping only the patched build is an option.

3. The GUI mode (`-H windowsgui`) is out of scope for XP: it needs ConPTY and DWM, which
   do not exist there. Build the console binary. On XP the terminal has no ANSI
   interpreter, so f4's Console-API backend (cell writes through WriteConsoleOutputW, input
   through ReadConsoleInputW) is required - see `probes/console` for the exact surface
   that works.

What to expect on the first real XP run: everything the audit marks as covered should
work; a function it marks "NOT covered" fails at its call site with ERROR_PROC_NOT_FOUND,
which f4 sees as an ordinary error. If something the audit did not flag fails, the fix is
one GO2XPTBL entry in the shim.
