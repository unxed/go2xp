# Experimental XP build for f4

The companion f4 patch adds a `go2xp` build-tag import, a real published module
version (no placeholder), and a manual **Windows XP handoff** workflow. It checks
out go2xp at the requested ref and builds both shim and patcher from that same
checkout using `scripts/bundle.sh` and an isolated modfile. Normal f4 builds do not
include the shim. Apply the go2xp patch before selecting its published ref.

Locally, after applying the f4 patch:

```sh
F4=/absolute/path/to/f4 sh scripts/bundle.sh /absolute/path/to/bundle-xp
```

This uses stock Go, windows/386, no cgo, and keeps symbols for audit (`-w`, not
`-s`). The bundle includes both f4.exe and f4-xp.exe plus audit logs and checksums.
The current f4 already has a Console API backend. Start the XP executable with:

```bat
f4-xp.exe --tty winapi
```

--help/--version and a WinAPI screen dump with both file panels were verified under
Wine. Real XP panels, filesystem operations and process interaction
need the [test plan](xp-test-plan.md). See [reference-review.md](reference-review.md)
for known limitations; an absent lazy procedure can panic when its caller uses
LazyProc.Addr, so an accepted audit entry is not a promise of graceful failure.
