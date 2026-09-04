# go2xp

Run binaries built with **stock** Go on Windows XP (and Windows 7) — no toolchain fork, no helper DLL.

Idea: missing WinAPI functions are implemented in a Go package (`shim`) linked into the
application; a post-build patcher (`go2xp patch`) fixes the PE header, re-points the
import table slots at those polyfills and hooks `GetProcAddress`/`LoadLibraryExW`
so lazily resolved imports are covered too.

Status: design stage. See `docs/SPEC.md` (spec, Russian) and `STATUS.md` (progress log).

First showcase: [f4](https://github.com/unxed/f4).

License: BSD-3-Clause.
