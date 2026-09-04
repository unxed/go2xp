# go2xp

Run binaries built with **stock** Go on Windows XP (and Windows 7) — no toolchain fork, no helper DLL.

Idea: missing WinAPI functions are implemented in a Go package (`shim`) linked into the
application; a post-build patcher (`go2xp patch`) fixes the PE header, re-points the
import table slots at those polyfills and hooks `GetProcAddress`/`LoadLibraryExW`
so lazily resolved imports are covered too.

Status: experimental XP handoff. The probes, Windows shim tests and the self-patched
patcher run under Wine. **Real XP acceptance is still pending**, and export coverage
alone does not establish complete Go compatibility. See [reference review](docs/reference-review.md)
for known cancellation, filesystem and Win7 limitations.

Build the XP bundle on Linux with Go 1.26.6 or later:

```sh
sh scripts/bundle.sh /path/to/bundle-xp
# Optionally include an f4 checkout with the companion shim-import patch:
F4=/path/to/f4 sh scripts/bundle.sh /path/to/bundle-xp
```

Run `test-xp.cmd` from the extracted bundle on the XP machine. See
[the test plan](docs/xp-test-plan.md), `docs/SPEC.md` (spec, Russian) and
`STATUS.md` (append-only progress log).

First showcase: [f4](https://github.com/unxed/f4).

License: BSD-3-Clause.
