# ReactOS 0.4.16 as the target you can actually run

XP cannot be put in CI. ReactOS can: it is the same NT 5.x-era API surface
(0.4.16 reports itself as NT 5.2, build 3790), it installs and boots in QEMU
with no KVM, and it can be driven unattended over the QEMU monitor
(`scripts/reactos-vm.py`). That makes it the one target where "the patched
binary comes up and keeps working" is a check rather than a hope, which is why
it has its own profile here.

It is not a stand-in for XP. Where the two differ, `profiles/reactos.json`
says so, and the differences run both ways.

## What was measured, and how

The image is the official release `ReactOS-0.4.16-i386.zip`
(sha1 `0bc124352e54b8773f328df4642655a924dec144`), holding
`ReactOS-0.4.16-i386.iso`. The guest identifies itself as
`ReactOS Version 0.4.16-x86, Build 20260829-0.4.16-release-0-g822e864,
Reporting NT 5.2 (Build 3790)`.

Nothing in `profiles/reactos.json` comes from documentation. Every name was
checked against the export tables of the DLLs in `\reactos\system32` of that
image -- all 447 of them, 34,815 exported names -- read with pefile:

```sh
pip install pycdlib pefile
python3 scripts/fetch-reactos-exports.py ReactOS-0.4.16-i386.iso \
    > profiles/reactos-kernel32-exports.tsv
python3 scripts/fetch-reactos-exports.py --all ReactOS-0.4.16-i386.iso \
    > /tmp/reactos-all-exports.tsv   # not committed: 35k lines, grep fodder
```

## The `*_vista.dll` question

ReactOS ships `kernel32_vista.dll`, `ntdll_vista.dll`, `advapi32_vista.dll`
and `gdi32_vista.dll`, and they carry exactly the Vista+ names an application
is missing -- so the obvious question is whether the loader redirects to them
for an application that asks for a high enough Windows version.

It does not. They are internal compatibility modules: in the 0.4.16 image the
only importers are ReactOS's own DLLs (36 of them -- combase, msvcrt, ole32,
oleaut32, msi, crypt32, atl, pdh, ...), and no application binary is among
them. `scripts/fetch-reactos-exports.py --list-vista-importers` prints that
list, which is worth re-running on a newer image before assuming it still
holds. So a name that only `kernel32_vista.dll` has counts as absent, and the
export list marks it `no  kernel32_vista.dll only` rather than dropping it.

## Where ReactOS and XP part company

ReactOS **has** four functions the xp profile lists as missing:
`ReOpenFile`, `FindFirstStreamW`, `FindNextStreamW` and
`SetFileCompletionNotificationModes`. Auditing a ReactOS run against
`profiles/xp.json` would therefore be wrong in the expensive direction: the
patcher would point those four import slots at shim stubs and replace working
functions with failures. Hence a separate profile rather than a reused one.

In the other direction the profile header is 5.2 rather than 5.1, and
`GetTempPath2W` is absent here as it is on XP.

## Result

Built with stock Go 1.26.6 (`GOOS=windows GOARCH=386 CGO_ENABLED=0`,
`-ldflags=-w`), shim linked in, then `go2xp patch -profile
profiles/reactos.json`. On the live system: the `hello` and `files` probes
print their OK lines, and f4 -- the showcase application -- reaches
`main.main`, draws both panels and runs its file operations, viewer, editor
and command line. The early polyfills run inside `osinit`, and the stubs for
lazily resolved names do their job: f4 asks for `CreatePseudoConsole`, gets
`E_NOTIMPL` from the stub, and degrades instead of panicking in
`LazyProc.Addr`.

One caveat that generalises beyond ReactOS: because the stubs give every
absent export an address, an application that decides "this API exists" by
resolving a name will now decide wrong. f4 had exactly that bug in its ConPTY
probe and was fixed to allocate a pseudo console instead. Applications
adopting the shim should probe capabilities by using them, not by looking them
up.
