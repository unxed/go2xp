# Reference review before the XP handoff (2026-09-05)

Scope: stock **Go 1.26.6, windows/386, CGO_ENABLED=0**, go2xp based on
`4e75640757188aee0fbebc50fb1de5d650b71b07`. This is an implementation review and a
Wine test record, not evidence of execution on an original XP or Windows 7 kernel.

## Pinned references

- [syncguy/go-legacy-winxp](https://github.com/syncguy/go-legacy-winxp/commit/5571222f3659eca21869c344d29fcc68aaa2ef7f),
  `winxp-compat`: four XP commits over Go 1.24.4 (`b065c91`). Five changed source files,
  59 additions and 7 deletions. The branch already uses RtlGenRandom; its remaining
  source is not equivalent to stock Go 1.26.6.
- [thongtech/go-legacy-win7 v1.26.6-1](https://github.com/thongtech/go-legacy-win7/tree/87e1f288113a36969275ef6a383c9023cac84e3c/patches),
  commit `87e1f288113a36969275ef6a383c9023cac84e3c`. Read all nine patches and checked
  the resulting Windows source against the installed stock 1.26.6 source.
- [thongtech main snapshot](https://github.com/thongtech/go-legacy-win7/tree/65ef63f2695c106c29263fe31cf7fb4cec2afefd/patches)
  is already **Go 1.27.1**. Its additional IOCP, console-device and filesystem patches
  are useful warnings, but must not be confused with the requested 1.26 reference.

## Go 1.26 patch-by-patch reconciliation

| Reference patch | go2xp result / remaining limit |
|---|---|
| 0001 ProcessPrng -> RtlGenRandom | Covered by the sentinel DLL and ProcessPrng assembly polyfill, including runtime startup and crypto/rand. |
| 0002 GOPATH go get | Toolchain UX, unrelated to a compiled application's Windows imports. |
| 0003 LoadLibrary fallback | SYSTEM32 bare names now become absolute paths; failed directory queries and oversized names fail instead of widening the search. General LOAD_LIBRARY_SEARCH_* policy emulation is not complete. |
| 0004 console handles and process wait | XP CreateProcessW now receives a plain STARTUPINFO when the real attribute-list API is absent. **Win7 console pseudo-handles in the real attribute list, custom parent processes, and the old Process.Wait timing workaround are not implemented.** |
| 0005 socket fallback | WSASocketW wrapper retries without NO_HANDLE_INHERIT on WSAEINVAL. The flag-to-SetHandleInformation interval is not atomic. |
| 0006 removeall_noat | The old probe ignored its deferred RemoveAll error. It now checks a nonempty nested tree. NtCreateFile retries rejected OBJ_DONT_REPARSE only for synchronous FILE_OPEN of one component relative to a parent handle and rejects reparse points. This is **not** full os.Root support: multi-component no-follow opens, creation and readonly deletion/ReOpenFile remain outside that fallback. |
| 0007 race/atomic operations | The race detector is not supported for windows/386. Replacing public atomic APIs is not needed for this non-race application target. |
| 0008 atomic Or -> CAS | Source compatibility with 0007; stock non-race 386 already provides atomic operations. |
| 0009 old SMB enumeration | Local directory information classes are served by NtQueryDirectoryFile. A FindFirstFile fallback for SMB servers rejecting those classes is **not implemented**; test local filesystems before network shares. |

The XP fork adds the six early APIs already covered by go2xp (WER, GetErrorMode,
CreateWaitableTimerExW, RaiseFailFastException, GetQueuedCompletionStatusEx), the
attribute-list stubs and CancelIo fallback. It does not prove that these suffice
for Go 1.26. Its directory and net/poll source must be considered separately.

## Important boundaries the old audit did not establish

- **CancelIo is not CancelIoEx.** It cancels only operations issued by the calling
  OS thread, and cannot select one OVERLAPPED. Go can issue I/O and cancel it on
  different threads. The existing fallback is incomplete; pending pipe/socket
  cancellation and deadlines require additional work and XP validation. A simple
  successful transfer does not prove cancellation.
- `FileReplaceCompletionInformation` (IOCP detach), no-follow flags, directory
  information classes and console pseudo-handles are semantic differences in
  APIs whose *names already exist*. An export-name audit cannot detect them.
- Missing lazy exports do not always become ordinary returned errors. Generated
  wrappers that call `LazyProc.Addr()` can **panic**; only callers using Find or an
  explicit error-returning lookup are known to degrade gracefully.
- `audit` currently checks the historical **kernel32 XP** name list, with symbol
  heuristics and a small advapi exception list. Other DLL names and dynamic aliases
  remain unknown. It is not a complete compatibility certificate or a Win7 audit.
- `profiles/win7.json` remains an unfinished experimental profile. This handoff
  does not claim full Win7 support. Use the XP profile for the supplied bundle.
- f4 main `650ad10a78ec39dd52853b7587277ebb4fcb567c` already has a WinAPI terminal
  backend. Start it with `--tty winapi`; the old statement that the backend must
  still be written is obsolete. A Wine screen dump now confirms startup into both panels; basic I/O on real XP remains
  acceptance tests, not an inference from `--help` under Wine.

## What the new checks prove

- Linux Go tests and a windows/386 build of the patcher.
- The patcher can find its shim table even though its own strings also contain
  GO2XPTBL; truncated candidates cannot panic the reader.
- Windows shim tests call the actual stdcall table entries. They cover sentinel
  misses/ordinals, system-directory prefixing and failures, XP/plain STARTUPINFO
  without mutating caller data, and rejected no-follow flags with unsafe paths
  refused. Reparse metadata is injected because this Wine build's symlink creation
  did not produce a usable reparse point; native junction behavior remains unverified.
- The Wine harness preserves exit status, rejects FAIL/panic output, requires the
  correct probe verdict, runs Windows shim tests, and runs the Windows patcher for
  inspect, exports, patch and verify.
- bundle.sh builds and audits all probes and the self-patched patcher, accepts
  relative/absolute output paths, and uses an isolated modfile for optional f4.

See the delivered validation log for the actual run results. A successful run does
not close the original-XP export-dump, loader, signal, cancellation, or filesystem
acceptance items. The list above is the follow-up scope; none is silently accepted
as fully supported merely because CI is green.
