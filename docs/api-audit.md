# API audit: what f4 asks of Windows, and what XP SP3 can answer

> Historical inventory. The [2026-09-05 reference review](reference-review.md) corrects
> the claims below about ordinary errors, CancelIo equivalence, complete coverage and
> the missing console backend. Do not use this inventory as an acceptance report.

Done without an XP machine, from a stock Go 1.26.6 windows/386 build of f4 (`./cmd/f4`).
Two sources: the static import table (`go2xp inspect`) and the full set of lazily
resolved names, which are visible statically because every `NewProc` is a package-level
variable named `proc<Function>` (`go tool nm f4.exe | grep '\.proc[A-Z]'`). The raw list
is in `f4-lazy-imports.txt` (312 names).

Static imports: 46, all kernel32, identical to a hello-world. f4 adds none of its own,
so the runtime set the shim already covers is the whole static story.

Presence on XP SP3 is from MS Learn "Minimum supported client" plus the reference forks
(SPEC 7.1); the export dump from a live XP will confirm it. Whether Go copes with an
absent function was checked in the Go 1.26.6 sources, not guessed.

## Absent on XP and required: polyfilled

| Function | Why it matters | Polyfill |
|---|---|---|
| GetFileInformationByHandleEx | `os.ReadDir` since Go 1.22, no fallback (os/dir_windows.go). A file manager cannot list a folder without it | NtQueryDirectoryFile / NtQueryInformationFile; the Win32 and NT structures are layout-identical |
| InitializeProcThreadAttributeList, UpdateProcThreadAttribute, DeleteProcThreadAttributeList | every `os/exec` child (syscall/exec_windows.go), no fallback | fake list on XP (CreateProcessW there ignores it); forwarded where the real ones exist |
| WSASocketW (override: exists on XP) | net passes WSA_FLAG_NO_HANDLE_INHERIT unconditionally (net/sock_windows.go); XP answers WSAEINVAL, so no socket can be created | retry without the flag on that exact error, then SetHandleInformation |
| CancelIoEx | closing any async handle | CancelIo |
| SetFileInformationByHandle | Fchmod (internal/poll), os.Root deletes | NtSetInformationFile |
| CreateEventExW | dependency use | CreateEventW with the flags unpacked |
| ProcessPrng | crypto/rand, runtime throw at startup | SystemFunction036 via the sentinel DLL |

## Absent on XP, but Go copes on its own

GetTempPath2W (os falls back to GetTempPathW), SetFileCompletionNotificationModes
(internal/poll tolerates the error), GetVolumeInformationByHandleW (os.ReadDir sets vol=0
and continues; only os.SameFile degrades).

## Absent on XP, left to fail with an error

The caller gets ERROR_PROC_NOT_FOUND and handles it like any other failure. None sits on
a path a file manager needs to start: GetFinalPathNameByHandleW (symlink resolution),
CreateSymbolicLinkW, ReOpenFile (chmod of a read-only file inside os.Root),
QueryFullProcessImageNameW, GetCurrentConsoleFontEx, RegLoadMUIStringW, WSAPoll,
FindFirstStreamW / FindNextStreamW.

## No XP equivalent at all

CreatePseudoConsole / ResizePseudoConsole / ClosePseudoConsole (ConPTY, Win10 1809),
DwmSetWindowAttribute, GetDpiForWindow. f4 already probes for ConPTY and needs the
Console-API backend on XP regardless, which is f4-side work.

## Not requested by f4

GetTickCount64, SetThreadDescription, GetSystemTimePreciseAsFileTime. They were on the
plan from general knowledge; dropped, since nothing would call them.

## Everything else

The remaining ~280 names are XP-era: kernel32 file/console/process functions, ntdll
(NtCreateFile, NtQueryInformationFile, RtlGetVersion...), ws2_32 and mswsock, advapi32
security and credentials, user32/gdi32 for the GUI mode, ole32, shell32, winmm, userenv,
secur32, netapi32, dnsapi, crypt32, iphlpapi. All present on XP SP3.

## What only XP can still tell us

Wine 9 exports all of the above, so a forced-polyfill run under Wine proves the polyfills
work, not that the list of what needs one is complete. The first real run will show any
lazy import this audit misjudged - it surfaces as ERROR_PROC_NOT_FOUND at the call site,
and the fix is one GO2XPTBL entry.
