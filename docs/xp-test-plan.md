# First run on original Windows XP SP3 x86

Use an unmodified XP SP3 32-bit system. Extract the bundle into a writable folder,
for example C:\go2xp. Read reference-review.md first: this is an experimental
handoff, with known cancellation and filesystem limitations.

## Capture and run

Run `test-xp.cmd` from cmd.exe. It creates `logs`, captures four export lists with
the self-patched go2xp, runs the unpatched hello as a negative baseline, then runs
each patched probe and records its exit code. Keep system-dialog screenshots.
The runner redirects output; probes needing console handles open CONIN$/CONOUT$.
Do not run it without an attached console.

If go2xp-xp.exe cannot start, copy kernel32.dll, advapi32.dll, ws2_32.dll and ntdll.dll
from this XP system for offline `go2xp exports`. Do not substitute Wine DLLs.

| Probe | Required result / purpose |
|---|---|
| hello | OK: runtime startup, timers, goroutines, crypto/rand |
| files | OK: write/read/stat/rename/enumerate and explicitly checked nested RemoveAll |
| exec | OK: child output and exit status |
| console | OK: Console API cell writes/reads and input queue |
| signals | OK on XP: CTRL_BREAK delivered to a child process group; Wine can SKIP |
| net | OK for loopback and local HTTP; external connectivity is optional |

An unpatched hello is expected to fail on XP. Record its exact loader dialog.
Any FAIL, panic, hang or nonzero exit from a patched probe needs investigation.
SKIP console/signals is not an XP acceptance pass. An external HTTPS error is not
necessarily a shim bug: capture the actual certificate/network error separately.

## f4, if included

    f4-xp.exe --help
    f4-xp.exe --tty winapi

Check panels, local directory navigation, read/write/copy of a small file, launching
cmd.exe and return to panels. Keep a separate record for deletion of a nonempty
folder, readonly files, pipes/deadlines and network shares: these exercise the
limitations listed in reference-review.md. Do not interpret a successful --help as
proof that the UI or those operations work. ConPTY and GUI support are not included.

Return the complete logs directory, build-info.txt, SHA256SUMS, screenshots and the
exact command for each failure. Probes do not all log by themselves; test-xp.cmd
captures stdout and stderr. A loader crash may leave only an empty log and a dialog.

Only after this run should the real export dumps and acceptance results be added to
STATUS.md. Translation of the historical Russian spec remains scheduled after XP
acceptance. The f4 workflow is manual and experimental until then.
