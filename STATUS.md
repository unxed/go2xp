# STATUS — протокол работ go2xp

Правила: один шаг из `docs/SPEC.md` §5 → коммит(ы) патчами для `git am` + запись здесь →
ожидание подтверждения пользователя. Записи не переписывать, только дописывать.
Формат записи: дата, шаг, что сделано, что проверено (как именно), что НЕ работает,
открытые вопросы, следующий шаг.

Легенда: `[ ]` не начат · `[~]` в работе · `[x]` готов и подтверждён · `[!]` заблокирован

## Сводка

| # | Шаг | Статус |
|---|---|---|
| 0 | ТЗ, STATUS, README, go.mod | [x] |
| 1 | `go2xp inspect` / `exports` | [x] проверено на hello-world (Go 1.26.6, 386) |
| 2 | `shim` минимальный + таблица GO2XPTBL | [x] |
| 3 | `go2xp patch` + `verify`, профиль xp | [x] + проходит под Wine (winxp) |
| 3.5 | Wine smoke test (`scripts/wine-test.sh`) | [x] |
| 3.6 | static audit (`go2xp audit`, kernel32 export history) | [x] |
| 3.7 | old-Wine stage | [ ] deferred; PlayOnLinux archive gone, alternatives costed in SPEC |
| 4 | ранние asm-полифиллы, `probes/hello` | [x] |
| 5 | Go-полифиллы, `probes/exec`, `probes/files` | [x] |
| 6 | `probes/net`, `probes/console`, `probes/signals` | [x] |
| 7 | CI / reusable action | [x] Wine stage green on GitHub Actions; audit gate reads the profile |
| 8 | профиль win7 | [ ] |
| 8.5 | перевод репозитория на английский (после первого запуска на XP) | [ ] |
| 9 | f4 showcase | [ ] |

## Открытые вопросы (из SPEC §8)

| # | Вопрос | Ответ | Где проверено |
|---|---|---|---|
| 1 | `cgo_import_dynamic "kernel32.dll"` в стороннем пакете | **да**, компилируется и даёт IAT-слот | шаг 2, `shim/shim_windows_386.go` |
| 2 | два одноимённых импорта → два слота? | **да**, линкер не сливает (даже сам рантайм импортирует `GetProcAddress` дважды) | шаг 1/2, вывод `inspect` |
| 3 | `RET $n` в asm 386 | **нет** («invalid instruction»); используем `BYTE $0xC2; WORD $n` (макрос `STDRET`), objdump показывает `RET $0x4` | шаг 2 |
| 4 | XP-загрузчик и расщеплённые описатели импорта | Wine-загрузчик принимает; описатель расщепляется на несколько при вырезании слота из середины; результат читается штатным `debug/pe` (`ImportedSymbols` ok). Проверку живым загрузчиком XP — на стенде | шаг 3 |
| 5 | `NewCallback` изнутри `syscall.Syscall` | — | — |
| 6 | `.reloc` при снятом DYNAMIC_BASE | — | — |

## Фактические данные (заполнять по мере получения)

- Список статических импортов hello-world (Go 1.26.6, 386): 45 импортов, все `kernel32.dll`;
  заголовок `os=6.1 subsystem=6.1 dllchar=0x8140` (DYNAMIC_BASE|NX|TS_AWARE), `.reloc` есть.
  **Отсутствуют на XP SP3 (6):** `WerSetFlags`, `WerGetFlags`, `RaiseFailFastException`,
  `GetQueuedCompletionStatusEx`, `GetErrorMode`, `CreateWaitableTimerExW`.
  `AddVectoredContinueHandler`, `RtlLookupFunctionEntry`, `RtlVirtualUnwind`,
  `IsProcessorFeaturePresent` в бинарник не попали (dead-code). `GetProcAddress` и
  `LoadLibraryExW` рантайм импортирует по два раза (разные слоты).
- Эталон экспортов XP SP3: живой XP нет — профиль строим по референсам (SPEC §7.1) и MS Learn «Minimum supported client»; эталон снимем при первом доступе к XP.
- Baseline: текст ошибки при запуске непропатченного exe на XP: *ждёт стенда*

## Журнал

### 2026-09-04 — шаг 0
- Написаны `docs/SPEC.md`, `STATUS.md`, `README.md`, `go.mod`.
- Источники: актуальный `runtime/os_windows.go` (tip) — список `cgo_import_dynamic`
  и `loadOptionalSyscalls` (`ProcessPrng` грузится лениво через `LoadLibraryExW` +
  `GetProcAddress`; при отсутствии `CreateWaitableTimerExW` штатный откат на winmm);
  предыдущая попытка (ТЗ под форк `go-legacy-winxp`, патчи 0001–0004) — список
  ломающихся символов и фоллбэков.
- Проверено: ничего (кода нет).
- Следующий шаг: 1 (`go2xp inspect`).

### 2026-09-04 — шаг 1
- `internal/pe`: свой парсер импорта (dll, name/ordinal, **RVA слота IAT**, индекс
  описателя) и таблицы экспорта поверх `debug/pe` (`debug/pe` даёт только строки
  `name:dll`, экспорта не читает — проверено по документации через Context7).
  Только PE32 (386), как и заявлено в ТЗ.
- `cmd/go2xp`: команды `inspect app.exe` и `exports kernel32.dll`.
- **Не проверено**: в среде исполнителя не было Go. Нужно прогнать:
  `mkdir -p /tmp/hw && cd /tmp/hw && go mod init hw && printf 'package main\nimport "fmt"\nfunc main(){fmt.Println("hi")}\n' > main.go`
  `GOOS=windows GOARCH=386 CGO_ENABLED=0 go build -o hw.exe . && go run github.com/unxed/go2xp/cmd/go2xp inspect hw.exe`
  Ожидание: `os=6.x`, импорты только `kernel32.dll` (список из SPEC §1.2) — записать
  фактический список сюда, в «Фактические данные». Также `exports` на любой DLL с XP
  (или с Win10 для проверки парсера).
- Следующий шаг: 2 (пакет `shim`, таблица GO2XPTBL) — после подтверждения шага 1.

### 2026-09-04 — шаг 1 (проверка) и шаг 2
- В песочнице поставлен Go 1.26.6; `inspect` прогнан на hello-world — факты выше.
  Исправлен `gofmt` в `internal/pe`.
- `shim/`: Go-файл с `cgo_import_dynamic` + `linkname` (свои слоты `GetProcAddress`,
  `LoadLibraryExW`), asm-файл с таблицей `GO2XPTBL` (магик, версия, count, записи
  `{dll, func, polyfill VA, own slot VA}`), первый полифилл `xp_WerSetFlags` (no-op, S_OK).
  `tableAddr()` из `init()` держит таблицу живой при dead-code elimination.
- **Правило (найдено экспериментально):** собственный IAT-слот shim'а попадает в бинарник
  только если на него ссылается `GO2XPTBL` (`_ = proc…` в Go не спасает). Поэтому каждый
  «свой» импорт обязан иметь запись в таблице с `polyfill=0, ownslot=&slot`.
- `inspect` читает `GO2XPTBL` (сырой скан магика), печатает записи и помечает слоты
  `[shim own slot]`. Проверено: адрес полифилла в таблице = адрес из `go tool objdump`.
- Тест сборки: `/tmp/hw` с `replace github.com/unxed/go2xp => ../go2xp`,
  `GOOS=windows GOARCH=386 CGO_ENABLED=0 go build`, затем `go run ./cmd/go2xp inspect hw.exe`.
- Живой XP нет: DoD шагов 3–6 переопределяем как «`go2xp verify` зелёный» + сверка по
  референсам; запуск пробников на XP — один раз, когда стенд появится.
- Следующий шаг: 3 (`go2xp patch` + `verify`, профиль `xp.json` с 6 функциями).

### 2026-09-04 — шаг 3
- `internal/pe/patch.go`: низкоуровневый PE-writer (правка версий OS/Subsystem,
  снятие DYNAMIC_BASE|HIGH_ENTROPY_VA, обнуление CheckSum, `AddSection` c ростом файла,
  пересчётом NumberOfSections/SizeOfImage; `FileOff` по таблице секций).
- `internal/patch`: `Patch` и `Verify` + профили `profiles/xp.json`, `profiles/win7.json`.
  Алгоритм patch: (1) заголовок → 5.1; (2) для каждого импорта, отсутствующего на цели
  и имеющего полифилл в `GO2XPTBL`, записать VA полифилла прямо в IAT-слот и пометить
  слот на удаление; собственные слоты shim (`OwnSlot`) не трогаются; (3) перестроить
  таблицу описателей импорта БЕЗ удалённых слотов в новой секции `.go2xp` —
  **с расщеплением** описателя на непрерывные по слотам участки (если вырезан слот из
  середины), `FirstThunk` каждого участка указывает на существующий IAT, `OriginalFirstThunk`
  — на свежесобранный INT; (4) `DataDirectory[IMPORT]` → новая секция.
- `forceHook` (рантаймовые `GetProcAddress`/`LoadLibraryExW`) срабатывает ТОЛЬКО когда
  хук-полифилл уже есть в таблице — появится на шаге 4; сейчас эти импорты остаются как есть
  (сами функции на XP присутствуют). `verify` это учитывает.
- Профиль `xp.json`: `missing` = только то, что shim уже полифиллит (пока `WerSetFlags`);
  всё прочее отсутствующее на XP — в `pending` (информационно), переносится в `missing`
  по мере появления полифиллов.
- Проверено (в песочнице, Go 1.26.6):
  * `go2xp patch` + `verify` на hello-world+shim → `verify OK`, заголовок `os=5.1 subsystem=5.1`,
    `dllchar` без DYNAMIC_BASE, `WerSetFlags` исчез из импорта, слот указывает на полифилл,
    появилась секция `.go2xp`, соседний `WerGetFlags` уехал в отдельный описатель (расщепление).
  * пропатченный файл читается штатным `debug/pe`: `ImportedSymbols` возвращает 46 символов
    без ошибок (INT/FirstThunk корректны).
  * `go test ./internal/patch/` — собирает пробник, патчит, проверяет инварианты — PASS.
- Известное упрощение: `DataDirectory[IAT]` (dir 12) оставлен исходным → `ImportedLibraries()`
  из stdlib даёт пустой список (он читает dir 12). Загрузчику это не мешает (он идёт по
  описателям импорта из dir 1). Привести dir 12 в порядок — при необходимости на шаге 6/7.
- **НЕ проверено**: реальная загрузка на XP (нет стенда). Это DoD, закрывается на стенде.
- Следующий шаг: 4 — ранние asm-полифиллы (`LoadLibraryExW`/`GetProcAddress`-хуки,
  `ProcessPrng`→SystemFunction036, `GetErrorMode`, `AddVectoredContinueHandler`,
  `CreateWaitableTimerExW`→0, `RaiseFailFastException`, `GetQueuedCompletionStatusEx`),
  перенос соответствующих функций из `pending` в `missing`, `probes/hello`.

### 2026-09-04 - step 4a (early polyfills, the simple half) and the Wine stage

All new text in this file is English from here on; the Russian entries above predate
that decision. Translating the older entries and docs/SPEC.md is a separate step.

- Code comments across the repository translated to English.
- `shim/shim_other.go`: on anything but windows/386 the package is now empty, so an
  application (f4 included) can keep a single unconditional `import _ ".../shim"`.
- Five early polyfills, all in assembly because they run inside `runtime.osinit`:
  * `WerSetFlags`, `WerGetFlags` - no-ops; error dialogs are still suppressed by
    `SetErrorMode`, which XP has.
  * `GetErrorMode` - XP has no getter, so it calls `SetErrorMode(0)` and restores the
    value it returns. Racy in principle, called once during osinit in practice.
  * `CreateWaitableTimerExW` - returns NULL, which makes the runtime clear
    `haveHighResTimer` and fall back to winmm `timeBeginPeriod` (pre-1.23 behaviour).
  * `RaiseFailFastException` - `TerminateProcess(GetCurrentProcess(), STATUS_FAIL_FAST_EXCEPTION)`.
- The shim now imports `SetErrorMode` and `TerminateProcess` for its own use; verified
  by disassembly that the polyfills call through the shim's own IAT slots
  (`0x0056b124`, `0x0056b120`) and not through the runtime's.
- **Assembler note:** the Go 386 assembler rejects a function whose PUSH/POP counts do
  not match, which stdcall argument pushes always break because the callee pops them.
  Arguments are therefore written with `SUBL $n, SP` + `MOVL`, never `PUSHL`.
- `AddVectoredContinueHandler` dropped from the pending list: on 386 the runtime always
  takes the `SetUnhandledExceptionFilter` path, and the import is not present at all.
- `probes/hello`: goroutine + timer + `crypto/rand`, prints `OK hello`, also logs to
  `hello.log` next to the exe.
- **`scripts/wine-test.sh`** - new mandatory stage before any VM work. Installed wine +
  wine32 here and ran it: hello passes both unpatched and patched with `winecfg /v winxp`,
  which means the rebuilt import table loads, the `.go2xp` section is well formed and the
  five polyfills run without corrupting the stack (`GetErrorMode` really does perform a
  call through its own slot during osinit). What Wine does not prove: the PE version
  fields, the real XP export set, XP semantics.
- Next: step 4b - the `LoadLibraryExW`/`GetProcAddress` hooks (which unlock `ProcessPrng`
  via `SystemFunction036` and every lazily resolved import at once) and
  `GetQueuedCompletionStatusEx`.

### 2026-09-04 - step 4b: the LoadLibraryExW and GetProcAddress hooks

This is the step the whole design was built around, and it works.

- `xp_LoadLibraryExW`: clears the LOAD_LIBRARY_SEARCH_* flags (0x1F00), which XP rejects
  with ERROR_INVALID_PARAMETER, and answers with a sentinel handle (0x476F3258, chosen
  because module handles are 64K-aligned image bases and can never collide with it) for
  any DLL listed in `go2xp_missing_dlls`. That list currently holds bcryptprimitives.dll,
  so the runtime's `throw("bcryptprimitives.dll not found")` can no longer happen.
- `xp_GetProcAddress`: walks GO2XPTBL and returns the polyfill for a matching function
  name. Matching is by name only, ignoring the module handle, so a lookup works whether
  the caller holds a real handle or the sentinel; unmatched names are forwarded to the
  real GetProcAddress, unless the handle is the sentinel, which fails cleanly.
- `xp_ProcessPrng` forwards to advapi32!SystemFunction036 (RtlGenRandom), zero-extending
  the BOOLEAN it returns in AL.
- An entry may now carry a polyfill and an own slot at once, which is how the two hooks
  cover the runtime's slots while leaving the shim's own ones alone. Confirmed by patch
  output: both runtime GetProcAddress slots and both LoadLibraryExW slots are redirected,
  the four shim slots are not.
- **Verified under Wine (winxp), and this is the real result:** the unpatched hello loads
  bcryptprimitives.dll, the patched one does not load it at all, advapi32 is loaded
  instead, and crypto/rand still returns bytes. The sentinel path, the name matching and
  the SystemFunction036 forwarding therefore all execute correctly end to end.
- Consequence worth restating: because every lazy import in the program - the runtime's
  windowsFindfunc, syscall.GetProcAddress and all of golang.org/x/sys/windows - funnels
  through this one slot, any future polyfill only needs a GO2XPTBL entry. No generated
  zsyscall code has to be patched, ever.

Known deviations, to fix before release:
1. Clearing LOAD_LIBRARY_SEARCH_SYSTEM32 widens the DLL search order back to the default,
   which is the planting risk the flag exists to prevent. The proper fix is to prepend the
   system directory the way Go did before 1.21; it needs GetSystemDirectoryW and a wide
   string append in assembly.
2. xp_GetProcAddress does not call SetLastError on the sentinel-miss path.

- Next: step 5 - GetQueuedCompletionStatusEx (the last static import missing on XP) and
  the late polyfills that can be written in Go via syscall.NewCallback: CancelIoEx,
  the ProcThreadAttributeList trio, GetTickCount64.

### 2026-09-04 - step 5: the last static import, and Go-written polyfills

**Milestone: a patched binary has no static import that XP lacks.** Checked by cross
referencing the import table of the patched exec probe against the profile's missing and
pending lists: nothing left, 41 imports, all of them XP-era kernel32.

- `xp_GetQueuedCompletionStatusEx` (assembly, because netpoll calls it from the scheduler
  where entering Go code is not safe): emulated with plain GetQueuedCompletionStatus, one
  packet per call instead of up to 64. All three outcomes are preserved - a dequeued
  packet fills entries[0] and returns TRUE, a timeout returns FALSE with WAIT_TIMEOUT
  intact for netpoll to recognise, and a packet from a failed I/O (which the plain
  function reports as FALSE with a non-NULL OVERLAPPED) is turned back into the TRUE the
  Ex form would return.
- **Late polyfills in Go.** A function that can only be called once the runtime is up no
  longer needs assembly: it is an ordinary Go function installed with
  `syscall.NewCallback`, reached through a two-instruction trampoline that jumps to the
  callback address. First user: `CancelIoEx`, emulated with `CancelIo`.
- **Design fix in xp_GetProcAddress.** It now asks the real function first and only falls
  back to the table when the OS genuinely lacks the export. Before this, one patched
  binary would have forced its emulations onto every Windows version - the CancelIo
  emulation would have replaced the native CancelIoEx on Win7. The sentinel handle is the
  exception: a DLL that is not there can only be answered from the table.
- `forcePolyfills` (env `GO2XP_FORCE_POLYFILLS`) reverses that order for testing, since
  otherwise Wine, which exports everything, would never run a single polyfill. A name the
  table does not know still goes to the real function; getting that wrong made every
  forced run crash in GetModuleFileNameW resolved to a null address, which is exactly the
  kind of mistake the Wine stage is there to catch.
- New probes `files` (write/read/stat/rename/walk/remove, Getwd, UserHomeDir) and `exec`
  (child output, exit code) - both reach netpoll, so every patched run now exercises the
  GetQueuedCompletionStatusEx emulation.
- `scripts/wine-test.sh` runs each probe three ways: unpatched, patched, patched with
  forced polyfills. All nine runs pass.
- Profile `pending` extended with the lazily resolved functions the reference forks list
  (ProcThreadAttributeList trio, GetFileInformationByHandleEx, GetFinalPathNameByHandleW,
  SetFileInformationByHandle, SetFileCompletionNotificationModes, CreateSymbolicLinkW).
  They cost nothing until something calls them, and Wine cannot tell us which ones XP
  actually needs - that list comes from the first real run.

- Next: step 6 - console and signal probes, then the first run on real hardware. Note that
  Wine cannot narrow the pending list any further: it exports everything, so only XP can
  say which lazy imports really fail.

### 2026-09-04 - step 6: console and signal probes

- `probes/console` covers the Console API surface f4 will need on XP, where there is no
  ConPTY and no ANSI interpreter: mode round-trip, screen buffer geometry, and a
  cell-level WriteConsoleOutputW/ReadConsoleOutputW pair. Three properties keep it usable
  in CI: the handles come from CONOUT$/CONIN$ rather than stdio, so redirection does not
  break it; the cell test writes to a back buffer that is never made active, so it cannot
  disturb the display; and the input queue is only inspected, never waited on. The console
  functions are reached through NewLazyDLL, so they run through the GetProcAddress hook.
- `probes/signals` re-executes itself in a new process group and sends CTRL_BREAK_EVENT to
  that group alone, rather than to its own, which would take the harness down with it.
  That is also the shape f4 needs: interrupt a child without killing yourself.
- Wine reports success from GenerateConsoleCtrlEvent but delivers nothing across process
  groups, so the probe detects Wine (ntdll exports wine_get_version, which no real Windows
  has) and reports SKIP there instead of a false failure. On real Windows the same
  situation is still a failure.
- `scripts/wine-test.sh` now runs the probes under script(1) so Wine gives them a real
  console, and decides PASS/FAIL from the probe's own verdict line rather than the exit
  status, which the terminal wrapper obscures. SKIP counts as a pass.
- Windows-only probes have a non-Windows stub file so `go build ./...` still works
  everywhere.
- 15 runs, all green (signals SKIPs under Wine).

Two things Wine has now told us it cannot check, both waiting on hardware: whether control
events actually reach os/signal, and which lazily resolved imports XP really lacks.

- Next: `probes/net`, then step 7 (CI) or the first run on real XP, whichever comes first.

### 2026-09-04 - step 5b: the f4 audit, and the polyfills it demanded

- Built f4 (`./cmd/f4`) with stock Go 1.26.6 for windows/386 - it builds clean, 98 MB -
  and took its full API surface statically: 46 static imports (all kernel32, identical to
  hello-world) and 312 lazily resolved names, read from the `proc*` variables with
  `go tool nm`. Every name classified in `docs/api-audit.md`; raw list in
  `docs/f4-lazy-imports.txt`.
- Three findings that would each have stopped f4 dead on XP, all confirmed in the Go
  sources rather than assumed: `os.ReadDir` uses GetFileInformationByHandleEx with no
  fallback; every os/exec child needs the ProcThreadAttributeList trio; net creates every
  socket with WSA_FLAG_NO_HANDLE_INHERIT, which XP rejects, so no socket could be made.
- Polyfills, all in Go: GetFileInformationByHandleEx and SetFileInformationByHandle map
  onto NtQueryDirectoryFile / NtQueryInformationFile / NtSetInformationFile, whose
  structures are layout-identical to the Win32 classes; STATUS_PENDING is waited out for
  overlapped handles. ProcThreadAttributeList trio as in go-legacy-winxp. CreateEventExW.
- **Override mechanism.** WSASocketW exists on XP, so the real-first hook would never let
  a wrapper run. `go2xp_overrides` lists names the table answers ahead of the real export;
  the wrapper retries without the flag on WSAEINVAL and makes the socket non-inheritable
  afterwards.
- Real functions inside Go polyfills are resolved through the shim's own GetProcAddress
  slot (`realProc`), never through the hooks - otherwise the WSASocketW wrapper would
  find itself. This also keeps ws2_32 out of the static imports.
- Caught by the Wine stage: a fake attribute list handed to a CreateProcessW that does
  parse them (Wine, Win7) crashes it. The stubs now forward to the real functions where
  those exist and fake the list only where they do not, so forced-polyfill runs stay
  honest and one binary is correct everywhere.
- The readdir polyfill passing under forced polyfills also settles the open question of
  whether a last-error set inside a NewCallback survives the way back to the caller:
  ERROR_NO_MORE_FILES reaches os, WalkDir terminates correctly.
- `probes/net`: loopback echo, local net/http, external http and https - all pass.
- 18 runs (6 probes x 3), all green.
- Dropped from the plan as not requested by f4: GetTickCount64, SetThreadDescription,
  GetSystemTimePreciseAsFileTime.

### 2026-09-04 - step 5c: ground truth for XP, and `go2xp audit`

- The idea of an old Wine (before Vista+ exports) as an XP proxy was checked first:
  PlayOnLinux's binary archive answers 404 and the Wayback Machine has only its index
  page, no .pol files. Remaining routes (Debian snapshot packages in a chroot, or building
  Wine 1.6 with patches) are costed in SPEC 3.7 and deferred: an old Wine is still just
  another approximation of XP.
- What is *not* an approximation: the kernel32 export history with the version each
  function first appeared in (Geoff Chappell). Fetched and turned into
  `profiles/kernel32-exports.tsv` (1820 exports, 856 present on XP) by
  `scripts/fetch-exports.py`.
- `go2xp audit app.exe`: reads every `proc*` symbol from the binary (each LazyProc is a
  package-level variable, so the whole lazy surface is visible statically), checks it
  against the export list and against GO2XPTBL, and prints what the target lacks and
  whether the shim covers it. Names kernel32 only forwards since Vista but which live in
  advapi32 on XP - where Go resolves them from anyway - are recognised and not reported.
- Result on f4: the machine check agrees with the hand audit in docs/api-audit.md to the
  name, and additionally confirms GetCurrentConsoleFontEx and FindFirstStreamW as absent.
  On the exec probe with the shim, the only uncovered name is
  SetFileCompletionNotificationModes, which Go tolerates.
- Limits, stated plainly: the export list covers kernel32 only (the other DLLs f4 uses
  are XP-era throughout, per the audit), and the audit sees names, not call sites - it
  cannot tell whether an absent function is actually reached.

### 2026-09-04 - step 7: CI and the reusable action

- `.github/workflows/ci.yml`: build, vet, unit tests, then the Wine stage (installs
  wine32 on the runner and runs `scripts/wine-test.sh`), then the audit gate: every probe
  is built and audited, and any "NOT covered" name outside the accepted list fails the
  job.
- `action/action.yml`: a composite action for other repositories - clones go2xp, builds
  the patcher, patches, verifies and audits the given exe. Used by f4 as
  `uses: unxed/go2xp/action@main`.
- `docs/f4-integration.md`: the two f4-side changes (the import and the `build-xp` job)
  and what to expect on the first XP run.
- Not verified on GitHub Actions itself yet; the workflow runs the same scripts that pass
  here. The first push will tell.
- First GitHub run: every Wine probe failed with "'/tmp' is not owned by you" - Wine
  refuses to create a prefix under a directory it does not own, and /tmp is root's on the
  runner. The default prefix now lives inside the script's own mktemp scratch dir.

### 2026-09-05 - CI: first runs on GitHub Actions

- The Wine stage passes on the runner: all 18 runs, the same as here. What looked like a
  hang was three signals runs waiting out 30 s each; the waits are now 10/15 s, the
  timeout wraps script(1) itself (so a straggler holding the pty cannot stall the
  harness), and the job has a 20-minute limit.
- The audit gate failed on its first run, correctly in substance and wrongly in mechanics:
  GetFinalPathNameByHandleW and ReOpenFile are accepted in the profile, but ci.yml carried
  a hand-copied exclusion list that did not have them. Two sources of truth. Now
  `go2xp audit -profile P` reads the accepted names from the profile's `pending` section
  (each list's key is the reason, shown in the output) and exits non-zero only for a
  name that is neither polyfilled nor accepted; the CI step is one line and the action
  uses the same flag.

### 2026-09-05 — finish the interrupted XP handoff and review Go 1.26 references

- Resumed from published `4e75640757188aee0fbebc50fb1de5d650b71b07`. The changes
  described at the end of the prior session were not present in that commit.
- Fixed the 386 integer overflow and linked the shim into cmd/go2xp. Found the next
  self-hosting failure: the patcher's own GO2XPTBL string was mistaken for its table.
  The scanner now validates candidates, continues past non-tables, bounds offsets,
  and has regressions for collisions and truncated data.
- Restored system-directory prefixing for SYSTEM32 DLL loads, with failures and
  oversized names failing closed; sentinel GetProcAddress misses set error 127.
- CreateProcessW strips the extended-startup flag and copies a plain STARTUPINFO only
  when the real attribute-list API is absent, preserving caller memory and forwarding
  unchanged on modern systems. Generated table/trampolines now have a checked generator.
- Read all nine patches in thongtech/go-legacy-win7 v1.26.6-1 (`87e1f288`) and the
  four syncguy XP commits through `5571222`; also distinguished the current 1.27.1
  reference snapshot. Full reconciliation and remaining limits: docs/reference-review.md.
- Added a bounded NtCreateFile fallback for rejected OBJ_DONT_REPARSE in synchronous
  FILE_OPEN of a single parent-relative component; intermediate paths are not retried,
  and final reparse points are refused. The files probe checks nonempty recursive
  deletion rather than ignoring the cleanup error.
- New bundle.sh builds/patches/verifies/audits all six probes, the self-patched
  Windows patcher and optional f4 via an isolated modfile. test-xp.cmd captures output,
  exit codes and four export dumps; the bundle contains the test plan and checksums.
- Wine harness now preserves exit codes and rejects FAIL/panic output. It also runs
  Windows shim regressions and the Windows patcher's inspect/exports/patch/verify.
  CI exercises the bundle and generator, uploads evidence, and no longer masks all
  Windows vet failures. The reusable action no longer ignores a failed audit.
- Local validation with stock Go 1.26.6 and Wine 9: go test ./..., native vet,
  windows/386 vet (unsafeptr disabled for ABI conversions), generator stability and
  diff checks passed. All 18 probe invocations passed the harness; the three signal
  runs explicitly SKIP under Wine. Four Windows shim tests and four Windows patcher
  commands passed. Reparse refusal is tested with injected metadata, not a native XP
  junction. Relative output/F4 paths and an absolute output path containing spaces
  were exercised by bundle builds.
- f4 `650ad10a78ec39dd52853b7587277ebb4fcb567c` with the companion import patch builds,
  patches, verifies and audits. Unpatched/patched --help and forced --version pass.
  A Wine WinAPI-mode run produced a screen dump showing both file panels and local
  entries; it was intentionally stopped by the 15-second runner timeout. This does
  not establish interactive operations or XP acceptance. test-xp.cmd itself ran under
  Wine and captured all six zero exit codes (including the signal SKIP).
- **Still unverified / incomplete:** original XP loader and exports, native signals,
  cross-thread CancelIoEx emulation, full os.Root/readonly/old-SMB behavior, and the
  Win7 profile/console-handle/process-wait semantics. The old statements that every
  absent lazy export returns an ordinary error and that f4 lacks a WinAPI backend
  were corrected. Hosted CI for this revision is pending publication; it is not
  implied by these local results.
