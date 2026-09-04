# go2xp — ТЗ (техническое задание)

Запуск приложений, собранных **стоковым** Go 1.26.x, на Windows XP SP3 (профиль `xp`)
и Windows 7 (профиль `win7`) — без форка тулчейна и без внешней DLL.

Текущее состояние работ — в `STATUS.md`.

---

## 0. Цель, границы, критерии

**Цель.** Утилита `go2xp` + Go-пакет `shim`, такие что:

```
import _ "github.com/unxed/go2xp/shim"      // одна строка в main-пакете приложения
GOOS=windows GOARCH=386 CGO_ENABLED=0 go build -o app.exe .
go2xp patch -profile xp app.exe             // пост-обработка бинарника
```

и `app.exe` запускается на XP SP3 x86.

**Не цель (v1):**
- amd64 под XP (XP x64 — экзотика; профиль `win7` на amd64 — позже, после `xp`/386);
- cgo-бинарники;
- прикладной слой f4 (Console API вместо ConPTY/ESC-последовательностей, winpty) — это уже сделано в репозиториях f4 и vtui, все API, специфические для более поздних версий Windows, используются только там, где поддерживаются;
- сохранение Authenticode-подписи (патч её ломает, это принято).

**Критерий готовности движка (DoD v1):** все пробники из §6 запускаются на живой
XP SP3 x86 и печатают `OK`. **DoD showcase:** f4 из CI (джоба `build-xp`) стартует на XP
до рабочего UI (панели, навигация, файловые операции, запуск внешней команды).

---

## 1. Почему стоковый Go-бинарник не идёт на XP

Ровно три класса причин (по возрастанию «глубины»):

1. **PE-заголовок.** Линкер Go пишет `MajorOperatingSystemVersion`/`MajorSubsystemVersion`
   = 6 (в старом форке это константа `PeMinimumTargetMajorVersion` в `cmd/link/internal/ld/pe.go`).
   Загрузчик XP (5.1) отказывает: «не является приложением Win32». Лечится правкой 4 полей.

2. **Статические импорты (IAT).** Рантайм объявляет функции через `//go:cgo_import_dynamic`
   в `runtime/os_windows.go`; линкер кладёт их в таблицу импорта. Если в `kernel32.dll` XP
   нет функции — падение **на этапе загрузки**: «точка входа не найдена». Из актуального
   списка (сверено с `runtime/os_windows.go` tip, сентябрь 2026) на XP SP3 отсутствуют:

   | функция | появилась | используется в рантайме для |
   |---|---|---|
   | `AddVectoredContinueHandler` | Vista | `initExceptionHandler` |
   | `CreateWaitableTimerExW` | Vista | `initHighResTimer`, `minit` — при 0 есть штатный откат на `winmm!timeBeginPeriod` |
   | `GetErrorMode` | Vista | `preventErrorDialogs` |
   | `GetQueuedCompletionStatusEx` | Vista | `netpoll` (пакетный приём) |
   | `RaiseFailFastException` | Win7 | `dieFromException`/`crash` |
   | `WerGetFlags`, `WerSetFlags` | Vista | `preventErrorDialogs` |
   | `RtlLookupFunctionEntry`, `RtlVirtualUnwind` | amd64-only | должны выпасть на 386 при dead-code elimination — **проверить инвентаризацией (§5, шаг 1)** |

   Всё остальное из списка (`AddVectoredExceptionHandler`, `IsProcessorFeaturePresent`,
   `LoadLibraryExW`, `SwitchToThread`, `SetProcessPriorityBoost`, …) в XP есть.

3. **Ленивые импорты (`GetProcAddress` в рантайме).** Всё, что резолвится в рантайме через
   `LoadLibraryExW` + `GetProcAddress`. Падение — не при загрузке, а при вызове
   (или `throw`). Известные проблемные места:
   - рантайм: `windowsLoadSystemLib` вызывает `LoadLibraryExW(name, 0, LOAD_LIBRARY_SEARCH_SYSTEM32)`;
     XP не знает этот флаг → `ERROR_INVALID_PARAMETER` → `throw("bcryptprimitives.dll not found")`.
     Плюс `bcryptprimitives.dll` в XP нет вообще → `ProcessPrng` надо подменять
     (на `advapi32!SystemFunction036` = `RtlGenRandom`, есть в XP SP3).
   - `ntdll!NtCreateWaitCompletionPacket` & co — рантайм проверяет на nil, ок без правок.
   - `syscall`/`x/sys/windows`/`os`/`os/exec`/`net`: `CancelIoEx` (→ `CancelIo`),
     `InitializeProcThreadAttributeList`/`UpdateProcThreadAttribute`/`DeleteProcThreadAttributeList`
     (`os/exec` зовёт их безусловно; на XP — эмулировать «пустой» список и снимать
     `EXTENDED_STARTUPINFO_PRESENT` в `CreateProcessW`), `GetTickCount64`, `GetFileInformationByHandleEx`,
     `GetFinalPathNameByHandleW`, `SetFileInformationByHandle`, `SetFileCompletionNotificationModes`,
     `CreateSymbolicLinkW`, `GetSystemTimePreciseAsFileTime`, `SetThreadDescription` и т.п.
     Точный список даст только запуск пробников (§6) — не гадать заранее, чинить по логу.

Семантические расхождения (флаги `CreateFile`, поведение консоли и т.д.) — четвёртый,
«тонкий» класс; решаем по факту, деградируя функциональность осознанно.

---

## 2. Ключевая идея (чем отличаемся от форков)

Форки (`thongtech/go-legacy-win7`, `syncguy/go-legacy-winxp`) правят рантайм. Мы **не
трогаем тулчейн**; всё делается двумя штатными механизмами Go + пост-патчем PE:

**A. Полифиллы живут в обычном Go-пакете `shim`**, который приложение импортирует.
Линкер вкомпилирует их в бинарник как любой другой код. Никакой отдельной DLL.

**B. Патчер перенаправляет на них IAT-слоты и хукает `GetProcAddress`.**

Ниже — четыре наблюдения, на которых всё держится (каждое надо подтвердить на шаге 2 §5):

1. **`//go:cgo_import_dynamic` разрешён в обычных (не-cgo) пакетах.** Компилятор явно
   допускает эту директиву вне cgo-кода (исторически ради `x/sys/unix` на Solaris; лишь
   проверяет, что имя библиотеки «безопасное» — `kernel32.dll` проходит). Значит `shim`
   может сам объявить импорты `kernel32!GetProcAddress`, `advapi32!SystemFunction036` и т.д.
   и получить **собственные** IAT-слоты, которые патчер не трогает. Так рантайм пишет:
   `//go:cgo_import_dynamic runtime._GetProcAddress GetProcAddress%2 "kernel32.dll"`.
   Схема для стороннего пакета — как в `x/sys/unix` для Solaris:
   `//go:cgo_import_dynamic go2xp_GetProcAddress GetProcAddress%2 "kernel32.dll"` +
   `//go:linkname procGetProcAddress go2xp_GetProcAddress` + `var procGetProcAddress uintptr`.
   IAT-слот — это и есть эта переменная; загрузчик Windows кладёт в неё адрес.

2. **Рантайм зовёт импорты косвенно через слот** (`MOVL _X(SB), AX; CALL AX` в
   `asmstdcall`), а не через `CALL [thunk]` с фиксированным адресом. Поэтому достаточно,
   чтобы **в слоте лежал адрес нашего полифилла**, — код рантайма менять не нужно.

3. **ВСЕ ленивые резолвы идут через один слот `runtime._GetProcAddress`.**
   `syscall.getprocaddress` → `runtime.syscall_getprocaddress` → `stdcall(_GetProcAddress, …)`;
   `x/sys/windows` линкнеймится на `syscall.getprocaddress`; сам рантайм зовёт
   `windowsFindfunc` → тот же слот. Аналогично `syscall.loadlibrary` →
   `runtime._LoadLibraryExW`. Подменив **два** слота (`GetProcAddress`, `LoadLibraryExW`)
   мы перехватываем **все** ленивые импорты во всей программе по имени — универсально,
   без перечисления call-site'ов.

4. **Полифиллы можно писать на Go** (а не только на asm) для всего, что вызывается после
   инициализации рантайма: Windows-callback'и (`syscall.NewCallback`) — штатный механизм
   входа в Go-код из stdcall-контекста, работает и когда нас позвали из `syscall.Syscall`
   (мы на стеке g0, как обычный callback из `EnumWindows`). Только ~8 «ранних» функций
   (`osinit`/`schedinit`: `AddVectoredContinueHandler`, `GetErrorMode`, `Wer*`,
   `CreateWaitableTimerExW`, `LoadLibraryExW`, `GetProcAddress`, `ProcessPrng`,
   `RaiseFailFastException`) пишутся на Go-ассемблере (Plan9, `NOSPLIT|NOFRAME`, stdcall
   вручную), потому что зовутся до того, как есть рантайм. Всё «позднее» — на Go.

---

## 3. Архитектура

```
go2xp/
  shim/            Go-пакет, линкуется в приложение
    shim_windows_386.s   ранние полифиллы на asm + таблица GO2XPTBL
    shim_windows.go      cgo_import_dynamic реальных функций, Go-полифиллы, init()
    polyfill_*.go        реализации по группам (proc, io, file, time, ...)
  cmd/go2xp/       патчер (CLI): inspect | patch | verify
  internal/pe/     работа с PE поверх debug/pe: импорты, секции, relocs, запись
  profiles/        xp.json, win7.json — списки «чего нет» + версии заголовка
  probes/          пробники (§6), каждый — отдельный main
  docs/SPEC.md     этот файл
  STATUS.md        протокол шагов
```

### 3.1 Таблица `GO2XPTBL`

Пакет `shim` кладёт в `.data` (через `DATA/GLOBL` в asm) таблицу:

```
magic   "GO2XPTBL" (8 байт)
version u32
count   u32
entries: { dll_name *cstr, func_name *cstr, polyfill_addr u32, own_slot_addr u32 }
```

- `polyfill_addr` — VA полифилла (stdcall-совместимого) для `dll!func`;
- `own_slot_addr` — адрес **собственного** IAT-слота shim'а для той же функции (если shim
  импортирует оригинал, чтобы форвардить в него), иначе 0. Патчер обязан **не** трогать
  этот слот.

Адреса — абсолютные VA при `ImageBase` линкера (линкер эмитит их + `.reloc`). Патчер ищет
магик сканом секций (не завися от символов/`-s -w`). Чтобы линкер не выкинул таблицу
dead-code-elimination'ом, `shim.init()` ссылается на неё (`keepalive`-функция в asm).

### 3.2 Патчер `go2xp patch`

Вход: `app.exe`, профиль. Действия, по порядку:

1. `inspect`: разобрать PE (`debug/pe` + свой парсер импорта/reloc); найти `GO2XPTBL`;
   вывести все импорты и отметить отсутствующие в профиле. Если shim не влинкован — ошибка.
2. Заголовок: `MajorOperatingSystemVersion=5, Minor=1`, `MajorSubsystemVersion=5, Minor=1`
   (профиль `win7`: 6.1). Снять `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` (XP всё равно не
   релоцирует exe; но так проще: слоты заполняем абсолютными VA). `HIGH_ENTROPY_VA` —
   снять. Пересчитать `CheckSum` (или обнулить).
3. Импорты. Для каждого слота IAT, чьё `(dll, name)` есть в профиле как отсутствующее
   **и** слот ≠ `own_slot_addr` из таблицы:
   - вырезать его из списка загрузчика: описатель импорта (`IMAGE_IMPORT_DESCRIPTOR`)
     для этой DLL **расщепляется** на два описателя той же DLL — `FirstThunk` первого
     покрывает слоты до вырезанного, второго — после. (Несколько описателей одной DLL —
     легально, загрузчик обрабатывает по очереди.) Новые описатели и их INT пишутся в
     новую секцию `.go2xp`; `DataDirectory[IMPORT]` перенаправляется на неё.
   - В сам слот записать `polyfill_addr` (сырое значение в файле).
   - Если у DLL после вырезания не осталось функций (`bcryptprimitives.dll`) — описатель
     удаляется целиком.
   - Слоты `GetProcAddress` и `LoadLibraryExW` (не принадлежащие shim) переводятся на
     полифиллы-хуки **всегда**, независимо от профиля.
4. `verify`: перечитать результат, убедиться, что в таблице импорта не осталось ничего
   вне белого списка профиля, а версии заголовка правильные. Код возврата ≠ 0 при ошибке.

Формат профиля (`profiles/xp.json`): версия заголовка + карта `dll → [функции, которых нет]`
+ карта `dll → отсутствует целиком`. Первичный источник списка — экспорт-таблицы
`kernel32/advapi32/ws2_32/ntdll` с живой XP SP3 (снять один раз `go2xp exports` и
закоммитить как `profiles/exports-xp-sp3.txt`).

### 3.3 Хуки `GetProcAddress` / `LoadLibraryExW` (asm, ранние)

- `xp_LoadLibraryExW(name, 0, flags)`: сбросить неизвестные XP флаги
  (`LOAD_LIBRARY_SEARCH_*`); если DLL в списке «отсутствует целиком» — вернуть
  **сентинел-хэндл** (например `0x00470058` = 'GX'), иначе — реальный `LoadLibraryExW`
  без флагов (для system32 — с полным путём через `GetSystemDirectoryW`, как делал Go ≤1.20).
- `xp_GetProcAddress(hmod, name)`: пробежать таблицу; если `(hmod — сентинел или реальный
  модуль с этим именем DLL) && name совпало` → вернуть `polyfill_addr`; иначе форвард в
  реальный `GetProcAddress` (через собственный слот shim'а). Сравнение строк — байтовое,
  в asm (`REPE CMPSB`-уровня простоты). Ординалы (name < 0x10000) — сразу форвард.

Итог: `ProcessPrng` и весь ленивый `syscall` закрываются одной таблицей, без правки
`zsyscall_windows.go`.

### 3.4 Правила для полифиллов

- ABI: stdcall (аргументы на стеке, callee чистит `RET $n`), сохранять `EBX/ESI/EDI/EBP`,
  выставлять `SetLastError` там, где оригинал бы его выставил.
- asm-полифиллы: `TEXT ·xp_X(SB),NOSPLIT|NOFRAME,$0`, никакого обращения к `g`/TLS Go,
  вызовы наружу только через собственные IAT-слоты shim'а.
- Go-полифиллы: обычная Go-функция + `syscall.NewCallback` в `shim.init()`; asm-обёртка
  `JMP`-ит на адрес из переменной, а если переменная ещё 0 (рантайм не поднят) — возвращает
  «не реализовано» (`0` + `ERROR_CALL_NOT_IMPLEMENTED`). Ограничение NewCallback на 386:
  все аргументы — `uintptr`-размера; это нормально для WinAPI.
- Полифилл = минимальный **мост к более старому API** (`GetQueuedCompletionStatusEx` →
  цикл `GetQueuedCompletionStatus` по одному; `CancelIoEx` → `CancelIo`;
  `ProcessPrng` → `SystemFunction036`), а не переизобретение. Заглушки-«no-op» допустимы там,
  где функция чисто косметическая (`Wer*`, `AddVectoredContinueHandler`,
  `SetThreadDescription`).
- Каждый полифилл — с комментарием: откуда семантика (ссылка на форк/MSDN), что деградирует.

### 3.5 Лицензии и заимствование

Заимствуем максимально: `go-legacy-win7` / `go-legacy-winxp` (BSD-3), сам Go (BSD-3),
`x/sys` (BSD-3) — всё совместимо с BSD-3 репозитория. В каждом заимствованном фрагменте —
комментарий с источником. Код GPL-патчеров (если встретится) — только как справка, не копировать.

---

## 4. Запасной план (если наблюдение 2 §2 не подтвердится)

Если окажется, что какой-то вызов идёт не через слот (например `CALL` в тело thunk'а),
резерв — `go build -overlay=overlay.json`: штатная подмена **отдельных файлов** рантайма
без правки GOROOT. Это «форк размером в один файл», хуже по поддержке, но не требует
патчить код. Решение принимается на шаге 3 по фактам, а не заранее.

---

## 5. План работ (атомарные шаги)

Правила игры: один шаг = один-два коммита (патчи для `git am`) + обновление `STATUS.md`
в том же коммите → **стоп, ждём подтверждения пользователя**. Не забегать вперёд.
Перед написанием кода с библиотеками/CLI — актуальная документация через Context7
(`resolve-library-id` → `query-docs`); если библиотеки там нет — сказать явно и искать в вебе.

| # | Шаг | Результат / DoD |
|---|---|---|
| 0 | ТЗ + STATUS + README, `go.mod` | этот коммит |
| 1 | `go2xp inspect app.exe`: PE-версии, полная таблица импортов (dll, name, RVA слота), `.reloc`-сводка; `go2xp exports kernel32.dll` для снятия эталона. Только `debug/pe` + свой код | запуск на hello-world с `GOARCH=386`; список импортов совпадает с §1.2 (или расхождения записаны в STATUS) |
| 2 | Пакет `shim` минимальный: собственные `cgo_import_dynamic`, таблица `GO2XPTBL`, keepalive, 1 тривиальный asm-полифилл (`WerSetFlags` → `return 0`). Патчер находит таблицу | `go build` проходит; `inspect` печатает таблицу и подтверждает, что shim получил **свой** слот `GetProcAddress` отдельно от рантаймовского |
| 3 | `go2xp patch`: заголовок + расщепление импортов + запись слотов + `verify` + новая секция. Профиль `xp.json` с 7 функциями из §1.2 и `bcryptprimitives.dll`. Полифиллы — пока заглушки | пропатченный hello-world **загружается** на XP (даже если сразу падает в `throw`). Baseline-скриншот — в STATUS |
| 3.5 | **Wine smoke test** (`scripts/wine-test.sh`): build probes → patch → verify → run under Wine with `winecfg /v winxp`. Catches malformed import tables, broken sections and stack-corrupting polyfills without a VM | `PASS` for every probe, patched and unpatched |
| 4 | Ранние asm-полифиллы: `LoadLibraryExW`-хук, `GetProcAddress`-хук, `ProcessPrng`, `GetErrorMode`, `AddVectoredContinueHandler`, `CreateWaitableTimerExW` (→0, штатный откат на winmm), `RaiseFailFastException`, `GetQueuedCompletionStatusEx` | `probes/hello` печатает `OK` на XP |
| 5 | Go-полифиллы (поздние): `CancelIoEx`, `*ProcThreadAttributeList*` + снятие флага в `CreateProcessW`, `GetTickCount64`, файловые `*ByHandle*` | `probes/exec`, `probes/files` — `OK` |
| 6 | Сеть/консоль: `probes/net` (http.Get, listen), `probes/console` (ReadConsoleInput, режимы) — чинить по логу | все пробники `OK` |
| 7 | CI: reusable GitHub Action (`go2xp-action`): build 386 → patch → verify → артефакт. Smoke-тест патчера в Linux CI (структурные проверки, без XP) | зелёный workflow в go2xp |
| 8 | Профиль `win7` (подмножество `xp`) — дёшево, раз всё есть | `verify` для win7 |
| 9 | f4: `import _ shim`, джоба `build-xp`; отдельно — Console-API бэкенд в f4 (вне этого ТЗ) | f4 стартует на XP |

---

## 6. Пробники (`probes/`)

Каждый — крошечный `main`, печатает `OK <имя>` и выходит с кодом 0; при ошибке — стек и код 1.
Логи писать и в stdout, и в файл рядом с exe (на XP консоль может закрыться).

- `hello` — только `fmt.Println` + `time.Sleep(10ms)` + горутина + `crypto/rand.Read`
  (задевает `ProcessPrng`, таймеры, netpoll не задевает).
- `files` — создать/прочитать/переименовать/удалить файл, `os.Stat`, `filepath.Walk`,
  `os.Getwd`, `os.UserHomeDir`.
- `exec` — `exec.Command("cmd", "/c", "echo hi").Output()`, пайпы, `os.Process.Wait`.
- `net` — `http.Get("http://example.com")` (без TLS), затем `https://` (задевает
  `crypto/x509` + `crypt32`), `net.Listen` + локальный клиент.
- `console` — `x/sys/windows` `GetConsoleMode/SetConsoleMode`, `ReadConsoleInputW`,
  `WriteConsoleOutputW` — то, что понадобится f4 на XP.
- `signals` — Ctrl+C через `os/signal`.

**Wine first, always.** Before anything is carried to a VM, run `scripts/wine-test.sh`.
Wine's loader is far more permissive than XP's (it exports Vista+ functions regardless of
the reported Windows version and does not enforce the PE subsystem version), so a pass
proves only that the binary is structurally sound and that the polyfills do not corrupt
the stack. A failure, however, is always a real bug, and finding it costs seconds instead
of a VM round-trip. What Wine cannot check: the PE version fields actually gating the
load, the real set of exports on XP SP3, and any XP-specific semantics.

Стенд: XP SP3 **x86**, VM (VirtualBox/86Box/VMware). Перенос файлов — общая папка/ISO.
Отдельно проверить, что `ntdll`/`kernel32` — оригинальные (не One-Core-API/расширенное
ядро), иначе результаты бессмысленны.

---

## 7. Референсы

- `runtime/os_windows.go` (Go tip) — актуальный список `cgo_import_dynamic` и логика
  `loadOptionalSyscalls`/`initHighResTimer` (откат на winmm при отсутствии `CreateWaitableTimerExW`).
- `thongtech/go-legacy-win7`, `syncguy/go-legacy-winxp` (ветка `winxp-compat`, 4 коммита
  поверх 1.24.4) — какие функции ломаются и как их обходили; нам нужны **фоллбэки**, не сами патчи.
- Старое ТЗ и патчи `0001..0004` из предыдущей попытки (см. `docs/prior-attempt/`, если
  будут закоммичены) — таблица «символ → что делать при отсутствии».
- `golang.org/x/sys/unix` (Solaris) — образец `cgo_import_dynamic` + `linkname` в
  стороннем пакете.
- `runtime/sys_windows_386.s` — образец stdcall-asm (`asmstdcall`, `callbackasm1`, `sigtramp`).
- MS PE/COFF spec — импорт-описатели, `.reloc`, `DllCharacteristics`.

### 7.1 Сверка перед релизом (обязательный чек-лист)

Перед первым релизом сверить **каждый** наш полифилл и список профиля с:
- https://github.com/thongtech/go-legacy-win7 — Go 1.26.6 на Win7 (эталон для профиля `win7`);
- https://github.com/syncguy/go-legacy-winxp — Go 1.24 на XP, ветка `winxp-compat` (эталон для `xp`);
- проекты бинарного патчинга Win7→XP из предыдущей попытки:
  - https://github.com/syncguy/go-legacy-winxp
  - https://github.com/thongtech/go-legacy-win7

Что сверять: (1) полный список функций, которые они подменяют/резолвят лениво — у нас не должно быть пропусков;
(2) семантика фоллбэков (что возвращают, какие LastError); (3) правки PE-заголовка. Расхождения — в STATUS.

---

## 8. Риски и открытые вопросы (закрываются по ходу, ответы — в STATUS)

1. Разрешит ли компилятор `cgo_import_dynamic` с `"kernel32.dll"` в стороннем пакете на
   **windows** (проверка `safeArg` имени библиотеки) — шаг 2.
2. Не сольёт ли линкер два одноимённых импорта (рантайма и shim'а) в один слот — шаг 2.
3. Поддерживает ли ассемблер Go для 386 `RET $n`; если нет — эпилог руками
   (`POPL AX; ADDL $n, SP; JMP AX`) — шаг 2.
4. Загрузчик XP и несколько описателей одной DLL / новая секция импорта — шаг 3.
5. `NewCallback` из контекста `syscall.Syscall` (реентерабельность рантайма) — шаг 5.
6. `.reloc`: при снятом `DYNAMIC_BASE` не нужен; если решим оставить ASLR для win7 —
   добавить записи для перезаписанных слотов.
