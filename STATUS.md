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
| 3 | `go2xp patch` + `verify`, профиль xp | [~] реализовано и протестировано структурно; ждёт подтверждения + запуска на XP |
| 4 | ранние asm-полифиллы, `probes/hello` | [ ] |
| 5 | Go-полифиллы, `probes/exec`, `probes/files` | [ ] |
| 6 | `probes/net`, `probes/console`, `probes/signals` | [ ] |
| 7 | CI / reusable action | [ ] |
| 8 | профиль win7 | [ ] |
| 9 | f4 showcase | [ ] |

## Открытые вопросы (из SPEC §8)

| # | Вопрос | Ответ | Где проверено |
|---|---|---|---|
| 1 | `cgo_import_dynamic "kernel32.dll"` в стороннем пакете | **да**, компилируется и даёт IAT-слот | шаг 2, `shim/shim_windows_386.go` |
| 2 | два одноимённых импорта → два слота? | **да**, линкер не сливает (даже сам рантайм импортирует `GetProcAddress` дважды) | шаг 1/2, вывод `inspect` |
| 3 | `RET $n` в asm 386 | **нет** («invalid instruction»); используем `BYTE $0xC2; WORD $n` (макрос `STDRET`), objdump показывает `RET $0x4` | шаг 2 |
| 4 | XP-загрузчик и расщеплённые описатели импорта | описатель расщепляется на несколько при вырезании слота из середины; результат читается штатным `debug/pe` (`ImportedSymbols` ok). Проверку живым загрузчиком XP — на стенде | шаг 3 |
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
