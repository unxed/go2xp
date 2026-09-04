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
| 2 | `shim` минимальный + таблица GO2XPTBL | [~] ждёт подтверждения |
| 3 | `go2xp patch` + `verify`, профиль xp | [ ] |
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
| 4 | XP-загрузчик и расщеплённые описатели импорта | — | — |
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
- Baseline: текст ошибки при запуске непропатченного exe на XP: *шаг 3*

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
