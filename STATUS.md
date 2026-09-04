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
| 1 | `go2xp inspect` / `exports` | [~] написано, НЕ проверено на реальном exe |
| 2 | `shim` минимальный + таблица GO2XPTBL | [ ] |
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
| 1 | `cgo_import_dynamic "kernel32.dll"` в стороннем пакете | — | — |
| 2 | два одноимённых импорта → два слота? | — | — |
| 3 | `RET $n` в asm 386 | — | — |
| 4 | XP-загрузчик и расщеплённые описатели импорта | — | — |
| 5 | `NewCallback` изнутри `syscall.Syscall` | — | — |
| 6 | `.reloc` при снятом DYNAMIC_BASE | — | — |

## Фактические данные (заполнять по мере получения)

- Список статических импортов hello-world (Go 1.26.6, 386): *шаг 1*
- Эталон экспортов XP SP3 (`profiles/exports-xp-sp3.txt`): *шаг 1*
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
