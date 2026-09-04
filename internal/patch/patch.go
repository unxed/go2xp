// Package patch реализует go2xp patch/verify: правит PE-заголовок под старую ОС,
// перенаправляет IAT-слоты отсутствующих функций на полифиллы shim и удаляет их
// из таблицы импорта, чтобы загрузчик не искал их в системных DLL.
package patch

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"sort"

	xpe "github.com/unxed/go2xp/internal/pe"
)

// Profile — профиль целевой ОС (profiles/*.json).
type Profile struct {
	Name            string              `json:"name"`
	OSMajor         uint16              `json:"osMajor"`
	OSMinor         uint16              `json:"osMinor"`
	SubsystemMajor  uint16              `json:"subsystemMajor"`
	SubsystemMinor  uint16              `json:"subsystemMinor"`
	Missing         map[string][]string `json:"missing"`
	MissingWholeDLL []string            `json:"missingWholeDLL"`
}

func LoadProfile(path string) (*Profile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p := &Profile{}
	if err := json.Unmarshal(b, p); err != nil {
		return nil, err
	}
	if p.SubsystemMajor == 0 {
		return nil, fmt.Errorf("profile %q: subsystemMajor is zero", path)
	}
	return p, nil
}

func (p *Profile) missing(dll, fn string) bool {
	for _, w := range p.MissingWholeDLL {
		if eqFold(w, dll) {
			return true
		}
	}
	for _, m := range p.Missing[dll] {
		if m == fn {
			return true
		}
	}
	return false
}

func eqFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 32
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 32
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// Result — что сделал патчер (для отчёта и verify).
type Result struct {
	Redirected  []string // dll!func -> polyfill
	KeptImports int
	DroppedDLLs []string
}

// Patch патчит файл на месте (in path -> out path).
func Patch(inPath, outPath, profilePath string) (*Result, error) {
	prof, err := LoadProfile(profilePath)
	if err != nil {
		return nil, err
	}
	info, err := xpe.Open(inPath)
	if err != nil {
		return nil, err
	}
	if len(info.Table) == 0 {
		return nil, fmt.Errorf("GO2XPTBL not found: the shim package is not linked into %s (add: import _ \"github.com/unxed/go2xp/shim\")", inPath)
	}
	// карта полифиллов: dll!func -> VA; и множество собственных слотов shim.
	poly := map[string]uint32{}
	ownSlot := map[uint32]bool{}
	for _, e := range info.Table {
		if e.Polyfill != 0 {
			poly[key(e.DLL, e.Func)] = e.Polyfill
		}
		if e.OwnSlot != 0 {
			ownSlot[e.OwnSlot] = true // VA
		}
	}

	raw, err := os.ReadFile(inPath)
	if err != nil {
		return nil, err
	}
	r, err := xpe.OpenRaw(raw)
	if err != nil {
		return nil, err
	}

	res := &Result{}
	// 1) заголовок
	r.SetVersions(prof.OSMajor, prof.OSMinor, prof.SubsystemMajor, prof.SubsystemMinor)
	r.ClearDynamicBase()
	r.ZeroCheckSum()

	// 2) пройти импорты, для отсутствующих: записать VA полифилла в слот (в файле),
	//    пометить слот как «убрать из таблицы импорта».
	imageBase := info.ImageBase
	badSlots := map[uint32]bool{} // slotRVA, которые надо исключить из перестроенной таблицы
	for _, im := range info.Imports {
		slotVA := imageBase + im.SlotRVA
		if ownSlot[slotVA] {
			continue // это слот самого shim — не трогаем
		}
		fn := im.Name
		redirect := false
		var pva uint32
		switch {
		case prof.missing(im.DLL, fn):
			// нужен полифилл. Для отсутствующей целиком DLL — тоже ищем полифилл по имени.
			if v, ok := poly[key(im.DLL, fn)]; ok {
				pva, redirect = v, true
			} else {
				// критично для функций, которые реально зовутся; но заглушку может
				// не быть на раннем этапе. Пишем 0-заглушку? Нет — это опасно.
				return nil, fmt.Errorf("%s!%s is missing on target %q but no polyfill is present in the shim table", im.DLL, fn, prof.Name)
			}
		case forceHook(im.DLL, fn):
			// GetProcAddress/LoadLibraryExW рантайма — на хук, НО только когда
			// соответствующий полифилл-хук уже есть в таблице (появится на шаге 4).
			// Иначе оставляем импорт как есть: сама функция на XP присутствует.
			if v, ok := poly[key(im.DLL, fn)]; ok {
				pva, redirect = v, true
			}
		}
		if redirect {
			off, ok := r.FileOff(im.SlotRVA)
			if !ok {
				return nil, fmt.Errorf("slot RVA %#x not mapped to file", im.SlotRVA)
			}
			binary.LittleEndian.PutUint32(r.Buf[off:], pva)
			badSlots[im.SlotRVA] = true
			res.Redirected = append(res.Redirected, fmt.Sprintf("%s!%s -> %#08x", im.DLL, fn, pva))
		}
	}

	// 3) перестроить таблицу импорта без bad-слотов, положить в новую секцию .go2xp
	newImp, dropped, kept, err := rebuildImports(r, info, badSlots)
	if err != nil {
		return nil, err
	}
	res.DroppedDLLs = dropped
	res.KeptImports = kept

	newRVA, err := r.AddSection(".go2xp", newImp, xpe.SCN_CNT_INIT_DATA|xpe.SCN_MEM_READ|xpe.SCN_MEM_WRITE)
	if err != nil {
		return nil, err
	}
	// DataDirectory[IMPORT] -> новая таблица описателей (в начале секции)
	r.SetDataDir(1, newRVA, uint32(descBytesLen))
	// IAT-директорию (12) обнуляем как размер, чтобы загрузчик не ругался на несоответствие; RVA оставим.
	// (не критично; XP не строг)

	if err := os.WriteFile(outPath, r.Buf, 0o755); err != nil {
		return nil, err
	}
	sort.Strings(res.Redirected)
	return res, nil
}

func forceHook(dll, fn string) bool {
	return eqFold(dll, "kernel32.dll") && (fn == "GetProcAddress" || fn == "LoadLibraryExW")
}

func key(dll, fn string) string { return dll + "!" + fn }

var descBytesLen int // длина блока IMAGE_IMPORT_DESCRIPTOR[], заполняется в rebuildImports

// rebuildImports собирает новую таблицу импорта, исключая badSlots.
// Возвращает байты секции: [descriptors][INT arrays][name strings], с RVA-ссылками,
// рассчитанными относительно места, куда AddSection положит секцию. Так как RVA
// секции ещё не известен на этом шаге, ссылки пишем как смещения и правим после
// размещения — поэтому rebuild работает в два прохода через placeholder + фиксап.
func rebuildImports(r *xpe.Raw, info *xpe.Info, badSlots map[uint32]bool) (section []byte, droppedDLLs []string, kept int, err error) {
	// сгруппировать импорты по описателю (dll), сохранить порядок слотов.
	type imp struct {
		name string
		ord  uint16
		slot uint32
	}
	type grp struct {
		dll   string
		ftRVA uint32 // FirstThunk оригинала — оставляем как есть, слоты уже на месте
		imps  []imp
	}
	var groups []*grp
	byDesc := map[int]*grp{}
	for _, im := range info.Imports {
		g := byDesc[im.DescIdx]
		if g == nil {
			g = &grp{dll: im.DLL}
			byDesc[im.DescIdx] = g
			groups = append(groups, g)
		}
		if badSlots[im.SlotRVA] {
			continue // исключаем
		}
		if len(g.imps) == 0 {
			// FirstThunk этой (под)группы = RVA первого сохранённого слота
			g.ftRVA = im.SlotRVA
		}
		g.imps = append(g.imps, imp{im.Name, im.Ordinal, im.SlotRVA})
	}

	// Проблема: если внутри одной DLL bad-слот стоит В СЕРЕДИНЕ, оставшиеся слоты
	// не непрерывны -> одного FirstThunk мало, нужно расщепление на несколько
	// описателей с непрерывными участками. Реализуем расщепление по непрерывности.
	type piece struct {
		dll   string
		ftRVA uint32
		names []imp // только именованные, в порядке; для INT
	}
	var pieces []piece
	for _, g := range groups {
		if len(g.imps) == 0 {
			droppedDLLs = append(droppedDLLs, g.dll)
			continue
		}
		// разбить g.imps на непрерывные по slot (шаг 4 байта) серии
		start := 0
		for i := 1; i <= len(g.imps); i++ {
			if i == len(g.imps) || g.imps[i].slot != g.imps[i-1].slot+4 {
				seg := g.imps[start:i]
				pieces = append(pieces, piece{dll: g.dll, ftRVA: seg[0].slot, names: seg})
				start = i
			}
		}
	}

	// Разметка секции: [N+1 дескрипторов по 20][для каждого piece: INT (k+1)*4][имена].
	// Все *RVA* абсолютные (в терминах RVA образа) — их можно вычислить только зная
	// RVA секции. AddSection кладёт секцию в конец; вычислим её RVA заранее тем же
	// способом, что и AddSection, чтобы проставить корректные RVA сразу.
	secRVA := plannedSectionRVA(r)

	nDesc := len(pieces)
	descBytesLen = (nDesc + 1) * 20
	// сначала посчитать layout
	intOff := descBytesLen
	// зарезервировать INT
	intSizes := make([]int, len(pieces))
	cur := intOff
	intStart := make([]int, len(pieces))
	for i, p := range pieces {
		intStart[i] = cur
		intSizes[i] = (len(p.names) + 1) * 4
		cur += intSizes[i]
	}
	nameStart := cur
	// собрать строки: имя DLL + IMAGE_IMPORT_BY_NAME для каждого именованного импорта
	buf := make([]byte, nameStart)
	// имена DLL
	dllNameOff := map[string]int{}
	appendStr := func(s string) int {
		off := len(buf)
		buf = append(buf, s...)
		buf = append(buf, 0)
		if len(buf)%2 == 1 {
			buf = append(buf, 0)
		}
		return off
	}
	for _, p := range pieces {
		if _, ok := dllNameOff[p.dll]; !ok {
			dllNameOff[p.dll] = appendStr(p.dll)
		}
	}
	// IMAGE_IMPORT_BY_NAME: hint(2)+name; запомнить offset для INT
	nameEntryOff := map[string]int{}
	for _, p := range pieces {
		for _, im := range p.names {
			if im.name == "" {
				continue
			}
			if _, ok := nameEntryOff[im.name]; !ok {
				off := len(buf)
				buf = append(buf, 0, 0) // hint
				buf = append(buf, im.name...)
				buf = append(buf, 0)
				if len(buf)%2 == 1 {
					buf = append(buf, 0)
				}
				nameEntryOff[im.name] = off
			}
		}
	}

	rva := func(off int) uint32 { return secRVA + uint32(off) }

	// заполнить дескрипторы и INT
	for i, p := range pieces {
		d := i * 20
		binary.LittleEndian.PutUint32(buf[d:], rva(intStart[i])) // OriginalFirstThunk -> наш INT
		binary.LittleEndian.PutUint32(buf[d+4:], 0)              // TimeDateStamp
		binary.LittleEndian.PutUint32(buf[d+8:], 0)              // ForwarderChain
		binary.LittleEndian.PutUint32(buf[d+12:], rva(dllNameOff[p.dll]))
		binary.LittleEndian.PutUint32(buf[d+16:], p.ftRVA) // FirstThunk = существующий IAT
		// INT
		io := intStart[i]
		for j, im := range p.names {
			var v uint32
			if im.name == "" {
				v = 0x80000000 | uint32(im.ord)
			} else {
				v = rva(nameEntryOff[im.name])
			}
			binary.LittleEndian.PutUint32(buf[io+j*4:], v)
			kept++
		}
		binary.LittleEndian.PutUint32(buf[io+len(p.names)*4:], 0) // терминатор INT
	}
	// последний дескриптор — нулевой (уже нули)
	return buf, droppedDLLs, kept, nil
}

// plannedSectionRVA повторяет расчёт RVA новой секции из AddSection БЕЗ модификации.
func plannedSectionRVA(r *xpe.Raw) uint32 {
	var maxRVAEnd uint32
	sa := r.SectAlign()
	for _, s := range r.Sections() {
		if e := s.VirtualAddress + alignUp(s.VirtualSize, sa); e > maxRVAEnd {
			maxRVAEnd = e
		}
	}
	return alignUp(maxRVAEnd, sa)
}

func alignUp(v, a uint32) uint32 {
	if a == 0 {
		return v
	}
	return (v + a - 1) &^ (a - 1)
}
