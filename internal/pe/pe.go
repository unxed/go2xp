// Package pe: чтение PE поверх debug/pe там, где стандартного пакета не хватает
// (RVA слотов IAT, таблица экспорта, версии заголовка). Только 32-битные образы (v1).
package pe

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"
)

// Import — одна запись таблицы импорта.
type Import struct {
	DLL     string
	Name    string // пусто, если по ординалу
	Ordinal uint16
	SlotRVA uint32 // RVA слота IAT (FirstThunk[i])
	DescIdx int    // индекс IMAGE_IMPORT_DESCRIPTOR
}

// Info — сводка по образу.
type Info struct {
	Machine                                    uint16
	OSMajor, OSMinor, SubsysMajor, SubsysMinor uint16
	DllCharacteristics                         uint16
	ImageBase                                  uint32
	ImportDirRVA, ImportDirSize                uint32
	HasReloc                                   bool
	Sections                                   []string
	Imports                                    []Import
	Table                                      []TableEntry // GO2XPTBL, nil if shim not linked in
}

// TableEntry — запись GO2XPTBL из пакета shim (см. shim/shim_windows_386.s).
type TableEntry struct {
	DLL, Func string
	Polyfill  uint32 // VA полифилла, 0 если запись только помечает собственный слот
	OwnSlot   uint32 // VA собственного IAT-слота shim (не трогать), 0 если нет
}

const tableMagic = "GO2XPTBL"

const (
	dirExport = 0
	dirImport = 1
	dirReloc  = 5
)

// Open читает файл и собирает Info.
func Open(path string) (*Info, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	f, err := pe.NewFile(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	oh, ok := f.OptionalHeader.(*pe.OptionalHeader32)
	if !ok {
		return nil, fmt.Errorf("only PE32 (386) images are supported in v1")
	}
	in := &Info{
		Machine: f.Machine, OSMajor: oh.MajorOperatingSystemVersion, OSMinor: oh.MinorOperatingSystemVersion,
		SubsysMajor: oh.MajorSubsystemVersion, SubsysMinor: oh.MinorSubsystemVersion,
		DllCharacteristics: oh.DllCharacteristics, ImageBase: oh.ImageBase,
		ImportDirRVA: oh.DataDirectory[dirImport].VirtualAddress, ImportDirSize: oh.DataDirectory[dirImport].Size,
		HasReloc: oh.DataDirectory[dirReloc].Size != 0,
	}
	for _, s := range f.Sections {
		in.Sections = append(in.Sections, s.Name)
	}
	r := &reader{raw: raw, f: f}
	if in.ImportDirRVA != 0 {
		in.Imports, err = r.imports(in.ImportDirRVA)
		if err != nil {
			return nil, err
		}
	}
	if in.Table, err = r.table(in.ImageBase); err != nil {
		return nil, err
	}
	return in, nil
}

// table ищет GO2XPTBL сырым сканом файла и разбирает записи.
func (r *reader) table(imageBase uint32) ([]TableEntry, error) {
	o := bytes.Index(r.raw, []byte(tableMagic))
	if o < 0 {
		return nil, nil
	}
	if binary.LittleEndian.Uint32(r.raw[o+8:]) != 1 {
		return nil, fmt.Errorf("unsupported GO2XPTBL version")
	}
	n := int(binary.LittleEndian.Uint32(r.raw[o+12:]))
	var out []TableEntry
	for i := 0; i < n; i++ {
		e := r.raw[o+16+i*16:]
		dll, err := r.cstr(binary.LittleEndian.Uint32(e) - imageBase)
		if err != nil {
			return nil, fmt.Errorf("GO2XPTBL entry %d: %w", i, err)
		}
		fn, err := r.cstr(binary.LittleEndian.Uint32(e[4:]) - imageBase)
		if err != nil {
			return nil, fmt.Errorf("GO2XPTBL entry %d: %w", i, err)
		}
		out = append(out, TableEntry{DLL: dll, Func: fn,
			Polyfill: binary.LittleEndian.Uint32(e[8:]), OwnSlot: binary.LittleEndian.Uint32(e[12:])})
	}
	return out, nil
}

type reader struct {
	raw []byte
	f   *pe.File
}

// off переводит RVA в смещение в файле.
func (r *reader) off(rva uint32) (int, error) {
	for _, s := range r.f.Sections {
		if rva >= s.VirtualAddress && rva < s.VirtualAddress+s.VirtualSize {
			return int(rva - s.VirtualAddress + s.Offset), nil
		}
	}
	return 0, fmt.Errorf("RVA %#x not in any section", rva)
}

func (r *reader) u32(rva uint32) (uint32, error) {
	o, err := r.off(rva)
	if err != nil || o+4 > len(r.raw) {
		return 0, fmt.Errorf("bad RVA %#x", rva)
	}
	return binary.LittleEndian.Uint32(r.raw[o:]), nil
}

func (r *reader) cstr(rva uint32) (string, error) {
	o, err := r.off(rva)
	if err != nil {
		return "", err
	}
	e := bytes.IndexByte(r.raw[o:], 0)
	if e < 0 {
		return "", fmt.Errorf("unterminated string at %#x", rva)
	}
	return string(r.raw[o : o+e]), nil
}

func (r *reader) imports(dir uint32) ([]Import, error) {
	var out []Import
	for idx := 0; ; idx++ {
		d := dir + uint32(idx)*20
		oft, err := r.u32(d)
		if err != nil {
			return nil, err
		}
		nameRVA, _ := r.u32(d + 12)
		ft, _ := r.u32(d + 16)
		if oft == 0 && nameRVA == 0 && ft == 0 {
			break
		}
		dll, err := r.cstr(nameRVA)
		if err != nil {
			return nil, err
		}
		lookup := oft
		if lookup == 0 { // нет INT — читаем имена из IAT (до загрузки там те же значения)
			lookup = ft
		}
		for i := uint32(0); ; i++ {
			v, err := r.u32(lookup + i*4)
			if err != nil {
				return nil, err
			}
			if v == 0 {
				break
			}
			im := Import{DLL: dll, SlotRVA: ft + i*4, DescIdx: idx}
			if v&0x80000000 != 0 {
				im.Ordinal = uint16(v)
			} else {
				if im.Name, err = r.cstr(v + 2); err != nil { // IMAGE_IMPORT_BY_NAME: hint(2) + name
					return nil, err
				}
			}
			out = append(out, im)
		}
	}
	return out, nil
}

// Exports возвращает имена экспортов DLL (для снятия эталона с живой XP).
func Exports(path string) ([]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	f, err := pe.NewFile(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	oh, ok := f.OptionalHeader.(*pe.OptionalHeader32)
	if !ok {
		return nil, fmt.Errorf("only PE32 DLLs are supported")
	}
	dir := oh.DataDirectory[dirExport].VirtualAddress
	if dir == 0 {
		return nil, fmt.Errorf("no export table")
	}
	r := &reader{raw: raw, f: f}
	nNames, err := r.u32(dir + 24)
	if err != nil {
		return nil, err
	}
	namesRVA, _ := r.u32(dir + 32)
	var out []string
	for i := uint32(0); i < nNames; i++ {
		p, err := r.u32(namesRVA + i*4)
		if err != nil {
			return nil, err
		}
		s, err := r.cstr(p)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}
