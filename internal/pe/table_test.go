package pe

import (
	"debug/pe"
	"encoding/binary"
	"testing"
)

func TestTableIgnoresMagicInProgramStrings(t *testing.T) {
	raw := make([]byte, 256)
	copy(raw, "GO2XPTBL not found in executable")
	copy(raw[64:], tableMagic)
	put := func(off int, v uint32) { binary.LittleEndian.PutUint32(raw[off:], v) }
	put(72, 1)
	put(76, 1)
	put(80, 0x401080)
	put(84, 0x4010a0)
	put(88, 0x4010c0)
	copy(raw[128:], "kernel32.dll\x00")
	copy(raw[160:], "GetErrorMode\x00")
	r := &reader{raw: raw, f: &pe.File{Sections: []*pe.Section{{SectionHeader: pe.SectionHeader{
		VirtualAddress: 0x1000, VirtualSize: 256, Size: 256,
	}}}}}
	table, err := r.table(0x400000)
	if err != nil || len(table) != 1 || table[0].Func != "GetErrorMode" {
		t.Fatalf("table = %v, %v", table, err)
	}
}

func TestTableTruncatedMagicDoesNotPanic(t *testing.T) {
	for _, suffix := range []string{"", "\x01", "\x01\x00\x00\x00", "\x01\x00\x00\x00\xff\xff\xff\xff"} {
		r := &reader{raw: []byte(tableMagic + suffix), f: &pe.File{}}
		if table, _ := r.table(0x400000); len(table) != 0 {
			t.Fatalf("truncated candidate produced %v", table)
		}
	}
}
