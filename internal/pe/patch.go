package pe

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
)

// Raw gives write access to the raw bytes and to the header offsets we care about.
type Raw struct {
	Buf          []byte
	peOff        int // offset of the "PE\0\0" signature
	optOff       int // offset of the optional header
	numSections  int
	sectAlign    uint32
	fileAlign    uint32
	imageBase    uint32
	sizeOfImage  uint32
	firstSectOff int // offset of the first section header
}

// OpenRaw parses the minimum needed to write to the image (PE32 only).
func OpenRaw(buf []byte) (*Raw, error) {
	if len(buf) < 0x40 {
		return nil, fmt.Errorf("too small")
	}
	peOff := int(binary.LittleEndian.Uint32(buf[0x3c:]))
	if peOff+24 > len(buf) || string(buf[peOff:peOff+4]) != "PE\x00\x00" {
		return nil, fmt.Errorf("bad PE signature")
	}
	fileHdr := peOff + 4
	nSect := int(binary.LittleEndian.Uint16(buf[fileHdr+2:]))
	optSize := int(binary.LittleEndian.Uint16(buf[fileHdr+16:]))
	optOff := fileHdr + 20
	magic := binary.LittleEndian.Uint16(buf[optOff:])
	if magic != 0x10b {
		return nil, fmt.Errorf("only PE32 (0x10b) supported, got %#x", magic)
	}
	r := &Raw{
		Buf: buf, peOff: peOff, optOff: optOff, numSections: nSect,
		sectAlign:    binary.LittleEndian.Uint32(buf[optOff+32:]),
		fileAlign:    binary.LittleEndian.Uint32(buf[optOff+36:]),
		imageBase:    binary.LittleEndian.Uint32(buf[optOff+28:]),
		sizeOfImage:  binary.LittleEndian.Uint32(buf[optOff+56:]),
		firstSectOff: optOff + optSize,
	}
	return r, nil
}

// header field offsets within the PE32 optional header
const (
	ohMajorOS     = 40
	ohMinorOS     = 42
	ohMajorSubsys = 48
	ohMinorSubsys = 50
	ohCheckSum    = 64
	ohDllChar     = 70
	ohDataDir     = 96 // start of DataDirectory[16], each 8 bytes (RVA,size)
)

func (r *Raw) u16(off int) uint16       { return binary.LittleEndian.Uint16(r.Buf[off:]) }
func (r *Raw) u32(off int) uint32       { return binary.LittleEndian.Uint32(r.Buf[off:]) }
func (r *Raw) setU16(off int, v uint16) { binary.LittleEndian.PutUint16(r.Buf[off:], v) }
func (r *Raw) setU32(off int, v uint32) { binary.LittleEndian.PutUint32(r.Buf[off:], v) }

// SetVersions writes the OS and subsystem version fields.
func (r *Raw) SetVersions(osMaj, osMin, subMaj, subMin uint16) {
	r.setU16(r.optOff+ohMajorOS, osMaj)
	r.setU16(r.optOff+ohMinorOS, osMin)
	r.setU16(r.optOff+ohMajorSubsys, subMaj)
	r.setU16(r.optOff+ohMinorSubsys, subMin)
}

// ClearDynamicBase drops ASLR and high-entropy so that slots can hold absolute VAs
// (XP would not relocate an exe anyway). It returns the previous value.
func (r *Raw) ClearDynamicBase() uint16 {
	off := r.optOff + ohDllChar
	old := r.u16(off)
	const dyn = 0x0040
	const highEntropy = 0x0020
	r.setU16(off, old&^(dyn|highEntropy))
	return old
}

// ZeroCheckSum clears CheckSum, which is valid for anything but drivers and boot images.
func (r *Raw) ZeroCheckSum() { r.setU32(r.optOff+ohCheckSum, 0) }

func (r *Raw) DataDir(i int) (rva, size uint32) {
	o := r.optOff + ohDataDir + i*8
	return r.u32(o), r.u32(o + 4)
}
func (r *Raw) SetDataDir(i int, rva, size uint32) {
	o := r.optOff + ohDataDir + i*8
	r.setU32(o, rva)
	r.setU32(o+4, size)
}

// Section is a raw section header.
type Section struct {
	Name                        string
	VirtualSize, VirtualAddress uint32
	RawSize, RawPtr             uint32
	Characteristics             uint32
	hdrOff                      int
}

func (r *Raw) Sections() []Section {
	out := make([]Section, r.numSections)
	for i := 0; i < r.numSections; i++ {
		o := r.firstSectOff + i*40
		out[i] = Section{
			Name:            cstr8(r.Buf[o : o+8]),
			VirtualSize:     r.u32(o + 8),
			VirtualAddress:  r.u32(o + 12),
			RawSize:         r.u32(o + 16),
			RawPtr:          r.u32(o + 20),
			Characteristics: r.u32(o + 36),
			hdrOff:          o,
		}
	}
	return out
}

func cstr8(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// FileOff maps an RVA to a file offset using the section table.
func (r *Raw) FileOff(rva uint32) (int, bool) {
	for _, s := range r.Sections() {
		if rva >= s.VirtualAddress && rva < s.VirtualAddress+alignUp(s.VirtualSize, r.sectAlign) {
			return int(rva - s.VirtualAddress + s.RawPtr), true
		}
	}
	return 0, false
}

func alignUp(v, a uint32) uint32 {
	if a == 0 {
		return v
	}
	return (v + a - 1) &^ (a - 1)
}

// AddSection appends a section holding data at the end of the image and of the file.
// It needs 40 spare bytes of header padding for one more section header.
// It returns the RVA of the new section.
func (r *Raw) AddSection(name string, data []byte, characteristics uint32) (uint32, error) {
	secs := r.Sections()
	// make sure 40 free bytes follow the last section header
	lastHdrEnd := r.firstSectOff + r.numSections*40
	firstRaw := int(^uint32(0))
	var maxRVAEnd, maxRawEnd uint32
	for _, s := range secs {
		if int(s.RawPtr) < firstRaw && s.RawSize > 0 {
			firstRaw = int(s.RawPtr)
		}
		if e := s.VirtualAddress + alignUp(s.VirtualSize, r.sectAlign); e > maxRVAEnd {
			maxRVAEnd = e
		}
		if e := s.RawPtr + s.RawSize; e > maxRawEnd {
			maxRawEnd = e
		}
	}
	if lastHdrEnd+40 > firstRaw {
		return 0, fmt.Errorf("no room for a new section header (need 40 bytes of header padding)")
	}
	newRVA := alignUp(maxRVAEnd, r.sectAlign)
	newRaw := alignUp(maxRawEnd, r.fileAlign)
	rawSize := alignUp(uint32(len(data)), r.fileAlign)

	// append the data; the file has to grow physically
	if int(newRaw)+int(rawSize) > len(r.Buf) {
		r.Buf = append(r.Buf, make([]byte, int(newRaw)+int(rawSize)-len(r.Buf))...)
	}
	copy(r.Buf[newRaw:], data)

	// write the section header
	o := lastHdrEnd
	var nb [8]byte
	copy(nb[:], name)
	copy(r.Buf[o:o+8], nb[:])
	r.setU32(o+8, uint32(len(data))) // VirtualSize
	r.setU32(o+12, newRVA)
	r.setU32(o+16, rawSize)
	r.setU32(o+20, newRaw)
	r.setU32(o+24, 0)
	r.setU32(o+28, 0)
	r.setU16(o+32, 0)
	r.setU16(o+34, 0)
	r.setU32(o+36, characteristics)

	r.numSections++
	r.setU16(r.peOff+4+2, uint16(r.numSections))
	r.setU32(r.optOff+56, alignUp(newRVA+alignUp(uint32(len(data)), r.sectAlign), r.sectAlign)) // SizeOfImage
	return newRVA, nil
}

// section characteristics
const (
	SCN_CNT_INIT_DATA = 0x00000040
	SCN_MEM_READ      = 0x40000000
	SCN_MEM_WRITE     = 0x80000000
)

var _ = pe.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE

// SectAlign returns the image's SectionAlignment.
func (r *Raw) SectAlign() uint32 { return r.sectAlign }
