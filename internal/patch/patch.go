// Package patch implements go2xp patch and verify: it rewrites the PE header for an
// older Windows, redirects the IAT slots of missing functions to the shim polyfills and
// removes those slots from the import table so the loader never looks them up.
package patch

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"sort"

	xpe "github.com/unxed/go2xp/internal/pe"
)

// Profile describes a target OS (profiles/*.json).
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

// Result reports what the patcher did.
type Result struct {
	Redirected  []string // dll!func -> polyfill
	KeptImports int
	DroppedDLLs []string
}

// Patch reads inPath, patches it and writes outPath.
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
	// polyfill map (dll!func -> VA) and the set of the shim's own slots
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
	// 1) header
	r.SetVersions(prof.OSMajor, prof.OSMinor, prof.SubsystemMajor, prof.SubsystemMinor)
	r.ClearDynamicBase()
	r.ZeroCheckSum()

	// 2) walk the imports; for the missing ones write the polyfill VA into the slot
	//    and mark the slot for removal from the import table
	imageBase := info.ImageBase
	badSlots := map[uint32]bool{} // slot RVAs to leave out of the rebuilt table
	for _, im := range info.Imports {
		slotVA := imageBase + im.SlotRVA
		if ownSlot[slotVA] {
			continue // the shim's own slot: never touch it
		}
		fn := im.Name
		redirect := false
		var pva uint32
		switch {
		case prof.missing(im.DLL, fn):
			// A polyfill is required; for a wholly missing DLL we look it up by name too.
			if v, ok := poly[key(im.DLL, fn)]; ok {
				pva, redirect = v, true
			} else {
				// Refuse rather than leave a slot pointing at nothing: a null slot
				// would crash at the first call instead of failing the build.
				return nil, fmt.Errorf("%s!%s is missing on target %q but no polyfill is present in the shim table", im.DLL, fn, prof.Name)
			}
		case forceHook(im.DLL, fn):
			// The runtime's GetProcAddress/LoadLibraryExW go to our hooks, but only
			// once those hooks exist in the table (step 4). Until then the import is
			// left alone: the functions themselves do exist on XP.
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

	// 3) rebuild the import table without the bad slots into a new .go2xp section
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
	// DataDirectory[IMPORT] -> the new descriptor array at the start of the section
	r.SetDataDir(1, newRVA, uint32(descBytesLen))
	// DataDirectory[IAT] (12) is left as it was. The loader walks the import
	// descriptors, not that directory; only stdlib helpers such as
	// debug/pe.ImportedLibraries read it. See STATUS.md for the follow-up.

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

var descBytesLen int // size of the IMAGE_IMPORT_DESCRIPTOR array, set by rebuildImports

// rebuildImports builds a new import table that leaves out badSlots. It returns the
// section bytes laid out as [descriptors][INT arrays][name strings]. Internal RVAs are
// computed up front from plannedSectionRVA, which mirrors the placement AddSection
// will perform, so no fixup pass is needed afterwards.
func rebuildImports(r *xpe.Raw, info *xpe.Info, badSlots map[uint32]bool) (section []byte, droppedDLLs []string, kept int, err error) {
	// group imports by descriptor (one DLL each), keeping the slot order
	type imp struct {
		name string
		ord  uint16
		slot uint32
	}
	type grp struct {
		dll   string
		ftRVA uint32 // original FirstThunk: kept as is, the slots stay where they are
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
			continue // dropped
		}
		if len(g.imps) == 0 {
			// FirstThunk of this (sub)group is the RVA of its first surviving slot
			g.ftRVA = im.SlotRVA
		}
		g.imps = append(g.imps, imp{im.Name, im.Ordinal, im.SlotRVA})
	}

	// If a dropped slot sits in the middle of a DLL's run, the surviving slots are no
	// longer contiguous and a single FirstThunk cannot describe them. Split the DLL into
	// several descriptors, one per contiguous run of slots. Multiple descriptors naming
	// the same DLL are legal and the loader processes them in turn.
	type piece struct {
		dll   string
		ftRVA uint32
		names []imp // the run's imports in order, used to build the INT
	}
	var pieces []piece
	for _, g := range groups {
		if len(g.imps) == 0 {
			droppedDLLs = append(droppedDLLs, g.dll)
			continue
		}
		// split g.imps into runs whose slots are contiguous (4 bytes apart)
		start := 0
		for i := 1; i <= len(g.imps); i++ {
			if i == len(g.imps) || g.imps[i].slot != g.imps[i-1].slot+4 {
				seg := g.imps[start:i]
				pieces = append(pieces, piece{dll: g.dll, ftRVA: seg[0].slot, names: seg})
				start = i
			}
		}
	}

	// Layout: [N+1 descriptors of 20 bytes][per run: INT of (k+1)*4][name strings].
	// Every RVA below is an image RVA, so the section's own RVA has to be known first;
	// plannedSectionRVA reproduces the placement AddSection will use.
	secRVA := plannedSectionRVA(r)

	nDesc := len(pieces)
	descBytesLen = (nDesc + 1) * 20
	// compute the layout first
	intOff := descBytesLen
	// reserve the INT arrays
	intSizes := make([]int, len(pieces))
	cur := intOff
	intStart := make([]int, len(pieces))
	for i, p := range pieces {
		intStart[i] = cur
		intSizes[i] = (len(p.names) + 1) * 4
		cur += intSizes[i]
	}
	nameStart := cur
	// string area: one DLL name per descriptor plus IMAGE_IMPORT_BY_NAME per import
	buf := make([]byte, nameStart)
	// DLL names
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
	// IMAGE_IMPORT_BY_NAME is hint(2 bytes) + name; remember the offset for the INT
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

	// fill in the descriptors and the INTs
	for i, p := range pieces {
		d := i * 20
		binary.LittleEndian.PutUint32(buf[d:], rva(intStart[i])) // OriginalFirstThunk -> our INT
		binary.LittleEndian.PutUint32(buf[d+4:], 0)              // TimeDateStamp
		binary.LittleEndian.PutUint32(buf[d+8:], 0)              // ForwarderChain
		binary.LittleEndian.PutUint32(buf[d+12:], rva(dllNameOff[p.dll]))
		binary.LittleEndian.PutUint32(buf[d+16:], p.ftRVA) // FirstThunk = the existing IAT
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
		binary.LittleEndian.PutUint32(buf[io+len(p.names)*4:], 0) // INT terminator
	}
	// the trailing descriptor stays all zeroes
	return buf, droppedDLLs, kept, nil
}

// plannedSectionRVA mirrors AddSection's RVA computation without modifying anything.
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
