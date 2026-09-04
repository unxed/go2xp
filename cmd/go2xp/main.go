// go2xp patches Go binaries for old Windows releases. Commands: inspect, exports, patch, verify.
package main

import (
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/unxed/go2xp/internal/pe"
)

func main() {
	if len(os.Args) < 3 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "inspect":
		err = inspect(os.Args[2])
	case "exports":
		err = exports(os.Args[2])
	case "patch":
		// go2xp patch -profile profiles/xp.json in.exe out.exe
		err = patchCmd(os.Args[2:])
	case "verify":
		// go2xp verify -profile profiles/xp.json app.exe
		err = verifyCmd(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "go2xp:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage:\n  go2xp inspect app.exe      PE header + import table with IAT slot RVAs\n  go2xp exports kernel32.dll  list exported names (to build a target-OS profile)")
	os.Exit(2)
}

func patchCmd(args []string) error {
	fs := flag.NewFlagSet("patch", flag.ExitOnError)
	profile := fs.String("profile", "profiles/xp.json", "target OS profile")
	fs.Parse(args)
	if fs.NArg() < 1 {
		return fmt.Errorf("usage: go2xp patch -profile P in.exe [out.exe]")
	}
	in := fs.Arg(0)
	out := fs.Arg(1)
	if out == "" {
		out = in
	}
	return doPatch(in, out, *profile)
}

func verifyCmd(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	profile := fs.String("profile", "profiles/xp.json", "target OS profile")
	fs.Parse(args)
	if fs.NArg() < 1 {
		return fmt.Errorf("usage: go2xp verify -profile P app.exe")
	}
	return doVerify(fs.Arg(0), *profile)
}

func inspect(path string) error {
	in, err := pe.Open(path)
	if err != nil {
		return err
	}
	fmt.Printf("machine=%#x imagebase=%#x os=%d.%d subsystem=%d.%d dllchar=%#x reloc=%v\n",
		in.Machine, in.ImageBase, in.OSMajor, in.OSMinor, in.SubsysMajor, in.SubsysMinor, in.DllCharacteristics, in.HasReloc)
	fmt.Printf("sections=%v\n", in.Sections)
	fmt.Printf("import dir rva=%#x size=%#x, %d imports:\n", in.ImportDirRVA, in.ImportDirSize, len(in.Imports))
	own := map[uint32]bool{}
	for _, t := range in.Table {
		if t.OwnSlot != 0 {
			own[t.OwnSlot-in.ImageBase] = true
		}
	}
	for _, im := range in.Imports {
		name := im.Name
		if name == "" {
			name = fmt.Sprintf("#%d", im.Ordinal)
		}
		mark := ""
		if own[im.SlotRVA] {
			mark = "  [shim own slot]"
		}
		fmt.Printf("  desc%d slot=%#08x %-24s %s%s\n", im.DescIdx, im.SlotRVA, im.DLL, name, mark)
	}
	if in.Table == nil {
		fmt.Println("GO2XPTBL: not found (shim not linked in)")
		return nil
	}
	fmt.Printf("GO2XPTBL: %d entries\n", len(in.Table))
	for _, t := range in.Table {
		fmt.Printf("  %-14s %-28s polyfill=%#08x ownslot=%#08x\n", t.DLL, t.Func, t.Polyfill, t.OwnSlot)
	}
	return nil
}

func exports(path string) error {
	names, err := pe.Exports(path)
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Println(n)
	}
	return nil
}
