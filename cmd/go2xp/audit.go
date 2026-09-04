package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/unxed/go2xp/internal/pe"
)

// audit lists every function the binary may look up at run time and reports which of
// them the target lacks, and whether the shim covers each one. It needs the export
// list in profiles/kernel32-exports.tsv and only knows about kernel32: a name absent
// there may simply live in another DLL (advapi32, ws2_32...), which is reported as such.
func audit(path, exportsPath string) error {
	lazy, err := pe.LazyProcs(path)
	if err != nil {
		return err
	}
	if len(lazy) == 0 {
		return fmt.Errorf("no proc* symbols found; was the binary linked with -s?")
	}
	xp, err := loadExports(exportsPath)
	if err != nil {
		return err
	}
	info, err := pe.Open(path)
	if err != nil {
		return err
	}
	covered := map[string]bool{}
	for _, e := range info.Table {
		if e.Polyfill != 0 {
			covered[e.Func] = true
		}
	}

	var absent, uncovered []string
	other, advapi := 0, 0
	for _, n := range lazy {
		present, known := xp[n]
		switch {
		case !known:
			other++
		case !present && advapi32OnXP[n]:
			advapi++
		case !present:
			absent = append(absent, n)
			if !covered[n] {
				uncovered = append(uncovered, n)
			}
		}
	}
	fmt.Printf("%d lazily resolved names; %d not in kernel32 (other DLLs or the program's own aliases); %d kernel32-forwarded since Vista but resolved from advapi32 on XP\n", len(lazy), other, advapi)
	fmt.Printf("%d kernel32 names absent on the target:\n", len(absent))
	for _, n := range absent {
		mark := "  polyfilled"
		if !covered[n] {
			mark = "  NOT covered"
		}
		fmt.Printf("  %-40s%s\n", n, mark)
	}
	if len(uncovered) > 0 {
		fmt.Printf("%d absent and not covered by the shim; each fails with ERROR_PROC_NOT_FOUND at its call site (see docs/api-audit.md for which of these are acceptable)\n", len(uncovered))
	}
	return nil
}

// advapi32OnXP lists names kernel32 only started exporting (as forwarders) in Vista or
// later, while on XP they live in advapi32.dll - which is where Go resolves them from
// anyway, so their absence from XP's kernel32 does not matter.
var advapi32OnXP = map[string]bool{
	"OpenProcessToken": true, "OpenThreadToken": true, "CreateProcessAsUserW": true,
	"RegCloseKey": true, "RegOpenKeyExW": true, "RegQueryValueExW": true, "RegEnumKeyExW": true,
	"RegEnumValueW": true, "RegQueryInfoKeyW": true, "RegCreateKeyExW": true, "RegDeleteKeyExW": true,
	"RegSetValueExW": true, "RegDeleteValueW": true, "RegNotifyChangeKeyValue": true,
	"RegGetValueW": true, "RegLoadMUIStringW": true, "AdjustTokenPrivileges": true,
	"LookupPrivilegeValueW": true, "GetTokenInformation": true, "RevertToSelf": true,
	"ImpersonateLoggedOnUser": true, "SystemFunction036": true,
}

// loadExports reads profiles/kernel32-exports.tsv: name, xp|no|?, version range.
func loadExports(path string) (map[string]bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) >= 2 {
			out[parts[0]] = parts[1] == "xp"
		}
	}
	return out, sc.Err()
}
