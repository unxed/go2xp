package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/unxed/go2xp/internal/pe"
)

// auditCmd: go2xp audit [-profile profiles/xp.json] app.exe
//
// Lists every function the binary may look up at run time and reports, for each one the
// target lacks, whether the shim polyfills it, whether the profile accepts its absence,
// or neither. The exit status is non-zero only in the last case, which makes the command
// usable as a CI gate with the profile as the single source of truth.
//
// The export list (profiles/kernel32-exports.tsv, next to the profile) covers kernel32
// only: a name absent from it may simply live in another DLL, which is reported as such.
func auditCmd(args []string) error {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	profile := fs.String("profile", "profiles/xp.json", "target OS profile; the export list is read from the same directory")
	fs.Parse(args)
	if fs.NArg() < 1 {
		return fmt.Errorf("usage: go2xp audit [-profile P] app.exe")
	}
	path := fs.Arg(0)

	lazy, err := pe.LazyProcs(path)
	if err != nil {
		return err
	}
	if len(lazy) == 0 {
		return fmt.Errorf("no proc* symbols found; was the binary linked with -s?")
	}
	xp, err := loadExports(filepath.Join(filepath.Dir(*profile), "kernel32-exports.tsv"))
	if err != nil {
		return err
	}
	accepted, err := loadAccepted(*profile)
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
			if !covered[n] && accepted[n] == "" {
				uncovered = append(uncovered, n)
			}
		}
	}
	fmt.Printf("%s: %d lazily resolved names; %d not in kernel32 (other DLLs or the program's own aliases); %d kernel32-forwarded since Vista but resolved from advapi32 on XP\n",
		filepath.Base(path), len(lazy), other, advapi)
	fmt.Printf("%d kernel32 names absent on the target:\n", len(absent))
	for _, n := range absent {
		mark := "NOT covered"
		switch {
		case covered[n]:
			mark = "polyfilled"
		case accepted[n] != "":
			mark = "accepted: " + accepted[n]
		}
		fmt.Printf("  %-40s%s\n", n, mark)
	}
	if len(uncovered) > 0 {
		return fmt.Errorf("%d absent name(s) neither polyfilled nor accepted by the profile: %s (each fails with ERROR_PROC_NOT_FOUND at its call site; polyfill it in the shim or list it under \"pending\" in the profile with a reason)",
			len(uncovered), strings.Join(uncovered, ", "))
	}
	return nil
}

// loadAccepted reads the profile's "pending" section: every list under it (except the
// comment) names functions whose absence on the target is understood and accepted, and
// the list's key is the reason.
func loadAccepted(profilePath string) (map[string]string, error) {
	b, err := os.ReadFile(profilePath)
	if err != nil {
		return nil, err
	}
	var p struct {
		Pending map[string]json.RawMessage `json:"pending"`
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	out := map[string]string{}
	for reason, raw := range p.Pending {
		var names []string
		if json.Unmarshal(raw, &names) != nil {
			continue // the comment, or a non-list entry
		}
		for _, n := range names {
			out[n] = reason
		}
	}
	return out, nil
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

// loadExports reads kernel32-exports.tsv: name, xp|no|?, version range.
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
