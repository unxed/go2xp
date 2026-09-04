package pe

import (
	"bytes"
	"debug/pe"
	"os"
	"sort"
	"strings"
)

// LazyProcs returns the names of every function the binary may resolve at run time
// through GetProcAddress. Each syscall.LazyProc / x/sys LazyProc is a package-level
// variable named proc<Function>, so the set is visible in the COFF symbol table without
// running anything. It is empty if the binary was linked with -s.
func LazyProcs(path string) ([]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	f, err := pe.NewFile(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, s := range f.Symbols {
		i := strings.LastIndex(s.Name, ".proc")
		if i < 0 {
			continue
		}
		name := s.Name[i+len(".proc"):]
		if name == "" || name[0] < 'A' || name[0] > 'Z' {
			continue
		}
		seen[name] = true
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}
