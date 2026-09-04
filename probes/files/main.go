// Probe "files": ordinary file system work - the paths that reach CreateFileW,
// GetFileInformationByHandle, directory enumeration and the temp/home lookups.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "github.com/unxed/go2xp/shim"
)

func main() {
	dir, err := os.MkdirTemp("", "go2xp")
	check(err, "MkdirTemp")
	defer os.RemoveAll(dir)

	name := filepath.Join(dir, "probe.txt")
	check(os.WriteFile(name, []byte("go2xp"), 0o644), "WriteFile")

	got, err := os.ReadFile(name)
	check(err, "ReadFile")
	if string(got) != "go2xp" {
		fail("ReadFile returned %q", got)
	}

	st, err := os.Stat(name)
	check(err, "Stat")
	if st.Size() != 5 {
		fail("Stat size %d, want 5", st.Size())
	}

	renamed := filepath.Join(dir, "renamed.txt")
	check(os.Rename(name, renamed), "Rename")

	var seen []string
	check(filepath.WalkDir(dir, func(p string, _ os.DirEntry, err error) error {
		if err == nil && p != dir {
			seen = append(seen, filepath.Base(p))
		}
		return err
	}), "WalkDir")
	if strings.Join(seen, ",") != "renamed.txt" {
		fail("WalkDir saw %v", seen)
	}

	check(os.Remove(renamed), "Remove")
	if _, err := os.Getwd(); err != nil {
		fail("Getwd: %v", err)
	}
	if _, err := os.UserHomeDir(); err != nil {
		fail("UserHomeDir: %v", err)
	}
	fmt.Println("OK files")
}

func check(err error, what string) {
	if err != nil {
		fail("%s: %v", what, err)
	}
}

func fail(format string, a ...any) {
	fmt.Printf("FAIL files: "+format+"\n", a...)
	os.Exit(1)
}
