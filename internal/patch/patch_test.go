package patch

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	xpe "github.com/unxed/go2xp/internal/pe"
)

// buildProbe compiles a tiny windows/386 exe with the shim linked in.
func buildProbe(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	must := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	must("main.go", "package main\n\nimport _ \"github.com/unxed/go2xp/shim\"\n\nfunc main() {}\n")
	must("go.mod", "module probe\n\ngo 1.26.6\n\nrequire github.com/unxed/go2xp v0.0.0\n\nreplace github.com/unxed/go2xp => "+root+"\n")
	out := filepath.Join(dir, "probe.exe")
	cmd := exec.Command("go", "build", "-buildvcs=false", "-o", out, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH=386", "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build probe: %v\n%s", err, b)
	}
	return out
}

func TestPatchVerify(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not in PATH")
	}
	in := buildProbe(t)
	out := in + ".xp"
	prof := filepath.Join("..", "..", "profiles", "xp.json")

	res, err := Patch(in, out, prof)
	if err != nil {
		t.Fatalf("Patch: %v", err)
	}
	if len(res.Redirected) == 0 {
		t.Fatalf("nothing redirected")
	}
	if err := Verify(out, prof); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	info, err := xpe.Open(out)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if info.OSMajor != 5 || info.OSMinor != 1 {
		t.Errorf("OS version = %d.%d, want 5.1", info.OSMajor, info.OSMinor)
	}
	if info.DllCharacteristics&0x0040 != 0 {
		t.Errorf("DYNAMIC_BASE still set")
	}
	// WerSetFlags must be gone from the import table
	for _, im := range info.Imports {
		if im.Name == "WerSetFlags" {
			t.Errorf("WerSetFlags still imported")
		}
	}
	// shim's own GetProcAddress/LoadLibraryExW slots must survive
	own := 0
	for _, e := range info.Table {
		if e.OwnSlot != 0 {
			own++
		}
	}
	if own < 2 {
		t.Errorf("shim own slots = %d, want >=2", own)
	}
}
