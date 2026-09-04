package shim

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

func tableProc(t *testing.T, name string) uintptr {
	t.Helper()
	base := unsafe.Pointer(Table)
	n := *(*uint32)(unsafe.Add(base, 12))
	for i := uint32(0); i < n; i++ {
		e := unsafe.Slice((*uintptr)(unsafe.Add(base, 16+i*16)), 4)
		p := (*byte)(unsafe.Pointer(e[1]))
		var b []byte
		for *p != 0 {
			b = append(b, *p)
			p = (*byte)(unsafe.Add(unsafe.Pointer(p), 1))
		}
		if string(b) == name && e[2] != 0 {
			return e[2]
		}
	}
	t.Fatalf("no table entry for %s", name)
	return 0
}

func wideString(p uintptr) string {
	var b []uint16
	for p != 0 {
		c := *(*uint16)(unsafe.Pointer(p))
		if c == 0 {
			break
		}
		b = append(b, c)
		p += 2
	}
	return syscall.UTF16ToString(b)
}

func TestSentinelMissSetsLastError(t *testing.T) {
	p := tableProc(t, "GetProcAddress")
	name, _ := syscall.BytePtrFromString("NoSuchGo2xpExport")
	r, _, e := syscall.SyscallN(p, 0x476f3258, uintptr(unsafe.Pointer(name)))
	if r != 0 || e != 127 {
		t.Fatalf("result=%x, error=%v; want NULL/127", r, e)
	}
	// Ordinals must not be dereferenced, even for the sentinel.
	r, _, e = syscall.SyscallN(p, 0x476f3258, 42)
	if r != 0 || e != 127 {
		t.Fatalf("ordinal result=%x, error=%v", r, e)
	}
}

func TestSystemDLLSearch(t *testing.T) {
	oldLoad, oldDir := procLoadLibraryExW, procGetSystemDirectoryW
	defer func() { procLoadLibraryExW, procGetSystemDirectoryW = oldLoad, oldDir }()
	procGetSystemDirectoryW = syscall.NewCallback(func(buf, count uintptr) uintptr {
		b, _ := syscall.UTF16FromString(`C:\Windows\System32`)
		copy(unsafe.Slice((*uint16)(unsafe.Pointer(buf)), int(count)), b)
		return uintptr(len(b) - 1)
	})
	var got string
	var gotFlags uintptr
	procLoadLibraryExW = syscall.NewCallback(func(name, file, flags uintptr) uintptr {
		got, gotFlags = wideString(name), flags
		return 0x12340000
	})
	p := tableProc(t, "LoadLibraryExW")
	name, _ := syscall.UTF16PtrFromString("version.dll")
	r, _, e := syscall.SyscallN(p, uintptr(unsafe.Pointer(name)), 0, 0x800)
	if r == 0 || got != `C:\Windows\System32\version.dll` || gotFlags != 0 {
		t.Fatalf("load=%x/%v, name=%q flags=%x", r, e, got, gotFlags)
	}
	got = ""
	name, _ = syscall.UTF16PtrFromString(strings.Repeat("x", 300) + ".dll")
	r, _, e = syscall.SyscallN(p, uintptr(unsafe.Pointer(name)), 0, 0x800)
	if r != 0 || e != 206 || got != "" {
		t.Fatalf("overflow loaded %q: %x/%v", got, r, e)
	}
	procGetSystemDirectoryW = syscall.NewCallback(func(buf, count uintptr) uintptr {
		syscall.SyscallN(procSetLastError, 5)
		return 0
	})
	r, _, e = syscall.SyscallN(p, uintptr(unsafe.Pointer(name)), 0, 0x800)
	if r != 0 || got != "" {
		t.Fatalf("directory failure loaded %q: %x/%v", got, r, e)
	}
}

func TestCreateProcessXPStartupInfo(t *testing.T) {
	oldCreate, oldInit := realCreateProcessW, realInitializeProcThreadAttributeList
	defer func() { realCreateProcessW, realInitializeProcThreadAttributeList = oldCreate, oldInit }()
	var gotFlags uintptr
	var gotCB uint32
	realCreateProcessW = syscall.NewCallback(func(a, b, c, d, e, f, g, h, si, pi uintptr) uintptr {
		runtime.GC() // the copied STARTUPINFO must remain live across the callback
		gotFlags = f
		gotCB = (*syscall.StartupInfo)(unsafe.Pointer(si)).Cb
		return 1
	})
	si := syscall.StartupInfo{Cb: 72}
	p := tableProc(t, "CreateProcessW")
	for _, xp := range []bool{true, false} {
		realInitializeProcThreadAttributeList = oldInit
		if xp {
			realInitializeProcThreadAttributeList = 0
		}
		r, _, e := syscall.SyscallN(p, 0, 0, 0, 0, 1, 0x80400, 0, 0, uintptr(unsafe.Pointer(&si)), 0)
		wantFlags, wantCB := uintptr(0x80400), uint32(72)
		if xp {
			wantFlags, wantCB = 0x400, uint32(unsafe.Sizeof(si))
		}
		if r != 1 || gotFlags != wantFlags || gotCB != wantCB || si.Cb != 72 {
			t.Fatalf("XP=%v: result=%x/%v, flags=%x cb=%d original=%d", xp, r, e, gotFlags, gotCB, si.Cb)
		}
	}
}

func TestNtCreateFileNoReparse(t *testing.T) {
	old := realNtCreateFile
	defer func() { realNtCreateFile = old }()
	var retries int
	realNtCreateFile = syscall.NewCallback(func(a, b, c, d, e, f, g, h, i, j, k uintptr) uintptr {
		oa := (*objectAttributes)(unsafe.Pointer(c))
		if oa.attributes&0x1000 != 0 {
			return 0xc000000d
		}
		retries++
		r, _, _ := syscall.SyscallN(old, a, b, c, d, e, f, g, h, i, j, k)
		return r
	})
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "child"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	parent, _ := syscall.UTF16PtrFromString(dir)
	h, err := syscall.CreateFile(parent, syscall.GENERIC_READ, 7, nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(h)
	p := tableProc(t, "NtCreateFile")
	open := func(name string) uintptr {
		u, _ := syscall.UTF16FromString(name)
		us := unicodeString{length: uint16((len(u) - 1) * 2), maximumLength: uint16(len(u) * 2), buffer: &u[0]}
		oa := objectAttributes{length: 24, root: uintptr(h), name: &us, attributes: 0x1040}
		var result syscall.Handle
		var iosb ioStatusBlock
		r, _, _ := syscall.SyscallN(p, uintptr(unsafe.Pointer(&result)), 0x100080, uintptr(unsafe.Pointer(&oa)), uintptr(unsafe.Pointer(&iosb)), 0, 0, 7, 1, 0x20, 0, 0)
		if int32(r) >= 0 {
			syscall.CloseHandle(result)
		}
		if oa.attributes != 0x1040 {
			t.Fatal("mutated caller's attributes")
		}
		return r
	}
	if r := open("child"); r != 0 {
		t.Fatalf("relative open: %#x", r)
	}
	if retries != 1 {
		t.Fatalf("retries=%d", retries)
	}
	for _, name := range []string{`sub\child`, "../child", ".."} {
		if r := open(name); r != 0xc000000d {
			t.Fatalf("unsafe name %q: %#x", name, r)
		}
	}
	if retries != 1 {
		t.Fatal("retried a path that could traverse a junction")
	}
	// Inject the metadata result to cover refusal even on Wine builds that report
	// success from CreateSymbolicLinkW without creating a usable reparse point.
	oldInfo := getFileInformationByHandle
	defer func() { getFileInformationByHandle = oldInfo }()
	getFileInformationByHandle = func(h syscall.Handle, info *syscall.ByHandleFileInformation) error {
		err := oldInfo(h, info)
		info.FileAttributes |= syscall.FILE_ATTRIBUTE_REPARSE_POINT
		return err
	}
	if r := open("child"); r != 0xc000050b {
		t.Fatalf("reparse point: %#x", r)
	}
}
