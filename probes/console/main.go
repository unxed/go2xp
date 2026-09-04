// Probe "console": the Console API surface f4 needs on XP, where there is no ConPTY and
// no ANSI interpreter - screen buffers, cell-level reads and writes, and the input queue.
//
// Everything here is deliberately non-interactive and safe under redirection: the console
// handles come from CONOUT$/CONIN$ rather than from stdio, the cell test uses a back
// buffer that is never made active, and the input queue is only inspected, never waited
// on. Console functions are reached through NewLazyDLL, so they also exercise the
// GetProcAddress hook.
//go:build windows

package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	_ "github.com/unxed/go2xp/shim"
)

var (
	kernel32                       = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleMode             = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode             = kernel32.NewProc("SetConsoleMode")
	procCreateConsoleScreenBuffer  = kernel32.NewProc("CreateConsoleScreenBuffer")
	procGetConsoleScreenBufferInfo = kernel32.NewProc("GetConsoleScreenBufferInfo")
	procWriteConsoleOutputW        = kernel32.NewProc("WriteConsoleOutputW")
	procReadConsoleOutputW         = kernel32.NewProc("ReadConsoleOutputW")
	procGetNumberOfConsoleInput    = kernel32.NewProc("GetNumberOfConsoleInputEvents")
	procPeekConsoleInputW          = kernel32.NewProc("PeekConsoleInputW")
)

type coord struct{ x, y int16 }

type smallRect struct{ left, top, right, bottom int16 }

type charInfo struct {
	ch   uint16
	attr uint16
}

type consoleScreenBufferInfo struct {
	size              coord
	cursorPosition    coord
	attributes        uint16
	window            smallRect
	maximumWindowSize coord
}

func main() {
	conout, err := openConsole("CONOUT$")
	if err != nil {
		// No console at all: nothing to test, and that is not a failure of the shim.
		fmt.Println("SKIP console: no console attached")
		return
	}
	defer syscall.CloseHandle(conout)

	// Mode round-trip on the real output handle.
	var mode uint32
	if r, _, e := procGetConsoleMode.Call(uintptr(conout), uintptr(unsafe.Pointer(&mode))); r == 0 {
		fail("GetConsoleMode: %v", e)
	}
	if r, _, e := procSetConsoleMode.Call(uintptr(conout), uintptr(mode)); r == 0 {
		fail("SetConsoleMode: %v", e)
	}

	var info consoleScreenBufferInfo
	if r, _, e := procGetConsoleScreenBufferInfo.Call(uintptr(conout), uintptr(unsafe.Pointer(&info))); r == 0 {
		fail("GetConsoleScreenBufferInfo: %v", e)
	}
	if info.size.x <= 0 || info.size.y <= 0 {
		fail("screen buffer is %dx%d", info.size.x, info.size.y)
	}

	// Cell-level write and read back, on a buffer that is never shown, so the test
	// cannot disturb whatever is on screen.
	const genericRW = 0x40000000 | 0x80000000
	const shareRW = 0x00000001 | 0x00000002
	const consoleTextmodeBuffer = 1
	back, _, e := procCreateConsoleScreenBuffer.Call(genericRW, shareRW, 0, consoleTextmodeBuffer, 0)
	if back == 0 || back == uintptr(syscall.InvalidHandle) {
		fail("CreateConsoleScreenBuffer: %v", e)
	}
	defer syscall.CloseHandle(syscall.Handle(back))

	// A COORD is packed into a single argument: X in the low word, Y in the high one.
	// Two cells wide, one row tall.
	const bufferSize = uintptr(1<<16 | 2)

	want := [2]charInfo{{ch: 'g', attr: 7}, {ch: 'o', attr: 7}}
	region := smallRect{left: 0, top: 0, right: 1, bottom: 0}
	if r, _, e := procWriteConsoleOutputW.Call(back, uintptr(unsafe.Pointer(&want[0])),
		bufferSize, 0, uintptr(unsafe.Pointer(&region))); r == 0 {
		fail("WriteConsoleOutputW: %v", e)
	}

	var got [2]charInfo
	region = smallRect{left: 0, top: 0, right: 1, bottom: 0}
	if r, _, e := procReadConsoleOutputW.Call(back, uintptr(unsafe.Pointer(&got[0])),
		bufferSize, 0, uintptr(unsafe.Pointer(&region))); r == 0 {
		fail("ReadConsoleOutputW: %v", e)
	}
	if got[0].ch != 'g' || got[1].ch != 'o' {
		fail("read back %q%q, want \"go\"", rune(got[0].ch), rune(got[1].ch))
	}

	// The input queue is only inspected: waiting on it would hang without a keyboard.
	conin, err := openConsole("CONIN$")
	if err != nil {
		fail("open CONIN$: %v", err)
	}
	defer syscall.CloseHandle(conin)

	var pending uint32
	if r, _, e := procGetNumberOfConsoleInput.Call(uintptr(conin), uintptr(unsafe.Pointer(&pending))); r == 0 {
		fail("GetNumberOfConsoleInputEvents: %v", e)
	}
	var records [8]byte // one INPUT_RECORD is larger; only the count matters here
	var read uint32
	if pending > 0 {
		procPeekConsoleInputW.Call(uintptr(conin), uintptr(unsafe.Pointer(&records[0])), 0,
			uintptr(unsafe.Pointer(&read)))
	}
	fmt.Printf("OK console (%dx%d, %d event(s) pending)\n", info.size.x, info.size.y, pending)
}

func openConsole(name string) (syscall.Handle, error) {
	p, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	return syscall.CreateFile(p, syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil, syscall.OPEN_EXISTING, 0, 0)
}

func fail(format string, a ...any) {
	fmt.Printf("FAIL console: "+format+"\n", a...)
	os.Exit(1)
}
