// Package shim, linked into an application, makes it patchable by go2xp: it carries
// polyfills for WinAPI functions missing on old Windows releases and a table
// (GO2XPTBL) that tells the patcher where those polyfills are.
//
//	import _ "github.com/unxed/go2xp/shim"
//
// On any platform other than windows/386 the package is empty, so an application can
// import it unconditionally.
package shim

import (
	"os"
	"syscall"
	_ "unsafe" // for go:linkname
)

// Real system functions the polyfills forward to. Declaring them here gives the shim IAT
// slots of its own, which go2xp never redirects (their addresses are listed in GO2XPTBL
// as own slots). cgo_import_dynamic is allowed in non-cgo packages;
// golang.org/x/sys/unix uses the same trick on Solaris.
//
// A slot only survives dead-code elimination if GO2XPTBL references it, so every import
// below must have an own-slot entry in shim_windows_386.s.
//
//go:cgo_import_dynamic go2xp_GetProcAddress GetProcAddress%2 "kernel32.dll"
//go:cgo_import_dynamic go2xp_LoadLibraryExW LoadLibraryExW%3 "kernel32.dll"
//go:cgo_import_dynamic go2xp_SetErrorMode SetErrorMode%1 "kernel32.dll"
//go:cgo_import_dynamic go2xp_TerminateProcess TerminateProcess%2 "kernel32.dll"
//go:cgo_import_dynamic go2xp_GetQueuedCompletionStatus GetQueuedCompletionStatus%5 "kernel32.dll"
//go:cgo_import_dynamic go2xp_CancelIo CancelIo%1 "kernel32.dll"
//go:cgo_import_dynamic go2xp_GetSystemDirectoryW GetSystemDirectoryW%2 "kernel32.dll"
//go:cgo_import_dynamic go2xp_SetLastError SetLastError%1 "kernel32.dll"
//go:cgo_import_dynamic go2xp_SystemFunction036 SystemFunction036%2 "advapi32.dll"

//go:linkname procGetProcAddress go2xp_GetProcAddress
var procGetProcAddress uintptr

//go:linkname procLoadLibraryExW go2xp_LoadLibraryExW
var procLoadLibraryExW uintptr

//go:linkname procSetErrorMode go2xp_SetErrorMode
var procSetErrorMode uintptr

//go:linkname procTerminateProcess go2xp_TerminateProcess
var procTerminateProcess uintptr

//go:linkname procGetQueuedCompletionStatus go2xp_GetQueuedCompletionStatus
var procGetQueuedCompletionStatus uintptr

//go:linkname procCancelIo go2xp_CancelIo
var procCancelIo uintptr

//go:linkname procGetSystemDirectoryW go2xp_GetSystemDirectoryW
var procGetSystemDirectoryW uintptr

//go:linkname procSetLastError go2xp_SetLastError
var procSetLastError uintptr

//go:linkname procSystemFunction036 go2xp_SystemFunction036
var procSystemFunction036 uintptr

// Early polyfills, in assembly because they run before the Go runtime is up, and the two
// import hooks. See shim_windows_386.s for what each one does.
func xp_WerSetFlags()
func xp_WerGetFlags()
func xp_GetErrorMode()
func xp_CreateWaitableTimerExW()
func xp_RaiseFailFastException()
func xp_GetQueuedCompletionStatusEx()
func xp_LoadLibraryExW()
func xp_GetProcAddress()
func xp_ProcessPrng()
func xp_CancelIoEx()
func xp_GetFileInformationByHandleEx()
func xp_SetFileInformationByHandle()
func xp_InitializeProcThreadAttributeList()
func xp_UpdateProcThreadAttribute()
func xp_DeleteProcThreadAttributeList()
func xp_WSASocketW()
func xp_CreateEventExW()
func xp_CreateProcessW()
func xp_NtCreateFile()

// Late polyfills are written in Go and installed as stdcall callbacks by init; the
// assembly trampoline of each one jumps to the address kept here. Only functions that
// can never be called before the runtime exists may use this path.
var (
	cbCancelIoEx                        uintptr
	cbGetFileInformationByHandleEx      uintptr
	cbSetFileInformationByHandle        uintptr
	cbInitializeProcThreadAttributeList uintptr
	cbUpdateProcThreadAttribute         uintptr
	cbDeleteProcThreadAttributeList     uintptr
	cbWSASocketW                        uintptr
	cbCreateEventExW                    uintptr
	cbCreateProcessW                    uintptr
	cbNtCreateFile                      uintptr
)

// forcePolyfills makes xp_GetProcAddress answer from the table instead of preferring the
// real export. It exists so the test harness can exercise the polyfills on a system that
// has the real functions; production code leaves it alone. Read by assembly.
var forcePolyfills uintptr

// tableAddr is implemented in assembly and returns the address of GO2XPTBL.
func tableAddr() uintptr

// Table is exported only to keep GO2XPTBL, and everything it points at, alive through the
// linker's dead-code elimination.
var Table uintptr

func init() {
	Table = tableAddr()
	cbCancelIoEx = syscall.NewCallback(polyCancelIoEx)
	cbGetFileInformationByHandleEx = syscall.NewCallback(polyGetFileInformationByHandleEx)
	cbSetFileInformationByHandle = syscall.NewCallback(polySetFileInformationByHandle)
	cbInitializeProcThreadAttributeList = syscall.NewCallback(polyInitializeProcThreadAttributeList)
	cbUpdateProcThreadAttribute = syscall.NewCallback(polyUpdateProcThreadAttribute)
	cbDeleteProcThreadAttributeList = syscall.NewCallback(polyDeleteProcThreadAttributeList)
	cbWSASocketW = syscall.NewCallback(polyWSASocketW)
	cbCreateEventExW = syscall.NewCallback(polyCreateEventExW)
	cbCreateProcessW = syscall.NewCallback(polyCreateProcessW)
	cbNtCreateFile = syscall.NewCallback(polyNtCreateFile)
	if os.Getenv("GO2XP_FORCE_POLYFILLS") != "" {
		forcePolyfills = 1
	}
}

// polyCancelIoEx implements CancelIoEx (Vista+) with CancelIo, which XP has.
//
// The emulation is coarser than the original in two ways: CancelIo cancels every pending
// operation the calling thread issued on the handle rather than the single operation
// named by lpOverlapped, and it can only cancel what the calling thread started. In
// particular, Go can issue and cancel I/O on different OS threads, so this is NOT
// equivalent for pending operations or deadlines. See docs/reference-review.md.
// The lpOverlapped argument is ignored; same-thread successful calls are the only
// behavior this fallback can promise.
func polyCancelIoEx(hFile, lpOverlapped uintptr) uintptr {
	r, _, _ := syscall.Syscall(procCancelIo, 1, hFile, 0, 0)
	return r
}
