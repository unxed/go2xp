// Package shim, linked into an application, makes it patchable by go2xp: it carries
// polyfills for WinAPI functions missing on old Windows releases and a table
// (GO2XPTBL) that tells the patcher where those polyfills are.
//
//	import _ "github.com/unxed/go2xp/shim"
//
// On any platform other than windows/386 the package is empty, so an application
// can import it unconditionally.
package shim

import _ "unsafe" // for go:linkname

// Real system functions the polyfills forward to. Declaring them here gives the
// shim IAT slots of its own, which go2xp never redirects (their addresses are
// listed in GO2XPTBL as own slots). cgo_import_dynamic is allowed in non-cgo
// packages; golang.org/x/sys/unix uses the same trick on Solaris.
//
// A slot only survives dead-code elimination if GO2XPTBL references it, so every
// import below must have an own-slot entry in shim_windows_386.s.
//
//go:cgo_import_dynamic go2xp_GetProcAddress GetProcAddress%2 "kernel32.dll"
//go:cgo_import_dynamic go2xp_LoadLibraryExW LoadLibraryExW%3 "kernel32.dll"
//go:cgo_import_dynamic go2xp_SetErrorMode SetErrorMode%1 "kernel32.dll"
//go:cgo_import_dynamic go2xp_TerminateProcess TerminateProcess%2 "kernel32.dll"
//go:cgo_import_dynamic go2xp_SystemFunction036 SystemFunction036%2 "advapi32.dll"

//go:linkname procGetProcAddress go2xp_GetProcAddress
var procGetProcAddress uintptr

//go:linkname procLoadLibraryExW go2xp_LoadLibraryExW
var procLoadLibraryExW uintptr

//go:linkname procSetErrorMode go2xp_SetErrorMode
var procSetErrorMode uintptr

//go:linkname procTerminateProcess go2xp_TerminateProcess
var procTerminateProcess uintptr

//go:linkname procSystemFunction036 go2xp_SystemFunction036
var procSystemFunction036 uintptr

// Early polyfills, implemented in assembly because they run before the Go runtime
// is up. See shim_windows_386.s for what each one does.
func xp_WerSetFlags()
func xp_WerGetFlags()
func xp_GetErrorMode()
func xp_CreateWaitableTimerExW()
func xp_RaiseFailFastException()
func xp_LoadLibraryExW()
func xp_GetProcAddress()
func xp_ProcessPrng()

// tableAddr is implemented in assembly and returns the address of GO2XPTBL.
func tableAddr() uintptr

// Table is exported only to keep GO2XPTBL, and everything it points at, alive
// through the linker's dead-code elimination.
var Table uintptr

func init() { Table = tableAddr() }
