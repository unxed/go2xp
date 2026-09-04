// Package shim linked into an application makes it patchable by go2xp:
// it carries the polyfills for WinAPI functions missing on old Windows and a
// table (GO2XPTBL) that tells the patcher where they are.
//
//	import _ "github.com/unxed/go2xp/shim"
//
// Only windows/386 is supported for now.
package shim

import _ "unsafe" // for go:linkname

// Real system functions the polyfills forward to. NOTE: a slot only survives
// dead-code elimination if GO2XPTBL (in the .s file) references it.
// Real system functions the polyfills forward to. Declared here so that the
// shim gets IAT slots of its own; go2xp never redirects these (their addresses
// are listed in GO2XPTBL as "own slots"). cgo_import_dynamic is permitted in
// non-cgo packages — same trick golang.org/x/sys/unix uses on Solaris.
//
//go:cgo_import_dynamic go2xp_GetProcAddress GetProcAddress%2 "kernel32.dll"
//go:cgo_import_dynamic go2xp_LoadLibraryExW LoadLibraryExW%3 "kernel32.dll"

//go:linkname procGetProcAddress go2xp_GetProcAddress
var procGetProcAddress uintptr

//go:linkname procLoadLibraryExW go2xp_LoadLibraryExW
var procLoadLibraryExW uintptr

// tableAddr is implemented in assembly and returns the address of GO2XPTBL.
func tableAddr() uintptr

// Table is exported only to keep the table (and everything it references)
// alive through the linker's dead-code elimination.
var Table uintptr

func init() {
	Table = tableAddr()
	_ = procGetProcAddress
	_ = procLoadLibraryExW
}
