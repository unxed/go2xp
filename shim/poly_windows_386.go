package shim

import (
	"syscall"
	"unsafe"
)

// Late polyfills: ordinary Go functions installed as stdcall callbacks by init and
// reached through the trampolines in shim_windows_386.s. They may only be used for
// functions that are never called before the Go runtime is up.
//
// Every one of them returns the raw value the Win32 original would and sets the thread's
// last error the same way, because the caller is the generated //sys wrapper in syscall
// or x/sys, which reads GetLastError right after the call returns.

// Real system functions are resolved through the shim's own GetProcAddress slot, which
// the patcher never redirects, so nothing here can loop back into the hooks. This is
// also why the wrappers can stay out of the static import table: a program that never
// opens a socket never loads ws2_32.dll because of the shim.
func realProc(dll, name string) uintptr {
	dllp, _ := syscall.UTF16PtrFromString(dll)
	h, _, _ := syscall.SyscallN(procLoadLibraryExW, uintptr(unsafe.Pointer(dllp)), 0, 0)
	if h == 0 {
		return 0
	}
	namep, _ := syscall.BytePtrFromString(name)
	p, _, _ := syscall.SyscallN(procGetProcAddress, h, uintptr(unsafe.Pointer(namep)))
	return p
}

var (
	ntQueryDirectoryFile   = realProc("ntdll.dll", "NtQueryDirectoryFile")
	ntQueryInformationFile = realProc("ntdll.dll", "NtQueryInformationFile")
	ntSetInformationFile   = realProc("ntdll.dll", "NtSetInformationFile")
	rtlNtStatusToDosError  = realProc("ntdll.dll", "RtlNtStatusToDosError")
	setLastError           = realProc("kernel32.dll", "SetLastError")
	waitForSingleObject    = realProc("kernel32.dll", "WaitForSingleObject")
	createEventW           = realProc("kernel32.dll", "CreateEventW")
	setHandleInformation   = realProc("kernel32.dll", "SetHandleInformation")
)

const (
	errorInsufficientBuffer = 122
	errorInvalidParameter   = 87
	errorNoMoreFiles        = 18
	errorFileNotFound       = 2

	statusPending     = 0x103
	statusNoMoreFiles = 0x80000006
	statusNoSuchFile  = 0xC000000F
	infinite          = 0xFFFFFFFF
)

func setErr(code uintptr) { syscall.SyscallN(setLastError, code) }

type ioStatusBlock struct {
	status      uintptr
	information uintptr
}

// finish waits out STATUS_PENDING on a handle opened for overlapped I/O (the file handle
// itself is signalled because no event was passed), then converts the final NTSTATUS
// into the BOOL-plus-last-error shape of the Win32 originals.
func finish(h, status uintptr, iosb *ioStatusBlock) uintptr {
	if status == statusPending {
		syscall.SyscallN(waitForSingleObject, h, infinite)
		status = iosb.status
	}
	if int32(status) < 0 || status == statusNoMoreFiles {
		var code uintptr
		switch status {
		case statusNoMoreFiles:
			code = errorNoMoreFiles
		case statusNoSuchFile:
			// What GetFileInformationByHandleEx reports for an empty root directory; os
			// relies on this exact code, see os/dir_windows.go.
			code = errorFileNotFound
		default:
			code, _, _ = syscall.SyscallN(rtlNtStatusToDosError, status)
		}
		setErr(code)
		return 0
	}
	return 1
}

// Win32 FILE_INFO_BY_HANDLE_CLASS values and the FILE_INFORMATION_CLASS each maps to.
// For every pair listed the Win32 and the NT structures have the same layout, so the
// caller's buffer can be handed to ntdll untouched. Classes that XP's kernel cannot
// serve (FileIdInfo and later) are absent and fail with ERROR_INVALID_PARAMETER.
var queryClass = map[uintptr]uintptr{
	0:  4,  // FileBasicInfo          -> FileBasicInformation
	1:  5,  // FileStandardInfo       -> FileStandardInformation
	2:  9,  // FileNameInfo           -> FileNameInformation
	7:  22, // FileStreamInfo         -> FileStreamInformation
	8:  28, // FileCompressionInfo    -> FileCompressionInformation
	9:  35, // FileAttributeTagInfo   -> FileAttributeTagInformation
	17: 17, // FileAlignmentInfo      -> FileAlignmentInformation
}

// Directory classes go to NtQueryDirectoryFile instead; the bool is RestartScan.
var dirClass = map[uintptr]struct {
	nt      uintptr
	restart bool
}{
	10: {37, false}, // FileIdBothDirectoryInfo        -> FileIdBothDirectoryInformation
	11: {37, true},  // FileIdBothDirectoryRestartInfo
	14: {2, false},  // FileFullDirectoryInfo          -> FileFullDirectoryInformation
	15: {2, true},   // FileFullDirectoryRestartInfo
}

// BOOL WINAPI GetFileInformationByHandleEx(HANDLE, FILE_INFO_BY_HANDLE_CLASS, LPVOID, DWORD) - Vista+.
// This is how os reads directories since Go 1.22, with no fallback, so without it a
// file manager cannot list a single folder on XP.
func polyGetFileInformationByHandleEx(h, class, buf, size uintptr) uintptr {
	var iosb ioStatusBlock
	if d, ok := dirClass[class]; ok {
		restart := uintptr(0)
		if d.restart {
			restart = 1
		}
		status, _, _ := syscall.SyscallN(ntQueryDirectoryFile, h, 0, 0, 0,
			uintptr(unsafe.Pointer(&iosb)), buf, size, d.nt, 0 /* all entries that fit */, 0, restart)
		return finish(h, status, &iosb)
	}
	if nt, ok := queryClass[class]; ok {
		status, _, _ := syscall.SyscallN(ntQueryInformationFile, h, uintptr(unsafe.Pointer(&iosb)), buf, size, nt)
		return finish(h, status, &iosb)
	}
	setErr(errorInvalidParameter)
	return 0
}

// SetFileInformationByHandle classes with a layout-identical NT counterpart.
var setClass = map[uintptr]uintptr{
	0: 4,  // FileBasicInfo       -> FileBasicInformation      (Fchmod)
	3: 10, // FileRenameInfo      -> FileRenameInformation
	4: 13, // FileDispositionInfo -> FileDispositionInformation (delete on close)
	5: 19, // FileAllocationInfo  -> FileAllocationInformation
	6: 20, // FileEndOfFileInfo   -> FileEndOfFileInformation
}

// BOOL WINAPI SetFileInformationByHandle(HANDLE, FILE_INFO_BY_HANDLE_CLASS, LPVOID, DWORD) - Vista+.
func polySetFileInformationByHandle(h, class, buf, size uintptr) uintptr {
	nt, ok := setClass[class]
	if !ok {
		setErr(errorInvalidParameter)
		return 0
	}
	var iosb ioStatusBlock
	status, _, _ := syscall.SyscallN(ntSetInformationFile, h, uintptr(unsafe.Pointer(&iosb)), buf, size, nt)
	return finish(h, status, &iosb)
}

// The ProcThreadAttributeList trio (Vista+). os/exec builds one for every child, with
// no fallback. Our CreateProcessW wrapper removes EXTENDED_STARTUPINFO_PRESENT
// when the real attribute API is absent. The list then only needs to exist: the
// handle-inheritance list it would have carried is not honoured, and the child inherits
// every inheritable handle, which is what every program did before Vista. Same approach
// as go-legacy-winxp.
//
// Where the real functions exist they are used, because a fake list handed to a
// CreateProcessW that does parse attribute lists (Win7, Wine) crashes it. That keeps
// the same binary correct on every Windows, and keeps forced-polyfill test runs honest.
var (
	realInitializeProcThreadAttributeList = realProc("kernel32.dll", "InitializeProcThreadAttributeList")
	realUpdateProcThreadAttribute         = realProc("kernel32.dll", "UpdateProcThreadAttribute")
	realDeleteProcThreadAttributeList     = realProc("kernel32.dll", "DeleteProcThreadAttributeList")
)

// BOOL WINAPI InitializeProcThreadAttributeList(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD, PSIZE_T)
func polyInitializeProcThreadAttributeList(list, count, flags, psize uintptr) uintptr {
	if realInitializeProcThreadAttributeList != 0 {
		r, _, e := syscall.SyscallN(realInitializeProcThreadAttributeList, list, count, flags, psize)
		if r == 0 {
			setErr(uintptr(e))
		}
		return r
	}
	if list == 0 {
		// Size query. Any size will do; the caller allocates it and hands it back.
		if psize != 0 {
			// psize is a pointer the caller owns, handed over as an integer by the
			// stdcall ABI; converting it back is what vet warns about and is fine here.
			*(*uintptr)(unsafe.Pointer(psize)) = 128 //nolint:govet
		}
		setErr(errorInsufficientBuffer)
		return 0
	}
	return 1
}

// BOOL WINAPI UpdateProcThreadAttribute(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD_PTR, PVOID, SIZE_T, PVOID, PSIZE_T)
func polyUpdateProcThreadAttribute(list, flags, attr, val, size, prev, ret uintptr) uintptr {
	if realUpdateProcThreadAttribute != 0 {
		r, _, e := syscall.SyscallN(realUpdateProcThreadAttribute, list, flags, attr, val, size, prev, ret)
		if r == 0 {
			setErr(uintptr(e))
		}
		return r
	}
	return 1
}

// VOID WINAPI DeleteProcThreadAttributeList(LPPROC_THREAD_ATTRIBUTE_LIST)
func polyDeleteProcThreadAttributeList(list uintptr) uintptr {
	if realDeleteProcThreadAttributeList != 0 {
		syscall.SyscallN(realDeleteProcThreadAttributeList, list)
	}
	return 0
}

// SOCKET WSAAPI WSASocketW(int, int, int, LPWSAPROTOCOL_INFOW, GROUP, DWORD)
//
// WSASocketW exists on XP, so this is an override rather than a polyfill: net creates
// every socket with WSA_FLAG_NO_HANDLE_INHERIT (Windows 7 SP1+), which XP rejects with
// WSAEINVAL, and Go has no fallback. On that exact failure the call is retried without
// the flag and the handle is made non-inheritable afterwards, which is what the flag
// would have done atomically. Anything else is passed through untouched.
func polyWSASocketW(af, typ, proto, info, group, flags uintptr) uintptr {
	const (
		invalidSocket        = ^uintptr(0)
		wsaFlagNoHandleInher = 0x80
		wsaeinval            = 10022
		handleFlagInherit    = 1
	)
	wsaSocketW := realProc("ws2_32.dll", "WSASocketW")
	s, _, e := syscall.SyscallN(wsaSocketW, af, typ, proto, info, group, flags)
	if s == invalidSocket && flags&wsaFlagNoHandleInher != 0 && e == wsaeinval {
		s, _, e = syscall.SyscallN(wsaSocketW, af, typ, proto, info, group, flags&^wsaFlagNoHandleInher)
		if s != invalidSocket {
			syscall.SyscallN(setHandleInformation, s, handleFlagInherit, 0)
			return s
		}
	}
	if s == invalidSocket {
		setErr(uintptr(e))
	}
	return s
}

// HANDLE WINAPI CreateEventExW(LPSECURITY_ATTRIBUTES, LPCWSTR, DWORD dwFlags, DWORD dwDesiredAccess) - Vista+.
// The flags are just the two CreateEventW booleans packed together; the access mask
// has no XP equivalent and is dropped (CreateEventW grants EVENT_ALL_ACCESS).
func polyCreateEventExW(attrs, name, flags, access uintptr) uintptr {
	const (
		createEventManualReset = 1
		createEventInitialSet  = 2
	)
	manual := (flags & createEventManualReset) >> 0
	initial := (flags & createEventInitialSet) >> 1
	h, _, e := syscall.SyscallN(createEventW, attrs, manual, initial, name)
	if h == 0 {
		setErr(uintptr(e))
	}
	return h
}

var realCreateProcessW = realProc("kernel32.dll", "CreateProcessW")

// XP has no attribute-list API. Give CreateProcessW a plain STARTUPINFO on that
// system, keeping the caller's STARTUPINFOEX untouched. Forward unchanged whenever
// the real attribute API exists. Removing flags after a failed native call could
// silently discard valid attributes and reuse a command line the call has modified.
func polyCreateProcessW(app, cmd, processAttrs, threadAttrs, inherit, flags, env, cwd, startup, result uintptr) uintptr {
	const extendedStartupInfoPresent = 0x80000
	var plain syscall.StartupInfo
	si := (*syscall.StartupInfo)(unsafe.Pointer(startup))
	if realInitializeProcThreadAttributeList == 0 && flags&extendedStartupInfoPresent != 0 {
		if startup == 0 {
			setErr(errorInvalidParameter)
			return 0
		}
		plain = *si
		plain.Cb = uint32(unsafe.Sizeof(plain))
		si = &plain
		flags &^= extendedStartupInfoPresent
	}
	r, _, e := syscall.SyscallN(realCreateProcessW, app, cmd, processAttrs, threadAttrs,
		inherit, flags, env, cwd, uintptr(unsafe.Pointer(si)), result)
	if r == 0 {
		setErr(uintptr(e))
	}
	return r
}

var realNtCreateFile = realProc("ntdll.dll", "NtCreateFile")
var getFileInformationByHandle = syscall.GetFileInformationByHandle

type unicodeString struct {
	length, maximumLength uint16
	buffer                *uint16
}

type objectAttributes struct {
	length                          uint32
	root                            uintptr
	name                            *unicodeString
	attributes                      uint32
	securityDescriptor, securityQoS uintptr
}

// Go 1.26 RemoveAll opens each child relative to its already opened parent with
// OBJ_DONT_REPARSE. XP/7 reject that flag. For a single relative component, opening
// the reparse point itself and checking its attributes preserves the no-follow
// contract. Multi-component paths are deliberately not retried: their intermediate
// junctions could otherwise escape the root. This is not a general os.Root emulation.
func polyNtCreateFile(result, access, attrs, iosb, allocation, fileAttrs, share, disposition, options, ea, eaLen uintptr) uintptr {
	const (
		objDontReparse                = 0x1000
		fileOpenReparsePoint          = 0x200000
		statusInvalidParameter        = 0xc000000d
		statusReparsePointEncountered = 0xc000050b
		statusAccessDenied            = 0xc0000022
	)
	r, _, _ := syscall.SyscallN(realNtCreateFile, result, access, attrs, iosb, allocation,
		fileAttrs, share, disposition, options, ea, eaLen)
	if r != statusInvalidParameter || attrs == 0 || result == 0 || disposition != 1 || options&0x30 == 0 {
		return r
	}
	oa := (*objectAttributes)(unsafe.Pointer(attrs))
	if oa.attributes&objDontReparse == 0 || oa.root == 0 || oa.name == nil || oa.name.buffer == nil || oa.name.length == 0 || oa.name.length%2 != 0 {
		return r
	}
	name := unsafe.Slice(oa.name.buffer, int(oa.name.length/2))
	for _, c := range name {
		if c == '\\' || c == '/' || c == ':' || c == 0 {
			return r
		}
	}
	if syscall.UTF16ToString(name) == ".." {
		return r
	}
	copyAttrs := *oa
	copyAttrs.attributes &^= objDontReparse
	r, _, _ = syscall.SyscallN(realNtCreateFile, result, access, uintptr(unsafe.Pointer(&copyAttrs)),
		iosb, allocation, fileAttrs, share, disposition, options|fileOpenReparsePoint, ea, eaLen)
	if int32(r) < 0 {
		return r
	}
	hp := (*syscall.Handle)(unsafe.Pointer(result))
	var info syscall.ByHandleFileInformation
	if err := getFileInformationByHandle(*hp, &info); err != nil {
		syscall.CloseHandle(*hp)
		*hp = 0
		return statusAccessDenied // refuse rather than silently weaken no-follow
	}
	if info.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		syscall.CloseHandle(*hp)
		*hp = 0
		return statusReparsePointEncountered
	}
	return r
}
