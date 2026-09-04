#include "textflag.h"

// The Go 386 assembler has no "RET $imm"; encode "ret imm16" by hand.
#define STDRET(n) BYTE $0xC2; WORD $n

// A handle that xp_LoadLibraryExW returns for a DLL that does not exist on the target.
// Module handles are image bases and therefore 64K-aligned, so this value can never
// collide with a real one.
#define SENTINEL $0x476F3258

// GO2XPTBL, the contract between this package and cmd/go2xp:
//   +0  magic   "GO2XPTBL"
//   +8  version u32 = 1
//   +12 count   u32
//   +16 entries, 16 bytes each:
//        +0  VA of the DLL name  (C string, lowercase)
//        +4  VA of the function name (C string)
//        +8  VA of the polyfill, or 0 when the entry only marks an own slot
//        +12 VA of the shim's own IAT slot, or 0
//
// An entry with a polyfill tells the patcher: if this function is missing on the target
// OS, point its IAT slot here. An entry with an own slot tells it: this slot belongs to
// the shim, never redirect it. An entry may carry both, which is what the two hooks do.
// Every own import needs an entry, otherwise the linker drops the slot as dead code.
//
// Polyfills are __stdcall: arguments on the stack, callee pops them (STDRET), EAX holds
// the result, EBX/ESI/EDI/EBP must be preserved. The early ones run during
// runtime.osinit, before the Go runtime exists, so they must not touch g, TLS or anything
// else Go-specific, and may only call out through the shim's own import slots. The late
// ones are trampolines into Go (see cb* in shim_windows_386.go).
//
// Note on stack discipline: the assembler rejects a function whose PUSH and POP counts
// differ, and stdcall argument pushes always break that (the callee pops them), so
// arguments are written with SUBL/MOVL instead of PUSHL.

DATA go2xp_table+0(SB)/8, $"GO2XPTBL"
DATA go2xp_table+8(SB)/4, $1
DATA go2xp_table+12(SB)/4, $15
// kernel32.dll!WerSetFlags -> xp_WerSetFlags
DATA go2xp_table+16(SB)/4, $go2xp_s_kernel32_dll(SB)
DATA go2xp_table+20(SB)/4, $go2xp_s_WerSetFlags(SB)
DATA go2xp_table+24(SB)/4, $·xp_WerSetFlags(SB)
DATA go2xp_table+28(SB)/4, $0
// kernel32.dll!WerGetFlags -> xp_WerGetFlags
DATA go2xp_table+32(SB)/4, $go2xp_s_kernel32_dll(SB)
DATA go2xp_table+36(SB)/4, $go2xp_s_WerGetFlags(SB)
DATA go2xp_table+40(SB)/4, $·xp_WerGetFlags(SB)
DATA go2xp_table+44(SB)/4, $0
// kernel32.dll!GetErrorMode -> xp_GetErrorMode
DATA go2xp_table+48(SB)/4, $go2xp_s_kernel32_dll(SB)
DATA go2xp_table+52(SB)/4, $go2xp_s_GetErrorMode(SB)
DATA go2xp_table+56(SB)/4, $·xp_GetErrorMode(SB)
DATA go2xp_table+60(SB)/4, $0
// kernel32.dll!CreateWaitableTimerExW -> xp_CreateWaitableTimerExW
DATA go2xp_table+64(SB)/4, $go2xp_s_kernel32_dll(SB)
DATA go2xp_table+68(SB)/4, $go2xp_s_CreateWaitableTimerExW(SB)
DATA go2xp_table+72(SB)/4, $·xp_CreateWaitableTimerExW(SB)
DATA go2xp_table+76(SB)/4, $0
// kernel32.dll!RaiseFailFastException -> xp_RaiseFailFastException
DATA go2xp_table+80(SB)/4, $go2xp_s_kernel32_dll(SB)
DATA go2xp_table+84(SB)/4, $go2xp_s_RaiseFailFastException(SB)
DATA go2xp_table+88(SB)/4, $·xp_RaiseFailFastException(SB)
DATA go2xp_table+92(SB)/4, $0
// kernel32.dll!GetQueuedCompletionStatusEx -> xp_GetQueuedCompletionStatusEx
DATA go2xp_table+96(SB)/4, $go2xp_s_kernel32_dll(SB)
DATA go2xp_table+100(SB)/4, $go2xp_s_GetQueuedCompletionStatusEx(SB)
DATA go2xp_table+104(SB)/4, $·xp_GetQueuedCompletionStatusEx(SB)
DATA go2xp_table+108(SB)/4, $0
// kernel32.dll!CancelIoEx -> xp_CancelIoEx
DATA go2xp_table+112(SB)/4, $go2xp_s_kernel32_dll(SB)
DATA go2xp_table+116(SB)/4, $go2xp_s_CancelIoEx(SB)
DATA go2xp_table+120(SB)/4, $·xp_CancelIoEx(SB)
DATA go2xp_table+124(SB)/4, $0
// kernel32.dll!LoadLibraryExW -> xp_LoadLibraryExW  (and the shim's own slot)
DATA go2xp_table+128(SB)/4, $go2xp_s_kernel32_dll(SB)
DATA go2xp_table+132(SB)/4, $go2xp_s_LoadLibraryExW(SB)
DATA go2xp_table+136(SB)/4, $·xp_LoadLibraryExW(SB)
DATA go2xp_table+140(SB)/4, $go2xp_LoadLibraryExW(SB)
// kernel32.dll!GetProcAddress -> xp_GetProcAddress  (and the shim's own slot)
DATA go2xp_table+144(SB)/4, $go2xp_s_kernel32_dll(SB)
DATA go2xp_table+148(SB)/4, $go2xp_s_GetProcAddress(SB)
DATA go2xp_table+152(SB)/4, $·xp_GetProcAddress(SB)
DATA go2xp_table+156(SB)/4, $go2xp_GetProcAddress(SB)
// bcryptprimitives.dll!ProcessPrng -> xp_ProcessPrng
DATA go2xp_table+160(SB)/4, $go2xp_s_bcryptprimitives_dll(SB)
DATA go2xp_table+164(SB)/4, $go2xp_s_ProcessPrng(SB)
DATA go2xp_table+168(SB)/4, $·xp_ProcessPrng(SB)
DATA go2xp_table+172(SB)/4, $0
// kernel32.dll!SetErrorMode: the shim's own import slot; the patcher must not redirect it
DATA go2xp_table+176(SB)/4, $go2xp_s_kernel32_dll(SB)
DATA go2xp_table+180(SB)/4, $go2xp_s_SetErrorMode(SB)
DATA go2xp_table+184(SB)/4, $0
DATA go2xp_table+188(SB)/4, $go2xp_SetErrorMode(SB)
// kernel32.dll!TerminateProcess: the shim's own import slot; the patcher must not redirect it
DATA go2xp_table+192(SB)/4, $go2xp_s_kernel32_dll(SB)
DATA go2xp_table+196(SB)/4, $go2xp_s_TerminateProcess(SB)
DATA go2xp_table+200(SB)/4, $0
DATA go2xp_table+204(SB)/4, $go2xp_TerminateProcess(SB)
// kernel32.dll!GetQueuedCompletionStatus: the shim's own import slot; the patcher must not redirect it
DATA go2xp_table+208(SB)/4, $go2xp_s_kernel32_dll(SB)
DATA go2xp_table+212(SB)/4, $go2xp_s_GetQueuedCompletionStatus(SB)
DATA go2xp_table+216(SB)/4, $0
DATA go2xp_table+220(SB)/4, $go2xp_GetQueuedCompletionStatus(SB)
// kernel32.dll!CancelIo: the shim's own import slot; the patcher must not redirect it
DATA go2xp_table+224(SB)/4, $go2xp_s_kernel32_dll(SB)
DATA go2xp_table+228(SB)/4, $go2xp_s_CancelIo(SB)
DATA go2xp_table+232(SB)/4, $0
DATA go2xp_table+236(SB)/4, $go2xp_CancelIo(SB)
// advapi32.dll!SystemFunction036: the shim's own import slot; the patcher must not redirect it
DATA go2xp_table+240(SB)/4, $go2xp_s_advapi32_dll(SB)
DATA go2xp_table+244(SB)/4, $go2xp_s_SystemFunction036(SB)
DATA go2xp_table+248(SB)/4, $0
DATA go2xp_table+252(SB)/4, $go2xp_SystemFunction036(SB)
GLOBL go2xp_table(SB), NOPTR, $256

// DLLs that do not exist on the target at all. xp_LoadLibraryExW answers with the
// sentinel handle for these, and xp_GetProcAddress serves their exports from the
// table above. Names must be lowercase: the comparison only folds the input.
DATA go2xp_missing_dlls+0(SB)/4, $go2xp_s_bcryptprimitives_dll(SB)
DATA go2xp_missing_dlls+4(SB)/4, $0
GLOBL go2xp_missing_dlls(SB), RODATA|NOPTR, $8

DATA go2xp_s_CancelIo+0(SB)/8, $"CancelIo"
DATA go2xp_s_CancelIo+8(SB)/8, $"\x00\x00\x00\x00\x00\x00\x00\x00"
GLOBL go2xp_s_CancelIo(SB), RODATA|NOPTR, $16

DATA go2xp_s_CancelIoEx+0(SB)/8, $"CancelIo"
DATA go2xp_s_CancelIoEx+8(SB)/8, $"Ex\x00\x00\x00\x00\x00\x00"
GLOBL go2xp_s_CancelIoEx(SB), RODATA|NOPTR, $16

DATA go2xp_s_CreateWaitableTimerExW+0(SB)/8, $"CreateWa"
DATA go2xp_s_CreateWaitableTimerExW+8(SB)/8, $"itableTi"
DATA go2xp_s_CreateWaitableTimerExW+16(SB)/8, $"merExW\x00\x00"
GLOBL go2xp_s_CreateWaitableTimerExW(SB), RODATA|NOPTR, $24

DATA go2xp_s_GetErrorMode+0(SB)/8, $"GetError"
DATA go2xp_s_GetErrorMode+8(SB)/8, $"Mode\x00\x00\x00\x00"
GLOBL go2xp_s_GetErrorMode(SB), RODATA|NOPTR, $16

DATA go2xp_s_GetProcAddress+0(SB)/8, $"GetProcA"
DATA go2xp_s_GetProcAddress+8(SB)/8, $"ddress\x00\x00"
GLOBL go2xp_s_GetProcAddress(SB), RODATA|NOPTR, $16

DATA go2xp_s_GetQueuedCompletionStatus+0(SB)/8, $"GetQueue"
DATA go2xp_s_GetQueuedCompletionStatus+8(SB)/8, $"dComplet"
DATA go2xp_s_GetQueuedCompletionStatus+16(SB)/8, $"ionStatu"
DATA go2xp_s_GetQueuedCompletionStatus+24(SB)/8, $"s\x00\x00\x00\x00\x00\x00\x00"
GLOBL go2xp_s_GetQueuedCompletionStatus(SB), RODATA|NOPTR, $32

DATA go2xp_s_GetQueuedCompletionStatusEx+0(SB)/8, $"GetQueue"
DATA go2xp_s_GetQueuedCompletionStatusEx+8(SB)/8, $"dComplet"
DATA go2xp_s_GetQueuedCompletionStatusEx+16(SB)/8, $"ionStatu"
DATA go2xp_s_GetQueuedCompletionStatusEx+24(SB)/8, $"sEx\x00\x00\x00\x00\x00"
GLOBL go2xp_s_GetQueuedCompletionStatusEx(SB), RODATA|NOPTR, $32

DATA go2xp_s_LoadLibraryExW+0(SB)/8, $"LoadLibr"
DATA go2xp_s_LoadLibraryExW+8(SB)/8, $"aryExW\x00\x00"
GLOBL go2xp_s_LoadLibraryExW(SB), RODATA|NOPTR, $16

DATA go2xp_s_ProcessPrng+0(SB)/8, $"ProcessP"
DATA go2xp_s_ProcessPrng+8(SB)/8, $"rng\x00\x00\x00\x00\x00"
GLOBL go2xp_s_ProcessPrng(SB), RODATA|NOPTR, $16

DATA go2xp_s_RaiseFailFastException+0(SB)/8, $"RaiseFai"
DATA go2xp_s_RaiseFailFastException+8(SB)/8, $"lFastExc"
DATA go2xp_s_RaiseFailFastException+16(SB)/8, $"eption\x00\x00"
GLOBL go2xp_s_RaiseFailFastException(SB), RODATA|NOPTR, $24

DATA go2xp_s_SetErrorMode+0(SB)/8, $"SetError"
DATA go2xp_s_SetErrorMode+8(SB)/8, $"Mode\x00\x00\x00\x00"
GLOBL go2xp_s_SetErrorMode(SB), RODATA|NOPTR, $16

DATA go2xp_s_SystemFunction036+0(SB)/8, $"SystemFu"
DATA go2xp_s_SystemFunction036+8(SB)/8, $"nction03"
DATA go2xp_s_SystemFunction036+16(SB)/8, $"6\x00\x00\x00\x00\x00\x00\x00"
GLOBL go2xp_s_SystemFunction036(SB), RODATA|NOPTR, $24

DATA go2xp_s_TerminateProcess+0(SB)/8, $"Terminat"
DATA go2xp_s_TerminateProcess+8(SB)/8, $"eProcess"
DATA go2xp_s_TerminateProcess+16(SB)/8, $"\x00\x00\x00\x00\x00\x00\x00\x00"
GLOBL go2xp_s_TerminateProcess(SB), RODATA|NOPTR, $24

DATA go2xp_s_WerGetFlags+0(SB)/8, $"WerGetFl"
DATA go2xp_s_WerGetFlags+8(SB)/8, $"ags\x00\x00\x00\x00\x00"
GLOBL go2xp_s_WerGetFlags(SB), RODATA|NOPTR, $16

DATA go2xp_s_WerSetFlags+0(SB)/8, $"WerSetFl"
DATA go2xp_s_WerSetFlags+8(SB)/8, $"ags\x00\x00\x00\x00\x00"
GLOBL go2xp_s_WerSetFlags(SB), RODATA|NOPTR, $16

DATA go2xp_s_advapi32_dll+0(SB)/8, $"advapi32"
DATA go2xp_s_advapi32_dll+8(SB)/8, $".dll\x00\x00\x00\x00"
GLOBL go2xp_s_advapi32_dll(SB), RODATA|NOPTR, $16

DATA go2xp_s_bcryptprimitives_dll+0(SB)/8, $"bcryptpr"
DATA go2xp_s_bcryptprimitives_dll+8(SB)/8, $"imitives"
DATA go2xp_s_bcryptprimitives_dll+16(SB)/8, $".dll\x00\x00\x00\x00"
GLOBL go2xp_s_bcryptprimitives_dll(SB), RODATA|NOPTR, $24

DATA go2xp_s_kernel32_dll+0(SB)/8, $"kernel32"
DATA go2xp_s_kernel32_dll+8(SB)/8, $".dll\x00\x00\x00\x00"
GLOBL go2xp_s_kernel32_dll(SB), RODATA|NOPTR, $16

// func tableAddr() uintptr
TEXT ·tableAddr(SB), NOSPLIT, $0-4
	LEAL	go2xp_table(SB), AX
	MOVL	AX, ret+0(FP)
	RET

// HMODULE WINAPI LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
//
// Two jobs. First, a DLL listed in go2xp_missing_dlls resolves to the sentinel handle
// instead of failing, so that the runtime's "bcryptprimitives.dll not found" throw never
// happens and the lookups that follow reach xp_GetProcAddress. Second, XP rejects the
// LOAD_LIBRARY_SEARCH_* flags (0x1F00) with ERROR_INVALID_PARAMETER, so they are cleared.
//
// Clearing LOAD_LIBRARY_SEARCH_SYSTEM32 widens the search order back to the default,
// which is a DLL-planting risk the flag exists to prevent. Prepending the system
// directory, the way Go itself did before 1.21, is the proper fix and is still TODO.
TEXT ·xp_LoadLibraryExW(SB), NOSPLIT|NOFRAME, $0-0
	PUSHL	SI
	PUSHL	DI
	PUSHL	BX
	// return address at 12(SP); lpLibFileName 16(SP), hFile 20(SP), dwFlags 24(SP)
	MOVL	16(SP), BX		// the requested name, kept for each comparison
	LEAL	go2xp_missing_dlls(SB), DX

llx_entry:
	MOVL	(DX), DI		// candidate name, or NULL at the end of the list
	TESTL	DI, DI
	JZ	llx_forward
	MOVL	BX, SI

llx_cmp:
	MOVWLZX	(SI), AX		// UTF-16 unit against an ASCII byte
	CMPL	AX, $65			// fold 'A'-'Z' in the input; the table is lowercase
	JB	llx_folded
	CMPL	AX, $90
	JA	llx_folded
	ADDL	$32, AX
llx_folded:
	MOVBLZX	(DI), CX
	CMPL	AX, CX
	JNE	llx_next
	TESTL	AX, AX
	JZ	llx_sentinel		// both strings ended: it matched
	ADDL	$2, SI
	INCL	DI
	JMP	llx_cmp

llx_next:
	ADDL	$4, DX
	JMP	llx_entry

llx_sentinel:
	MOVL	SENTINEL, AX
	JMP	llx_ret

llx_forward:
	MOVL	24(SP), AX
	ANDL	$0xFFFFE0FF, AX		// clear LOAD_LIBRARY_SEARCH_* (0x1F00)
	SUBL	$12, SP
	MOVL	AX, 8(SP)
	MOVL	32(SP), AX		// hFile
	MOVL	AX, 4(SP)
	MOVL	28(SP), AX		// lpLibFileName
	MOVL	AX, 0(SP)
	MOVL	go2xp_LoadLibraryExW(SB), AX
	CALL	AX			// stdcall: the callee pops the 12 bytes

llx_ret:
	POPL	BX
	POPL	DI
	POPL	SI
	STDRET(12)

// FARPROC WINAPI GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
//
// This is the reason the whole design works with two slots: every lazily resolved import
// in the program - the runtime's own windowsFindfunc, syscall.GetProcAddress and
// therefore all of golang.org/x/sys/windows - funnels through here, so a polyfill in
// GO2XPTBL covers all of them at once, with no generated code to patch.
//
// The real function is asked first and always wins, so a polyfill is used only where the
// OS genuinely lacks the export. That keeps one patched binary correct across Windows
// versions: the same exe prefers the native CancelIoEx on Win7 and falls back to the
// CancelIo emulation on XP, with no profile involved at run time. The exception is the
// sentinel handle, which belongs to a DLL that is not there at all and can only be
// answered from the table.
//
// Setting forcePolyfills reverses the order, so a name the table knows is answered from
// the table even where the OS exports it. Anything the table does not know still goes to
// the real function - the point is to exercise the polyfills on a system that has the
// real ones, not to break every other lookup (see scripts/wine-test.sh).
TEXT ·xp_GetProcAddress(SB), NOSPLIT|NOFRAME, $0-0
	PUSHL	SI
	PUSHL	DI
	PUSHL	BX
	SUBL	$4, SP			// 0(SP): where a table miss should go next
	// return address at 16(SP); hModule 20(SP), lpProcName 24(SP)
	MOVL	$0, 0(SP)		// a miss fails, because the real call already ran
	MOVL	20(SP), AX
	CMPL	AX, SENTINEL
	JEQ	gpa_table		// a DLL that is not there: only the table can answer
	MOVL	·forcePolyfills(SB), AX
	TESTL	AX, AX
	JZ	gpa_real_first
	MOVL	$1, 0(SP)		// forced: a miss still has to reach the real export
	JMP	gpa_table

gpa_real_first:
	SUBL	$8, SP
	MOVL	32(SP), AX		// lpProcName
	MOVL	AX, 4(SP)
	MOVL	28(SP), AX		// hModule
	MOVL	AX, 0(SP)
	MOVL	go2xp_GetProcAddress(SB), AX
	CALL	AX
	TESTL	AX, AX
	JNZ	gpa_ret			// it exists here: nothing to emulate

gpa_table:
	MOVL	24(SP), BX
	CMPL	BX, $0x10000		// imported by ordinal: nothing to match by name
	JB	gpa_miss
	LEAL	go2xp_table(SB), DX
	MOVL	12(DX), CX		// entry count
	ADDL	$16, DX			// first entry

gpa_entry:
	TESTL	CX, CX
	JZ	gpa_miss
	MOVL	8(DX), AX		// polyfill VA
	TESTL	AX, AX
	JZ	gpa_next		// own-slot-only entry, nothing to serve
	MOVL	4(DX), DI		// this entry's function name
	MOVL	BX, SI

gpa_cmp:
	MOVBLZX	(DI), AX
	CMPB	(SI), AL		// GetProcAddress is case-sensitive: compare exactly
	JNE	gpa_next
	TESTL	AX, AX
	JZ	gpa_hit
	INCL	SI
	INCL	DI
	JMP	gpa_cmp

gpa_next:
	ADDL	$16, DX
	DECL	CX
	JMP	gpa_entry

gpa_hit:
	MOVL	8(DX), AX
	JMP	gpa_ret

gpa_miss:
	MOVL	0(SP), AX
	TESTL	AX, AX
	JZ	gpa_fail
	SUBL	$8, SP			// forced mode: everything else is still the OS's job
	MOVL	32(SP), AX		// lpProcName
	MOVL	AX, 4(SP)
	MOVL	28(SP), AX		// hModule
	MOVL	AX, 0(SP)
	MOVL	go2xp_GetProcAddress(SB), AX
	CALL	AX
	JMP	gpa_ret

gpa_fail:
	XORL	AX, AX			// the real call, if it ran, already set the error

gpa_ret:
	ADDL	$4, SP
	POPL	BX
	POPL	DI
	POPL	SI
	STDRET(8)

// BOOL WINAPI GetQueuedCompletionStatusEx(HANDLE port, LPOVERLAPPED_ENTRY entries,
//     ULONG count, PULONG removed, DWORD timeout, BOOL alertable) - Vista+.
//
// The last static import the runtime needs that XP does not have. Emulated with plain
// GetQueuedCompletionStatus, which dequeues exactly one packet, so netpoll gets one entry
// per call instead of up to 64: slower under load, but not different in behaviour.
//
// The three outcomes are kept faithful. A dequeued packet fills entries[0] and returns
// TRUE. A timeout returns FALSE with the last error already set to WAIT_TIMEOUT, which is
// what netpoll checks for. A packet belonging to a failed I/O makes the plain function
// return FALSE with a non-NULL OVERLAPPED, and the Ex form reports that as a normal
// dequeue, so it is turned back into TRUE here; the status stays in the OVERLAPPED where
// the caller reads it from. fAlertable has no equivalent and is ignored (the runtime
// always passes FALSE).
TEXT ·xp_GetQueuedCompletionStatusEx(SB), NOSPLIT|NOFRAME, $0-0
	PUSHL	BX
	PUSHL	SI
	PUSHL	DI
	// return address at 12(SP); port 16, entries 20, count 24, removed 28, timeout 32
	MOVL	24(SP), AX
	TESTL	AX, AX
	JZ	gqe_fail		// no room for even one entry
	SUBL	$12, SP			// scratch: bytes 0(SP), key 4(SP), overlapped 8(SP)
	MOVL	$0, 8(SP)
	SUBL	$20, SP			// arguments for GetQueuedCompletionStatus
	MOVL	48(SP), AX		// port
	MOVL	AX, 0(SP)
	LEAL	20(SP), AX		// &bytes
	MOVL	AX, 4(SP)
	LEAL	24(SP), AX		// &key
	MOVL	AX, 8(SP)
	LEAL	28(SP), AX		// &overlapped
	MOVL	AX, 12(SP)
	MOVL	64(SP), AX		// timeout
	MOVL	AX, 16(SP)
	MOVL	go2xp_GetQueuedCompletionStatus(SB), AX
	CALL	AX			// callee pops 20; scratch is at 0/4/8(SP) again
	TESTL	AX, AX
	JNZ	gqe_fill
	MOVL	8(SP), AX		// FALSE: was a packet still dequeued?
	TESTL	AX, AX
	JZ	gqe_unwind		// no - timeout or a real error, propagate it

gqe_fill:
	MOVL	32(SP), DI		// entries
	MOVL	4(SP), AX		// lpCompletionKey
	MOVL	AX, 0(DI)
	MOVL	8(SP), AX		// lpOverlapped
	MOVL	AX, 4(DI)
	MOVL	$0, 8(DI)		// Internal
	MOVL	0(SP), AX		// dwNumberOfBytesTransferred
	MOVL	AX, 12(DI)
	MOVL	40(SP), DI		// removed
	MOVL	$1, (DI)
	ADDL	$12, SP
	MOVL	$1, AX
	JMP	gqe_ret

gqe_unwind:
	ADDL	$12, SP

gqe_fail:
	XORL	AX, AX

gqe_ret:
	POPL	DI
	POPL	SI
	POPL	BX
	STDRET(24)

// BOOL WINAPI CancelIoEx(HANDLE hFile, LPOVERLAPPED lpOverlapped) - Vista+.
// A late polyfill: it is only ever called from ordinary goroutine context, so it is
// written in Go (polyCancelIoEx) and reached through this trampoline. Until init has
// installed the callback the trampoline reports failure, which is the correct answer for
// anything that manages to call it that early.
TEXT ·xp_CancelIoEx(SB), NOSPLIT|NOFRAME, $0-0
	MOVL	·cbCancelIoEx(SB), AX
	TESTL	AX, AX
	JZ	cix_early
	JMP	AX			// the callback pops the arguments itself

cix_early:
	XORL	AX, AX
	STDRET(8)

// BOOL WINAPI ProcessPrng(PBYTE pbData, SIZE_T cbData) - Win10+, bcryptprimitives.dll.
// XP's equivalent is advapi32!SystemFunction036, better known as RtlGenRandom: same
// argument layout, same cryptographic role, present since XP SP1. It returns BOOLEAN in
// AL, so the result is zero-extended before it becomes the BOOL the runtime tests.
TEXT ·xp_ProcessPrng(SB), NOSPLIT|NOFRAME, $0-0
	SUBL	$8, SP
	MOVL	16(SP), AX		// cbData
	MOVL	AX, 4(SP)
	MOVL	12(SP), AX		// pbData
	MOVL	AX, 0(SP)
	MOVL	go2xp_SystemFunction036(SB), AX
	CALL	AX
	MOVBLZX	AL, AX
	STDRET(8)

// HRESULT WINAPI WerSetFlags(DWORD dwFlags) - Vista+.
// Windows Error Reporting only affects crash dialogs, so a no-op returning S_OK is
// enough: runtime.preventErrorDialogs also calls SetErrorMode, which XP has.
TEXT ·xp_WerSetFlags(SB), NOSPLIT|NOFRAME, $0-0
	XORL	AX, AX
	STDRET(4)

// HRESULT WINAPI WerGetFlags(HANDLE hProcess, PDWORD pdwFlags) - Vista+.
// Reports "no flags set" so that the WerSetFlags call that follows is a no-op too.
TEXT ·xp_WerGetFlags(SB), NOSPLIT|NOFRAME, $0-0
	MOVL	8(SP), AX		// pdwFlags
	TESTL	AX, AX
	JZ	wgf_done
	MOVL	$0, (AX)
wgf_done:
	XORL	AX, AX
	STDRET(8)

// UINT WINAPI GetErrorMode(void) - Vista+.
// XP has no getter, but SetErrorMode returns the previous mode, so set-and-restore
// recovers it. This races with a concurrent SetErrorMode, which is acceptable here: the
// runtime calls it once from preventErrorDialogs during osinit.
TEXT ·xp_GetErrorMode(SB), NOSPLIT|NOFRAME, $0-0
	PUSHL	BX
	SUBL	$4, SP
	MOVL	$0, 0(SP)
	MOVL	go2xp_SetErrorMode(SB), AX
	CALL	AX
	MOVL	AX, BX			// BX = previous mode
	SUBL	$4, SP
	MOVL	BX, 0(SP)
	MOVL	go2xp_SetErrorMode(SB), AX
	CALL	AX			// put it back
	MOVL	BX, AX
	POPL	BX
	RET

// HANDLE WINAPI CreateWaitableTimerExW(LPSECURITY_ATTRIBUTES, LPCWSTR, DWORD, DWORD) - Vista+.
// Returning NULL is a supported outcome for runtime.initHighResTimer: it clears
// haveHighResTimer and the runtime falls back to winmm timeBeginPeriod, which is exactly
// the pre-1.23 behaviour and works on XP.
TEXT ·xp_CreateWaitableTimerExW(SB), NOSPLIT|NOFRAME, $0-0
	XORL	AX, AX
	STDRET(16)

// VOID WINAPI RaiseFailFastException(PEXCEPTION_RECORD, PCONTEXT, DWORD) - Win7+.
// Fail-fast means "die now, no handlers, no debugger dialog". TerminateProcess on the
// current-process pseudo-handle is the closest XP equivalent; the exit code is
// STATUS_FAIL_FAST_EXCEPTION so crash reports still look the same. Never returns.
TEXT ·xp_RaiseFailFastException(SB), NOSPLIT|NOFRAME, $0-0
	SUBL	$8, SP
	MOVL	$-1, 0(SP)		// GetCurrentProcess() pseudo-handle
	MOVL	$0xC0000409, 4(SP)	// STATUS_FAIL_FAST_EXCEPTION
	MOVL	go2xp_TerminateProcess(SB), AX
	CALL	AX
	INT	$3			// unreachable
	STDRET(12)
