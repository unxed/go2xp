#include "textflag.h"

// The Go 386 assembler has no "RET $imm"; encode "ret imm16" by hand.
#define STDRET(n) BYTE $0xC2; WORD $n

// GO2XPTBL, the contract between this package and cmd/go2xp:
//   +0  magic   "GO2XPTBL"
//   +8  version u32 = 1
//   +12 count   u32
//   +16 entries, 16 bytes each:
//        +0  VA of the DLL name  (C string)
//        +4  VA of the function name (C string)
//        +8  VA of the polyfill, or 0 when the entry only marks an own slot
//        +12 VA of the shim's own IAT slot, or 0
//
// An entry with a polyfill tells the patcher: if this function is missing on the
// target OS, point its IAT slot here. An entry with an own slot tells it: this
// slot belongs to the shim, never redirect it. Every own import needs an entry,
// otherwise the linker drops the slot as dead code.
//
// Polyfills are __stdcall: arguments on the stack, callee pops them (STDRET),
// EAX holds the result, EBX/ESI/EDI/EBP must be preserved. The ones here run
// during runtime.osinit, before the Go runtime exists, so they must not touch g,
// TLS or anything else Go-specific, and may only call out through the shim's own
// import slots.

DATA go2xp_table+0(SB)/8, $"GO2XPTBL"
DATA go2xp_table+8(SB)/4, $1
DATA go2xp_table+12(SB)/4, $9
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
// kernel32.dll!GetProcAddress: the shim's own import slot; the patcher must not redirect it
DATA go2xp_table+96(SB)/4, $go2xp_s_kernel32_dll(SB)
DATA go2xp_table+100(SB)/4, $go2xp_s_GetProcAddress(SB)
DATA go2xp_table+104(SB)/4, $0
DATA go2xp_table+108(SB)/4, $go2xp_GetProcAddress(SB)
// kernel32.dll!LoadLibraryExW: the shim's own import slot; the patcher must not redirect it
DATA go2xp_table+112(SB)/4, $go2xp_s_kernel32_dll(SB)
DATA go2xp_table+116(SB)/4, $go2xp_s_LoadLibraryExW(SB)
DATA go2xp_table+120(SB)/4, $0
DATA go2xp_table+124(SB)/4, $go2xp_LoadLibraryExW(SB)
// kernel32.dll!SetErrorMode: the shim's own import slot; the patcher must not redirect it
DATA go2xp_table+128(SB)/4, $go2xp_s_kernel32_dll(SB)
DATA go2xp_table+132(SB)/4, $go2xp_s_SetErrorMode(SB)
DATA go2xp_table+136(SB)/4, $0
DATA go2xp_table+140(SB)/4, $go2xp_SetErrorMode(SB)
// kernel32.dll!TerminateProcess: the shim's own import slot; the patcher must not redirect it
DATA go2xp_table+144(SB)/4, $go2xp_s_kernel32_dll(SB)
DATA go2xp_table+148(SB)/4, $go2xp_s_TerminateProcess(SB)
DATA go2xp_table+152(SB)/4, $0
DATA go2xp_table+156(SB)/4, $go2xp_TerminateProcess(SB)
GLOBL go2xp_table(SB), NOPTR, $160

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

DATA go2xp_s_LoadLibraryExW+0(SB)/8, $"LoadLibr"
DATA go2xp_s_LoadLibraryExW+8(SB)/8, $"aryExW\x00\x00"
GLOBL go2xp_s_LoadLibraryExW(SB), RODATA|NOPTR, $16

DATA go2xp_s_RaiseFailFastException+0(SB)/8, $"RaiseFai"
DATA go2xp_s_RaiseFailFastException+8(SB)/8, $"lFastExc"
DATA go2xp_s_RaiseFailFastException+16(SB)/8, $"eption\x00\x00"
GLOBL go2xp_s_RaiseFailFastException(SB), RODATA|NOPTR, $24

DATA go2xp_s_SetErrorMode+0(SB)/8, $"SetError"
DATA go2xp_s_SetErrorMode+8(SB)/8, $"Mode\x00\x00\x00\x00"
GLOBL go2xp_s_SetErrorMode(SB), RODATA|NOPTR, $16

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

DATA go2xp_s_kernel32_dll+0(SB)/8, $"kernel32"
DATA go2xp_s_kernel32_dll+8(SB)/8, $".dll\x00\x00\x00\x00"
GLOBL go2xp_s_kernel32_dll(SB), RODATA|NOPTR, $16


// func tableAddr() uintptr
TEXT ·tableAddr(SB), NOSPLIT, $0-4
	LEAL	go2xp_table(SB), AX
	MOVL	AX, ret+0(FP)
	RET

// HRESULT WINAPI WerSetFlags(DWORD dwFlags) - Vista+.
// Windows Error Reporting only affects crash dialogs, so a no-op returning S_OK
// is enough: runtime.preventErrorDialogs also calls SetErrorMode, which XP has.
TEXT ·xp_WerSetFlags(SB), NOSPLIT|NOFRAME, $0-0
	XORL	AX, AX
	STDRET(4)

// HRESULT WINAPI WerGetFlags(HANDLE hProcess, PDWORD pdwFlags) - Vista+.
// Reports "no flags set" so that the WerSetFlags call that follows is a no-op too.
TEXT ·xp_WerGetFlags(SB), NOSPLIT|NOFRAME, $0-0
	MOVL	8(SP), AX	// pdwFlags
	TESTL	AX, AX
	JZ	wgf_done
	MOVL	$0, (AX)
wgf_done:
	XORL	AX, AX
	STDRET(8)

// UINT WINAPI GetErrorMode(void) - Vista+.
// XP has no getter, but SetErrorMode returns the previous mode, so set-and-restore
// recovers it. This races with a concurrent SetErrorMode, which is acceptable here:
// the runtime calls it once from preventErrorDialogs during osinit.
TEXT ·xp_GetErrorMode(SB), NOSPLIT|NOFRAME, $0-0
	PUSHL	BX
	SUBL	$4, SP		// stdcall args are pushed by hand: the callee pops them,
	MOVL	$0, 0(SP)	// which the assembler's PUSH/POP balance check cannot see
	MOVL	go2xp_SetErrorMode(SB), AX
	CALL	AX
	MOVL	AX, BX		// BX = previous mode
	SUBL	$4, SP
	MOVL	BX, 0(SP)
	MOVL	go2xp_SetErrorMode(SB), AX
	CALL	AX		// put it back
	MOVL	BX, AX
	POPL	BX
	RET

// HANDLE WINAPI CreateWaitableTimerExW(LPSECURITY_ATTRIBUTES, LPCWSTR, DWORD, DWORD) - Vista+.
// Returning NULL is a supported outcome for runtime.initHighResTimer: it clears
// haveHighResTimer and the runtime falls back to winmm timeBeginPeriod, which is
// exactly the pre-1.23 behaviour and works on XP.
TEXT ·xp_CreateWaitableTimerExW(SB), NOSPLIT|NOFRAME, $0-0
	XORL	AX, AX
	STDRET(16)

// VOID WINAPI RaiseFailFastException(PEXCEPTION_RECORD, PCONTEXT, DWORD) - Win7+.
// Fail-fast means "die now, no handlers, no debugger dialog". TerminateProcess on
// the current-process pseudo-handle is the closest XP equivalent; the exit code is
// STATUS_FAIL_FAST_EXCEPTION so crash reports still look the same. Never returns.
TEXT ·xp_RaiseFailFastException(SB), NOSPLIT|NOFRAME, $0-0
	SUBL	$8, SP
	MOVL	$-1, 0(SP)		// GetCurrentProcess() pseudo-handle
	MOVL	$0xC0000409, 4(SP)	// STATUS_FAIL_FAST_EXCEPTION
	MOVL	go2xp_TerminateProcess(SB), AX
	CALL	AX
	INT	$3		// unreachable
	STDRET(12)
