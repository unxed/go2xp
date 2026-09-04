#include "textflag.h"

// The Go 386 assembler has no RET $imm; encode "ret imm16" by hand.
#define STDRET(n) BYTE $0xC2; WORD $n

// GO2XPTBL layout (all little-endian u32 unless noted):
//   +0  magic   "GO2XPTBL"
//   +8  version u32 = 1
//   +12 count   u32
//   +16 entries, 16 bytes each:
//        +0 dll  name (C string, VA)
//        +4 func name (C string, VA)
//        +8 polyfill VA (0 = none; entry only marks an own slot)
//        +12 own IAT slot VA (0 = none)
//
// Polyfills are stdcall: args on stack, callee pops them (RET $n), EAX = result.
// They must not touch the Go runtime (no g, no TLS): the early ones are called
// from runtime.osinit before anything exists.

DATA go2xp_table+0(SB)/8, $"GO2XPTBL"
DATA go2xp_table+8(SB)/4, $1
DATA go2xp_table+12(SB)/4, $3
// kernel32!WerSetFlags -> xp_WerSetFlags
DATA go2xp_table+16(SB)/4, $go2xp_s_kernel32(SB)
DATA go2xp_table+20(SB)/4, $go2xp_s_WerSetFlags(SB)
DATA go2xp_table+24(SB)/4, $·xp_WerSetFlags(SB)
DATA go2xp_table+28(SB)/4, $0
// kernel32!GetProcAddress: own slot only (do not redirect)
DATA go2xp_table+32(SB)/4, $go2xp_s_kernel32(SB)
DATA go2xp_table+36(SB)/4, $go2xp_s_GetProcAddress(SB)
DATA go2xp_table+40(SB)/4, $0
DATA go2xp_table+44(SB)/4, $go2xp_GetProcAddress(SB)
// kernel32!LoadLibraryExW: own slot only
DATA go2xp_table+48(SB)/4, $go2xp_s_kernel32(SB)
DATA go2xp_table+52(SB)/4, $go2xp_s_LoadLibraryExW(SB)
DATA go2xp_table+56(SB)/4, $0
DATA go2xp_table+60(SB)/4, $go2xp_LoadLibraryExW(SB)
GLOBL go2xp_table(SB), NOPTR, $64

DATA go2xp_s_kernel32+0(SB)/8, $"kernel32"
DATA go2xp_s_kernel32+8(SB)/8, $".dll\x00\x00\x00\x00"
GLOBL go2xp_s_kernel32(SB), RODATA|NOPTR, $16

DATA go2xp_s_WerSetFlags+0(SB)/8, $"WerSetFl"
DATA go2xp_s_WerSetFlags+8(SB)/8, $"ags\x00\x00\x00\x00\x00"
GLOBL go2xp_s_WerSetFlags(SB), RODATA|NOPTR, $16

DATA go2xp_s_GetProcAddress+0(SB)/8, $"GetProcA"
DATA go2xp_s_GetProcAddress+8(SB)/8, $"ddress\x00\x00"
GLOBL go2xp_s_GetProcAddress(SB), RODATA|NOPTR, $16

DATA go2xp_s_LoadLibraryExW+0(SB)/8, $"LoadLibr"
DATA go2xp_s_LoadLibraryExW+8(SB)/8, $"aryExW\x00\x00"
GLOBL go2xp_s_LoadLibraryExW(SB), RODATA|NOPTR, $16

// func tableAddr() uintptr
TEXT ·tableAddr(SB), NOSPLIT, $0-4
	LEAL	go2xp_table(SB), AX
	MOVL	AX, ret+0(FP)
	RET

// HRESULT WINAPI WerSetFlags(DWORD dwFlags) — Vista+. No-op: S_OK.
TEXT ·xp_WerSetFlags(SB), NOSPLIT|NOFRAME, $0-0
	XORL	AX, AX
	STDRET(4)
