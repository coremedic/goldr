#include "textflag.h" // https://go.dev/src/runtime/textflag.h

// Largely based on https://github.com/f1zm0/acheron/blob/main/internal/resolver/ldr_amd64.s

// func GetNtdllBase() uintptr
TEXT ·GetNtdllBase(SB), $0-16
	//All operations push values into AX
	//PEB
	MOVQ 0x60(GS), AX
	//PEB->LDR
	MOVQ 0x18(AX),AX

	//LDR->InMemoryOrderModuleList
	MOVQ 0x20(AX),AX

	//Flink (get next element)
	MOVQ (AX),AX

	//Flink - 0x10 -> _LDR_DATA_TABLE_ENTRY
	//_LDR_DATA_TABLE_ENTRY->DllBase (offset 0x30)
	//NTDLL is first module
	MOVQ 0x20(AX),CX
	MOVQ CX, start+0(FP)
	
	MOVQ 0x30(AX),CX
	MOVQ CX, size+8(FP)
		
	RET

// func GetKernel32Base() uintptr
TEXT ·GetKernel32Base(SB), $0-16
    // PEB
    MOVQ 0x60(GS), AX

    // PEB->LDR
    MOVQ 0x18(AX),AX

    // LDR->InMemoryOrderModuleList
    MOVQ 0x20(AX),AX

    // Move to the next module (ntdll.dll is the first module)
    MOVQ (AX),AX

    // Move to the next module (kernel32.dll is the second module)
    MOVQ (AX),AX

    // Flink - 0x10 -> _LDR_DATA_TABLE_ENTRY
    // _LDR_DATA_TABLE_ENTRY->DllBase (offset 0x30)
    // kernel32.dll is second module
    MOVQ 0x20(AX),CX
    MOVQ CX, start+0(FP)

    MOVQ 0x30(AX),CX
    MOVQ CX, size+8(FP)

	RET

// func GetModuleExportsDirAddr(modAddr uintptr) uintptr
TEXT ·GetModuleExportsDirAddr(SB), NOSPLIT, $0-8 
	// Load moduleAddr arg into AX
	MOVQ modAddr+0(FP), AX

	// If moduleAddr is null, error case
	TESTQ AX, AX
	JZ ERROR

	// Zero out R15 and R14
	XORQ R15, R15
    XORQ R14, R14

	// IMAGE_DOS_HEADER -> e_lfanew
	MOVB 0x3C(AX), R15
	// R15 = modAddr + R15 get absolute addr of PE header
	ADDQ AX, R15

	// PE Header -> IMAGE_DATA_DIRECTORY 
	// Get Exports Directory in IMAGE_DATA_DIRECTORY
	ADDQ $0x88, R15 

	// AX = modAddr + IMAGE_DATA_DIRECTORY.VirtualAddress
	ADDL (R15), R14
	ADDQ R14, AX

	// Return Module Exports Directory
	MOVQ AX, ret+8(FP)
	RET

ERROR:
	// ERROR case: return 0
	MOVQ $0, ret+8(FP)
	RET

// func GetExportsNumberOfNames(exportsAddr uintptr) uint32
TEXT ·GetExportsNumberOfNames(SB), NOSPLIT, $0-8
	// Load exportsAddr into AX
	MOVQ exportsAddr+0(FP), AX

	// If exportsAddr is null, error case
	TESTQ AX, AX
	JZ ERROR

	// Zero out R15
	XORQ R15, R15

	// Get IMAGE_EXPORT_DIRECTORY.NumberOfNames
	MOVL 0x18(AX), R15

	// Return IMAGE_EXPORT_DIRECTORY.NumberOfNames
	MOVL R15, ret+8(FP)
	RET

ERROR: 
	// ERROR case: return 0
	MOVQ $0, ret+8(FP)
	RET

// func GetExportsAddressOfFunctions(modAddr uintptr, exportsAddr uintptr) uintptr
TEXT ·GetExportsAddressOfFunctions(SB), NOSPLIT, $0-16
	// Load modAddr into AX 
	MOVQ modAddr+0(FP), AX
	// Load exportsAddr into R8
	MOVQ exportsAddr+8(FP), R8

	// If modAddr is null, error case
	TESTQ AX, AX
	JZ ERROR
	// If exportsAddr is null, error case
	TESTQ R8, R8
	JZ ERROR

	// Zero out Source Index
	XORQ SI, SI

	// Get IMAGE_EXPORT_DIRECTORY.AddressOfFunctions
	MOVL 0x1C(R8), SI
	// AX = exportsAddr + AddressOfFunctions
	ADDQ SI, AX

	// Return IMAGE_EXPORT_DIRECTORY.AddressOfFunctions
	MOVQ AX, ret+16(FP)
	RET

ERROR:
	// ERROR case: return 0
	MOVQ $0, ret+8(FP)
	RET

// func GetExportsAddressOfNames(modAddr uintptr, exportsAddr uintptr) uintptr
TEXT ·GetExportsAddressOfNames(SB), NOSPLIT, $0-16
	// Load modAddr into AX 
	MOVQ modAddr+0(FP), AX
	// Load exportsAddr into R8
	MOVQ exportsAddr+8(FP), R8

	// If modAddr is null, error case
	TESTQ AX, AX
	JZ ERROR
	// If exportsAddr is null, error case
	TESTQ R8, R8
	JZ ERROR

	// Zero out Source Index 
	XORQ SI, SI

	// Get IMAGE_EXPORT_DIRECTORY.AddressOfNames
	MOVL 0x20(R8), SI
	// AX = exportsAddr + AddressOfNames
	ADDQ SI, AX

	// Return IMAGE_EXPORT_DIRECTORY.AddressOfNames
	MOVQ AX, ret+16(FP)
	RET

ERROR:
	// ERROR case: return 0
	MOVQ $0, ret+8(FP)
	RET

// func GetExportsAddressOfOrdinals(modAddr uintptr, exportsAddr uintptr) uintptr
TEXT ·GetExportsAddressOfOrdinals(SB), NOSPLIT, $0-16
	// Load modAddr into AX 
	MOVQ modAddr+0(FP), AX
	// Load exportsAddr into R8
	MOVQ exportsAddr+8(FP), R8

	// If modAddr is null, error case
	TESTQ AX, AX
	JZ ERROR
	// If exportsAddr is null, error case
	TESTQ R8, R8
	JZ ERROR

	// Zero out Source Index
	XORQ SI, SI

	// Get IMAGE_EXPORT_DIRECTORY.AddressOfOrdinals
	MOVL 0x24(R8), SI
	// AX = exportsAddr + AddressOfNames
	ADDQ SI, AX

	// Return IMAGE_EXPORT_DIRECTORY.AddressOfOrdinals
	MOVQ AX, ret+16(FP)
	RET

ERROR:
	// ERROR case: return 0
	MOVQ $0, ret+8(FP)
	RET


// The following functins are from: https://github.com/f1zm0/acheron/blob/main/pkg/memory/helpers_amd64.s

// func RVA2VA(moduleBase uintptr, rva uint32) uintptr
TEXT ·RVA2VA(SB),NOSPLIT,$0-16
    MOVQ moduleBase+0(FP), AX
    XORQ DI, DI

    MOVL rva+8(FP), DI
    ADDQ DI, AX

    MOVQ AX, ret+16(FP)
    RET


// func ReadDwordAtOffset(start uintptr, offset uint32) DWORD
TEXT ·ReadDwordAtOffset(SB),NOSPLIT,$0-16
    MOVQ start+0(FP), AX
    MOVL offset+8(FP), R8

    XORQ DI, DI
    ADDQ R8, AX
    MOVL (AX), DI

    MOVL DI, ret+16(FP)
    RET


// func ReadWordAtOffset(start uintptr, offset uint32) WORD
TEXT ·ReadWordAtOffset(SB),NOSPLIT,$0-16
    MOVQ start+0(FP), AX
    MOVL offset+8(FP), R8

    XORQ DI, DI
    ADDQ R8, AX
    MOVW (AX), DI

    MOVW DI, ret+16(FP)
    RET


// func ReadByteAtOffset(start uintptr, offset uint32) uint8
TEXT ·ReadByteAtOffset(SB),NOSPLIT,$0-16
    MOVQ start+0(FP), AX
    MOVL offset+8(FP), R8

    XORQ DI, DI
    ADDQ R8, AX
    MOVB (AX), DI

    MOVB DI, ret+16(FP)
    RET
