package evasion

import "fmt"

var (
	ntdllBase uintptr = GetNtdllBase()
)

/*
* Syscall structure
 */
type Syscall struct {
	// Name of syscall i.e. "NtVirtualProtect"
	Name string
	// Relative Virtual Address of syscall
	RVA uint32
	// Virtual Address of syscall (pointer)
	VA uintptr
	// System Service Number (Syscall ID)
	SSN uint16
	// Pointer to clean trampoline
	TrampolinePtr uintptr
}

func Debug() {
	modExpDirAddr := GetModuleExportsDirAddr(ntdllBase)
	expNumNames := GetExportsNumberOfNames(modExpDirAddr)
	expAddrNames := GetExportsAddressOfNames(ntdllBase, modExpDirAddr)
	expAddrFunc := GetExportsAddressOfFunctions(ntdllBase, modExpDirAddr)
	expAddrOrd := GetExportsAddressOfOrdinals(ntdllBase, modExpDirAddr)

	fmt.Printf("Ntdll: 0x%x\nModuleExportsDirAddr: 0x%x\nExportsNumberOfNames: 0x%x\nExportsAddressOfNames: 0x%x\nExportsAddressOfFunctions: 0x%x\nExportsAddressOfOrdinals: 0x%x\n", ntdllBase, modExpDirAddr, expNumNames, expAddrNames, expAddrFunc, expAddrOrd)
}

// adapted from github.com/f1zm0/acheron/
// Parses syscalls in Ntdll
// func ParseSyscalls() []*Syscall {

// }
