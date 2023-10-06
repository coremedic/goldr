package syscalls

import (
	"fmt"
)

type Syscaller interface {
	Syscall(fnName string)
}

var (
	ntdllBase uintptr = GetNtdllBase()
)

func Debug() {
	modExpDirAddr := GetModuleExportsDirAddr(ntdllBase)
	expNumNames := GetExportsNumberOfNames(modExpDirAddr)
	expAddrNames := GetExportsAddressOfNames(ntdllBase, modExpDirAddr)
	expAddrFunc := GetExportsAddressOfFunctions(ntdllBase, modExpDirAddr)
	expAddrOrd := GetExportsAddressOfOrdinals(ntdllBase, modExpDirAddr)

	fmt.Printf("Ntdll: 0x%x\nModuleExportsDirAddr: 0x%x\nExportsNumberOfNames: %d\nExportsAddressOfNames: 0x%x\nExportsAddressOfFunctions: 0x%x\nExportsAddressOfOrdinals: 0x%x\n", ntdllBase, modExpDirAddr, expNumNames, expAddrNames, expAddrFunc, expAddrOrd)

	found := parseNtSyscalls()
	getCleanTrampolines(found)
	for _, sc := range found {
		fmt.Printf("Found syscall '%s'\n\tSSN: %d\n\tAddr: 0x%x\n\tTrampoline: 0x%x\n", sc.Name, sc.SSN, sc.VA, sc.TrampolinePtr)
	}
}
