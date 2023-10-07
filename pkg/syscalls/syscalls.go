package syscalls

import (
	"fmt"

	"github.com/coremedic/goldr/internal/types"
)

type Syscaller interface {
	Syscall(fnName string, args ...uintptr) (uint32, error)
}

var (
	ntdllBase  uintptr    = GetNtdllBase()
	ntSyscalls []*Syscall = parseNtSyscalls()
)

func init() {
	getCleanTrampolines(ntSyscalls)
}

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

type IndirectSyscaller struct{}

func (i IndirectSyscaller) Syscall(fnName string, args ...uintptr) (uint32, error) {
	var syscall *Syscall
	for _, sc := range ntSyscalls {
		if sc.Name == fnName {
			syscall = sc
			break
		}
	}
	if syscall.Name == "" {
		return 1, fmt.Errorf("failed to find syscall")
	}
	ret := ExecIndirectSyscall(syscall.SSN, syscall.TrampolinePtr, args...)
	if !types.NT_SUCCESS(ret) {
		return ret, fmt.Errorf("failed with code: 0x%x", ret)
	}
	return ret, nil
}
