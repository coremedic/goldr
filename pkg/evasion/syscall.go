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
	RVA DWORD
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

	fmt.Printf("Ntdll: 0x%x\nModuleExportsDirAddr: 0x%x\nExportsNumberOfNames: %d\nExportsAddressOfNames: 0x%x\nExportsAddressOfFunctions: 0x%x\nExportsAddressOfOrdinals: 0x%x\n", ntdllBase, modExpDirAddr, expNumNames, expAddrNames, expAddrFunc, expAddrOrd)
}

// adapted from github.com/f1zm0/acheron/
// Parses syscalls in Ntdll
func ParseSyscalls() []*Syscall {
	modExpDirAddr := GetModuleExportsDirAddr(ntdllBase)
	expNumNames := GetExportsNumberOfNames(modExpDirAddr)
	expAddrNames := GetExportsAddressOfNames(ntdllBase, modExpDirAddr)
	expAddrFunc := GetExportsAddressOfFunctions(ntdllBase, modExpDirAddr)
	expAddrOrd := GetExportsAddressOfOrdinals(ntdllBase, modExpDirAddr)

	syscallStubs := make([]*Syscall, 0)
	for i := uint32(0); i < expNumNames; i++ {
		fn := ReadCStringAt(ntdllBase, uint32(ReadDwordAtOffset(expAddrNames, i*4)))
		if fn[0] == 'Z' && fn[1] == 'w' {
			fn[0] = 'N'
			fn[1] = 't'
			nameOrd := ReadWordAtOffset(expAddrOrd, i*2)
			rva := ReadDwordAtOffset(expAddrFunc, uint32(nameOrd*4))

			syscallStubs = append(syscallStubs, &Syscall{
				Name: string(fn),
				RVA:  rva,
				VA:   RVA2VA(ntdllBase, uint32(rva)),
			})
		}
	}
	return syscallStubs
}
