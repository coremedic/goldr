package syscalls

import "github.com/coremedic/goldr/internal/types"

/*
* Syscall structure
 */
type Syscall struct {
	// Direct or Indirect syscall
	Method string `default:"indirect"`
	// Name of syscall i.e. "NtVirtualProtect"
	Name string
	// Relative Virtual Address of syscall
	RVA types.DWORD
	// Virtual Address of syscall (pointer)
	VA uintptr
	// System Service Number (Syscall ID)
	SSN uint16
	// Pointer to clean trampoline
	TrampolinePtr uintptr
}

// adapted from github.com/f1zm0/acheron/
// Parses syscalls in Ntdll
func parseNtSyscalls() []*Syscall {
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
