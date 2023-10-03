package evasion

// Assembly function stubs

func GetNtdllBase() uintptr
func GetKernel32Base() uintptr
func GetModuleExportsDirAddr(modAddr uintptr) uintptr
func GetExportsNumberOfNames(exportsAddr uintptr) uintptr
func GetExportsAddressOfFunctions(modAddr uintptr, exportsAddr uintptr) uintptr
func GetExportsAddressOfNames(modAddr uintptr, exportsAddr uintptr) uintptr
func GetExportsAddressOfOrdinals(modAddr uintptr, exportsAddr uintptr) uintptr
