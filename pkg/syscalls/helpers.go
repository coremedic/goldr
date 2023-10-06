package syscalls

import "github.com/coremedic/goldr/internal/types"

// Assembly function stubs

func GetNtdllBase() uintptr
func GetKernel32Base() uintptr
func GetModuleExportsDirAddr(modAddr uintptr) uintptr
func GetExportsNumberOfNames(exportsAddr uintptr) uint32
func GetExportsAddressOfFunctions(modAddr uintptr, exportsAddr uintptr) uintptr
func GetExportsAddressOfNames(modAddr uintptr, exportsAddr uintptr) uintptr
func GetExportsAddressOfOrdinals(modAddr uintptr, exportsAddr uintptr) uintptr
func GetTrampoline(stubAddr uintptr) uintptr

// Memory function stubs

func RVA2VA(moduleBase uintptr, rva uint32) uintptr
func ReadDwordAtOffset(start uintptr, offset uint32) types.DWORD
func ReadWordAtOffset(start uintptr, offset uint32) types.WORD
func ReadByteAtOffset(start uintptr, offset uint32) uint8

// ReadCStringAt reads a null-terminated ANSI string from memory.
func ReadCStringAt(start uintptr, offset uint32) []byte {
	var buf []byte
	for {
		ch := ReadByteAtOffset(start, offset)
		if ch == 0 {
			break
		}
		buf = append(buf, ch)
		offset++
	}
	return buf
}
