package loader

import (
	"unsafe"

	"github.com/coremedic/goldr/internal/types"
)

func GetNTHeader(baseAddr uintptr) *types.ImageNTHeaders64 {
	return (*types.ImageNTHeaders64)(unsafe.Pointer(baseAddr + uintptr((*types.ImageDosHeader)(unsafe.Pointer(baseAddr)).ELfanew)))
}

func GetRelocTable(ntHeader *types.ImageNTHeaders64) *types.ImageDataDirectory {
	retTable := &ntHeader.OptionalHeader.DataDirectory[types.ImageDirectoryEntryBaseReloc]
	if retTable.VirtualAddress == 0 {
		return nil
	} else {
		return retTable
	}
}
