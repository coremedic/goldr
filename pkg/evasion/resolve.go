package evasion

import (
	"debug/pe"
	"unsafe"

	"github.com/coremedic/goldr/internal/types"
	"github.com/coremedic/goldr/pkg/syscalls"
)

func resolveSyscall64(funcName string) uintptr {
	var libraryBase = syscalls.GetNtdllBase()

	dosHeader := (*types.ImageDosHeader)(unsafe.Pointer(&(*[64]byte)(unsafe.Pointer(libraryBase))[:][0]))

	offset := (libraryBase) + uintptr(dosHeader.ELfanew)
	imageNTHeaders := (*types.ImageNTHeaders64)(unsafe.Pointer(&(*[264]byte)(unsafe.Pointer(offset))[:][0]))

	exportDirectoryRVA := imageNTHeaders.OptionalHeader.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress

	offset = (libraryBase) + uintptr(exportDirectoryRVA)
	imageExportDirectory := (*types.ImageExportDirectory)(unsafe.Pointer(&(*[256]byte)(unsafe.Pointer(offset))[:][0]))

	offset = (libraryBase) + uintptr(imageExportDirectory.AddressOfFunctions)
	addresOfFunctionsRVA := (*uint)(unsafe.Pointer(&(*[4]byte)(unsafe.Pointer(offset))[:][0]))

	offset = (libraryBase) + uintptr(imageExportDirectory.AddressOfNames)
	addressOfNamesRVA := (*uint32)(unsafe.Pointer(&(*[4]byte)(unsafe.Pointer(offset))[:][0]))

	for i := (0); i < int(imageExportDirectory.NumberOfFunctions); i += 1 {

		offset = (libraryBase) + uintptr(imageExportDirectory.AddressOfNames) + uintptr(i*4)
		addressOfNamesRVA = (*uint32)(unsafe.Pointer(&(*[4]byte)(unsafe.Pointer(offset))[:][0]))
		functionNameRVA := (*uint32)(unsafe.Pointer(&(*[4]byte)(unsafe.Pointer(addressOfNamesRVA))[:][0]))
		offset = (libraryBase) + uintptr(*functionNameRVA)
		functionNameVA := (uintptr)(unsafe.Pointer(&(*[32]byte)(unsafe.Pointer(offset))[:][0]))

		// Read until null byte, strings should be null terminated.
		functionName := ""
		k := 0
		for {
			nextChar := (*byte)(unsafe.Pointer(&(*[64]byte)(unsafe.Pointer(functionNameVA))[:][k]))
			if *nextChar == 0x00 {
				break
			}
			functionName += string(*nextChar)
			k++
		}

		if functionName == funcName {

			// addressOfNameOrdinalsRVA[i]
			offset = (libraryBase) + uintptr(imageExportDirectory.AddressOfNameOrdinals) + uintptr(i*2) // We multiply by 2 because each element is 2 bytes in the array.
			ordinalRVA := (*uint16)(unsafe.Pointer(&(*[2]byte)(unsafe.Pointer(offset))[:][0]))

			offset = uintptr(unsafe.Pointer(*&addresOfFunctionsRVA)) + uintptr(uint32(*ordinalRVA)*4) // We multiply by 4 because each element is 4 bytes in the array.
			functionAddressRVA := (*uint32)(unsafe.Pointer(&(*[4]byte)(unsafe.Pointer(offset))[:][0]))

			offset = (libraryBase) + uintptr(*functionAddressRVA) // 0x1b5a0
			functionAddress := (uintptr)(unsafe.Pointer(&(*[4]byte)(unsafe.Pointer(offset))[:][0]))

			return functionAddress
		}
	}

	return 0x00
}
