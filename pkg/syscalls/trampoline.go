package syscalls

import "sort"

var cleanTrampolines []uintptr

func getCleanTrampolines(syscalls []*Syscall) {
	// sort syscalls by RVA
	sort.Slice(syscalls, func(i, j int) bool {
		return syscalls[i].RVA < syscalls[j].RVA
	})

	// find clean trampolines
	for _, st := range syscalls {
		if trampoline := GetTrampoline(st.VA); trampoline != uintptr(0) {
			st.TrampolinePtr = trampoline
			cleanTrampolines = append(cleanTrampolines, trampoline)
		}
	}

	// get SSNs
	for i, st := range syscalls {
		st.SSN = uint16(i)

		if st.TrampolinePtr == uintptr(0) {
			syscalls[i].TrampolinePtr = cleanTrampolines[0]
		}
	}
}
