package main

import (
	_ "embed"
	"fmt"
	"goldr/crypter"
	"log"
	"os"
	"text/template"
)

// stub template config
type Config struct {
	Memexec bool
	Debug   bool
}

//go:embed stub/stub.go
var stub []byte
var config Config

func main() {
	// if no args provided
	if len(os.Args) < 2 {
		log.Fatal("No arguments provided!\n")
	}

	// parse embeded stub template
	tpl, err := template.New("main").Parse(string(stub))
	if err != nil {
		log.Fatalf("Error parsing stub template: %s\n", err.Error())
	}

	// load binary
	bin, err := os.ReadFile(os.Args[1])
	if err != nil {
		log.Fatalf("Error reading binary: %s\n", err.Error())
	}

	// encrypt bin
	crypter.CryptBin(bin)

	// build config for stub
	fmt.Println(os.Args[2])
	if os.Args[2] == "--debug" || os.Args[2] == "-D" {
		config = Config{
			Memexec: true,
			Debug:   true,
		}
	} else {
		config = Config{
			Memexec: true,
		}
	}

	outputFile, err := os.Create("stub_gen.go")
	if err != nil {
		panic(err)
	}
	defer outputFile.Close()

	err = tpl.Execute(outputFile, config)
	if err != nil {
		panic(err)
	}
}
