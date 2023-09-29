package main

import (
	_ "embed"
	"fmt"
	"log"
	"os"
	"text/template"

	"github.com/coremedic/goldr/pkg/crypter"

	"github.com/spf13/cobra"
)

// stub template config
type Config struct {
	Memexec bool
	Unhook  bool
	Debug   bool
}

var (
	//go:embed stub/stub.go
	stub []byte

	config Config

	rootCmd = &cobra.Command{
		Use:   "goldr [binary]",
		Short: "GoLdr is a simple build time payload obfuscator",
		Long:  `GoLdr is a fast and flexible build time payload obfuscator written in golang`,
		Run:   run,
	}
)

func init() {
	rootCmd.PersistentFlags().BoolVarP(&config.Unhook, "unhook", "U", false, "Unhook dlls at runtime")
	rootCmd.PersistentFlags().BoolVarP(&config.Debug, "debug", "D", false, "Enable debug mode")
}

func run(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		log.Fatal("No arguments provided!\n")
	}

	// parse embeded stub template
	tpl, err := template.New("main").Parse(string(stub))
	if err != nil {
		log.Fatalf("Error parsing stub template: %s\n", err.Error())
	}

	// load binary
	bin, err := os.ReadFile(args[0])
	if err != nil {
		log.Fatalf("Error reading binary: %s\n", err.Error())
	}

	// encrypt bin
	crypter.CryptBin(bin)

	// build config for stub
	config.Memexec = true

	outputFile, err := os.Create(".tmp/stub_gen.go")
	if err != nil {
		panic(err)
	}
	defer outputFile.Close()

	err = tpl.Execute(outputFile, config)
	if err != nil {
		panic(err)
	}
}

func main() {
	if err := os.MkdirAll(".tmp", 0777); err != nil {
		log.Fatal(err.Error())
	}
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
