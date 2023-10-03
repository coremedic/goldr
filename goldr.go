package main

import (
	_ "embed"
	"errors"
	"fmt"
	"log"
	"os"
	"text/template"

	"github.com/coremedic/goldr/pkg/crypter"

	"github.com/spf13/cobra"
)

type Config struct {
	Spawn   bool // mutually exclusive
	Reflect bool // mutually exclusive
	Unhook  bool // optional
	Debug   bool // optional
}

var (
	//go:embed stub/stub.go
	stub []byte

	config                 Config
	mutuallyExclusiveFlags []*bool

	rootCmd = &cobra.Command{
		Use:   "goldr [binary]",
		Short: "GoLdr is a simple build time payload obfuscator",
		Long:  `GoLdr is a fast and flexible build time payload obfuscator written in golang`,
		Run:   run,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return checkFlags()
		},
	}
)

func init() {
	rootCmd.PersistentFlags().BoolVarP(&config.Unhook, "unhook", "U", false, "Unhook dlls at runtime")
	rootCmd.PersistentFlags().BoolVarP(&config.Debug, "debug", "D", false, "Enable debug mode")

	rootCmd.PersistentFlags().BoolVarP(&config.Spawn, "spawn", "S", false, "Enable spawn mode")
	mutuallyExclusiveFlags = append(mutuallyExclusiveFlags, &config.Spawn)

	rootCmd.PersistentFlags().BoolVarP(&config.Reflect, "reflect", "R", false, "Enable reflect mode")
	mutuallyExclusiveFlags = append(mutuallyExclusiveFlags, &config.Reflect)
}

func checkFlags() error {
	count := 0
	for _, flag := range mutuallyExclusiveFlags {
		if *flag {
			count++
		}
		if count > 1 {
			return errors.New("only one dropper method can be used")
		}
	}
	if count == 0 {
		return errors.New("at least one dropper method must be set")
	}
	return nil
}

func run(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		log.Fatal("No arguments provided!\n")
	}

	tpl, err := template.New("main").Parse(string(stub))
	if err != nil {
		log.Fatalf("Error parsing stub template: %s\n", err.Error())
	}

	bin, err := os.ReadFile(args[0])
	if err != nil {
		log.Fatalf("Error reading binary: %s\n", err.Error())
	}

	crypter.CryptBin(bin)

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
