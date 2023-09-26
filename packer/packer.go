package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"goldr/crypter"
	"log"
	"os"
	"path"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: go run main.go [path to binary file]")
	}

	binPath := os.Args[1]
	bin, err := os.ReadFile(binPath)
	if err != nil {
		log.Fatalf("Could not read file: %s", err.Error())
	}

	fmt.Printf("Original binary size: %d bytes\n", len(bin))
	key, err := crypter.GenKey()
	if err != nil {
		log.Fatal(err.Error())
	}
	cryptbin, err := crypter.SerpentEncrypt(bin, key)
	if err != nil {
		log.Fatal(err.Error())
	}
	fmt.Printf("Encrypted binary size: %d bytes\n", len(cryptbin))
	ok := verify(cryptbin, bin, key)
	if !ok {
		os.Exit(1)
	}
	os.WriteFile(path.Join("stub", "cryptbin"), cryptbin, 0777)
	os.WriteFile(path.Join("stub", "key"), key, 0777)
}

func verify(cryptbin, originalBin, key []byte) bool {
	decryptedBin, err := crypter.SerpentDecrypt(cryptbin, key)
	if err != nil {
		log.Fatalf("Decryption failed: %s", err.Error())
		return false
	}
	if bytes.Equal(originalBin, decryptedBin) {
		fmt.Println("Verification succeeded: original and decrypted binaries match.")
		return true
	} else {
		fmt.Println("Verification failed: original and decrypted binaries do not match.")
		return false
	}
}
