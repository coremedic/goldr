package crypter

import (
	"bytes"
	"fmt"
	"log"
	"os"
)

func CryptBin(bin []byte) {

	fmt.Printf("Original binary size: %d bytes\n", len(bin))
	key, err := GenKey()
	if err != nil {
		log.Fatal(err.Error())
	}
	cryptbin, err := SerpentEncrypt(bin, key)
	if err != nil {
		log.Fatal(err.Error())
	}
	fmt.Printf("Encrypted binary size: %d bytes\n", len(cryptbin))
	ok := verify(cryptbin, bin, key)
	if !ok {
		os.Exit(1)
	}
	os.WriteFile(".tmp/cryptbin", cryptbin, 0777)
	os.WriteFile(".tmp/key", key, 0777)
}

func verify(cryptbin, originalBin, key []byte) bool {
	decryptedBin, err := SerpentDecrypt(cryptbin, key)
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
