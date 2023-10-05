package crypter

import (
	"bytes"
	"log"
	"os"
)

func CryptBin(bin []byte) {
	compBin, err := CompressLZMA2(bin)
	if err != nil {
		log.Fatal(err.Error())
	}
	key, err := GenKey()
	if err != nil {
		log.Fatal(err.Error())
	}
	cryptbin, err := SerpentEncrypt(compBin, key)
	if err != nil {
		log.Fatal(err.Error())
	}
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
	decompBin, err := DecompressLZMA2(decryptedBin)
	if err != nil {
		log.Fatalf("Decompression failed: %s", err.Error())
		return false
	}
	return bytes.Equal(originalBin, decompBin)
}
