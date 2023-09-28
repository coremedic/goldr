package crypter

import (
	"bytes"
	"crypto/rand"
	"log"

	"github.com/enceve/crypto/serpent"
)

func SerpentEncrypt(data []byte, key []byte) ([]byte, error) {
	cipher, err := serpent.NewCipher(key)
	if err != nil {
		return nil, err
	}
	padding := 16 - (len(data) % 16)
	paddedData := append(data, bytes.Repeat([]byte{byte(padding)}, padding)...)
	encDataBytes := make([]byte, len(paddedData))
	for bs := 0; bs < len(paddedData); bs += 16 {
		cipher.Encrypt(encDataBytes[bs:], paddedData[bs:bs+16])
	}
	return encDataBytes, nil
}

func SerpentDecrypt(data []byte, key []byte) ([]byte, error) {
	cipher, err := serpent.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(data)%16 != 0 {
		return nil, err
	}
	decryptedBytes := make([]byte, len(data))
	for bs := 0; bs < len(data); bs += 16 {
		cipher.Decrypt(decryptedBytes[bs:], data[bs:bs+16])
	}
	padding := int(decryptedBytes[len(decryptedBytes)-1])
	return decryptedBytes[:len(decryptedBytes)-padding], nil
}

func GenKey() ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	return key, nil
}
