package crypter

import (
	"bytes"
	"errors"
	"io"

	"github.com/ulikunitz/xz"
)

func CompressLZMA2(input []byte) ([]byte, error) {
	var buf bytes.Buffer
	writer, err := xz.NewWriter(&buf)
	if err != nil {
		return nil, err
	}
	_, err = writer.Write(input)
	if err != nil {
		return nil, err
	}
	writer.Close()
	return buf.Bytes(), nil
}

func DecompressLZMA2(input []byte) ([]byte, error) {
	reader, err := xz.NewReader(bytes.NewReader(input))
	if err != nil {
		return nil, err
	}
	output, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	if len(output) == 0 {
		return nil, errors.New("decompressed data is empty")
	}
	return output, nil
}
