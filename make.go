package main

//go:generate go run packer/packer.go bin.exe
//go:generate env GOOS=windows GOARCH=amd64 go build -ldflags "-H=windowsgui -w -s" -o out.exe stub/stub.go
