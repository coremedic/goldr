<div align="center">
  <h1>GoLdr</h1>
  <br/>
  <p><i>A simple buildtime payload obfuscator</i></p>
  <br/>
</div>

# About
GoLdr takes an .exe binary file then encrypts it with the Serpent Block Cipher. \
The encrypted binary and its respective key are embeded into a stub which is compiled into a .exe binary file. \
On execution, the stub decrypts the embeded payload using the embeded key and executes the payload in memory. 

# Usage
Add your .exe binary to the root folder of the repo rename it "bin.exe" \
Run:
```sh
go generate
```
Your obfuscated binary will be generated as "out.exe"
