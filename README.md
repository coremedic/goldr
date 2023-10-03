<div align="center">
  <h1>GoLdr</h1>
  <br/>
  <p><i>A simple payload loader/dropper written in golang</i></p>
  <br/>
</div>

# About
GoLdr takes an .exe binary file then encrypts it with the Serpent Block Cipher. \
The encrypted binary and its respective key are embeded into a stub which is compiled into a .exe binary file. \
On execution, the stub decrypts the embeded payload using the embeded key and executes the payload in memory. 

# Usage
WORK IN PROGRESS \ 
GoLdr is not in a usable state at the moment
