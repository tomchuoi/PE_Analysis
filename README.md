# Shellcode development and PE Injection 
This project is designed to understand the shellcode development, Portable Executable (PE) file structure and the process of injecting shellcode by modifying its structure.


## Features
  +  PE Parsing: This program extracts information from PE Headers, including sections, imported modules and more.
  +  TCP reverse shell: A shellcode written in MASM that sets up backdoor on Windows. It adds itself to the registry for persistence, establishes a reverse shell to the attacker and dynamically resolves API functions and system calls at run time.
  +  Shellcode Injection: Create new section in the PE file and inject tcp reverse shell into it.

## Note
This project is designed for educational purposes only.

## How to use the reverse shell
Start the listener on port 4444 on the attack machine using netcat <code> nc -lvp 4444 </code> .
Make sure to change the ip address of the attacker in the shellcode first.
