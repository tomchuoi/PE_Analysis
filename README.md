# Shellcode development and PE Injection 
This project is designed to understand the shellcode development, Portable Executable (PE) file structure and the process of injecting shellcode by modifying its structure.


## Features
  +  PE Parsing: This program extracts information from PE Headers, including sections, imported modules and more.
  +  TCP reverse shell: A shellcode written in MASM that opens cmd.exe on target machine and redirects I/O stream to the attack machine. The shell dynamically find DLLs address and function calls to establish reverse connection.
  +  Shellcode Injection: Create new section in the PE file and inject tcp reverse shell into it.

## Note
This project is designed for educational purposes only.

## How to use the reverse shell
Start the listener on port 4444 on the attack machine <code> nc -lvp 4444 </code> 
Make sure to change the ip address of the attacker in the shellcode first.
