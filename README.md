# PE_Analysis
This program reads and analyzes Portable Executable (PE) file. It extracts information from PE Headers, including sections, imported modules and more.

## Features
+ Extracts information from DOS Headers, NT Headers and Section Headers.
+ Displays the following details about each section of the file:
   - Name
   - Characteristics
   - RawAddress
   - RawSize
   - VirtualAddress
   - VirtualSize
+ Lists imported modules and function whether it's imported by name or ordinal.

Note: This program only works correctly with 32 bit portable executable file.
