; This is just a test PE parser using MASM
.386
Option CaseMap:None

includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\user32.lib
includelib \masm32\lib\masm32.lib

Extrn printf:Near
Extrn exit:Near
Extrn getchar:Near

SIZEOF_IMAGE_FILE_HEADER Equ 14H
SIZEOF_NT_SIGNATURE Equ SizeOf DWord

.data
    filePath        DB  "C:\\Users\\Avenger\\Desktop\\DXCpl.exe", 0
    errorMsg        DB  "Error occurred while processing the file.", 0
    exitMsg			    DB	"Press enter to exit the program....", 0
    entryPointMsg   DB  "Address of Entry Point: 0x%X", 0
    sectionMsg      DB  "Number of Sections: %d", 0
    imageBaseMsg    DB  "Image Base: 0x%X", 0
    dword_msg       DB  "0x%X", 0
    newline			    DB  13, 10, 0
    NT_Header       DD ?

.Data?
    OptionalHeader	DD ?
    AddressOfEntryPoint	DD ?
	  imageBase		DD ?

.code
start:
    ; Get the handle to the PE file
    invoke CreateFile, addr filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL
    ; Check if file handle is valid
    cmp eax, INVALID_HANDLE_VALUE
    je  error_exit
    mov edx, eax ; edx = file handle

    ; Map the file into memory
    invoke CreateFileMapping, edx, NULL, PAGE_READONLY, 0, 0, NULL
    ; Check if mapping handle is valid
    cmp eax, NULL
    je  error_exit
    mov ecx, eax ; ecx = mapping handle

    ; Get the address of the mapped file
    invoke MapViewOfFile, ecx, FILE_MAP_READ, 0, 0, 0
    ; Check if mapping address is valid
    cmp eax, NULL
    je  error_exit
    mov ebx, eax ; ebx = base address of the mapped file

    Mov Edi, Ebx
    Add Edi, DWord Ptr [Edi + 3CH]
    Movzx Eax, Word Ptr [Edi + 6H]		; Move to the number of section
    Push Eax
    Push Offset sectionMsg
    Call printf
    Push Offset newline
    Call printf

    Mov Ebx, Edi
    Add Ebx, 18H						; Move to OptionalHeader
    Mov OptionalHeader, Ebx
    Mov Esi, DWord Ptr [OptionalHeader]
    Add Esi, 1CH						; Move to the ImageBase field
    Mov Ecx, [Esi]
    Mov imageBase, Ecx
    Push imageBase
    Push Offset imageBaseMsg            ; Push format string for printf
    Call printf                         ; Print ImageBase
    Push Offset newline
    Call printf


    Mov Ecx, DWord Ptr [Ebx + 10H]      ; Get the AddressOfEntryPoint
    Mov AddressOfEntryPoint, Ecx
    Push AddressOfEntryPoint
    Push Offset entryPointMsg           ; Push format string for printf
    Call printf							            ; Print AddressOfEntryPoint



    ; Cleanup and exit
    Invoke UnmapViewOfFile, Ebx
    Invoke CloseHandle, Ecx
    Invoke CloseHandle, Edx
    Jmp exit_program

error_exit:
    Push Offset errorMsg
    Call printf

exit_program:
    Call getchar
    Invoke ExitProcess, 0

end start
