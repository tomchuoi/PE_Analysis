.386
Option CaseMap:None

includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\user32.lib
IncludeLib \masm32\ lib\ masm32.lib

Extrn printf:Near
Extrn exit:Near
Extrn getchar:Near

SIZEOF_IMAGE_FILE_HEADER Equ 14H
SIZEOF_NT_SIGNATURE Equ SizeOf DWord
SIZEOF_OPTIONAL_HEADER Equ 224
IMAGE_SCN_MEM_READ_CODE_EXECUTE    Equ 60000020H

.data
    filePath        DB  "C:\\Users\\Avenger\\Desktop\\Test\\DXCpl.exe", 0
    errorMsg        DB  "Error occurred while processing the file.", 0
    exitMsg         DB  "Press enter to exit the program....", 0
    dword_msg       DB  "0x%X", 0
    sectionName		DB	".abc", 0
    sectionNameSize Equ SizeOf sectionName
    newline         DB  13, 10, 0
    NT_Header       DD ?
    fileHandle HANDLE 0
    fileMapping HANDLE 0
    viewOfFile PVOID 0

.data?
    OptionalHeader      DD ?
    AddressOfEntryPoint DD ?
    imageBase           DD ?
    NumberOfSections    DW ?
    BytesWritten        DD ?
    JmpBackEntryPoint	DD ?
    fileAlignment		DD ?
    sectionAlignment	DD ?
    sizeOfImage			DD ?

    newSection IMAGE_SECTION_HEADER<>
    lastSection IMAGE_SECTION_HEADER <>


.Code
start:
    ; Get the handle to the PE file
    invoke CreateFile, addr filePath, GENERIC_READ or GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL
    ; Check if file handle is valid
    cmp eax, INVALID_HANDLE_VALUE
    je  error_exit
    Mov fileHandle, Eax 						; eax = file handle

    ; Map the file into memory
    Push Eax
    Invoke CreateFileMapping, fileHandle, NULL, PAGE_READWRITE, 0, 0, NULL
    ; Check if mapping handle is valid
    cmp eax, NULL
    je  error_exit
    Mov Ecx, Eax 			; ecx = mapping handle
    Mov fileMapping, Eax

    ; Get the address of the mapped file
    invoke MapViewOfFile, ecx, FILE_MAP_WRITE, 0, 0, 0
    ; Check if mapping address is valid
    cmp eax, NULL
    je  error_exit
    Mov Ebx, Eax 			; ebx = base address of the mapped file
    Mov viewOfFile, Eax

    Mov Edi, Ebx
    Add Edi, DWord Ptr [Edi + 3CH]
    Mov NT_Header, Edi			; Save the offset of NT_Header from edi register

    Mov Ebx, Edi
    Add Ebx, 18H                        ; Move to OptionalHeader
    Mov OptionalHeader, Ebx
    Mov Esi, DWord Ptr [OptionalHeader]
    Add Esi, 1CH                        ; Move to the ImageBase field
    Mov Ecx, [Esi]
    Mov imageBase, Ecx

    Add Esi, 4H				; Move to SectionAlignment field
    Mov Ecx, [Esi]
    Mov sectionAlignment, Ecx

    Add Esi, 4H
    Mov Ecx, [Esi]
    Mov fileAlignment, Ecx		; Move to FileAlignment field

    Add Esi, 14H			; Move to SizeOfImage field
    Mov Ecx, [Esi]
    Mov sizeOfImage, Ecx

    Mov Ecx, DWord Ptr [Ebx + 10H]      ; Get the AddressOfEntryPoint
    Mov AddressOfEntryPoint, Ecx
    Xor Eax, Eax
    Mov Eax, AddressOfEntryPoint
    Add Eax, imageBase				; JmpBackEntryPoint = AddressOfEntryPoint + imageBase
    Mov JmpBackEntryPoint, Eax

    ; Calculate the offset of the last section's raw data from the beginning of the file
    Mov Esi, DWord Ptr [NT_Header]		; Get the pointer to the NT Header
    Add Esi, 6H                                 ; Move to the NumberOfSections field
    Xor Eax, Eax
    Mov Eax, [Esi]                              ; Load the number of sections
    Mov NumberOfSections, Ax
    Sub Ax, 1
    Mov Edi, DWord Ptr [OptionalHeader]
    Add Edi, SIZEOF_OPTIONAL_HEADER
    Mov Bx, 40
    IMul Ax, Bx
    Movzx Eax, Ax
    Add Edi, Eax				; File pointer point to the last section in the section table
  
    Add Edi, 8H					; Get the VirtualSize of the last section
    Mov Eax, [Edi]
    Mov lastSection.Misc.VirtualSize, Eax
  
    Add Edi, 4H				 	; Get the VirtualAddress of the last section
    Mov Eax, [Edi]
    Mov lastSection.VirtualAddress, Eax
  
    Add Edi, 4H
    Mov Eax, [Edi]
    Mov lastSection.SizeOfRawData, Eax
  
    Add Edi, 4H
    Mov Eax, [Edi]
    Mov lastSection.PointerToRawData, Eax
  
    ; Calculate new section information
    Mov Eax, IMAGE_SCN_MEM_READ_CODE_EXECUTE
    Mov newSection.Characteristics, Eax
  
    Mov Eax, lastSection.PointerToRawData
    Mov Ebx, lastSection.SizeOfRawData
    Add Eax, Ebx
    Mov newSection.PointerToRawData, Eax
  
    Mov Eax, sectionAlignment
    Dec Eax
    Not Eax
    And Eax, sectionAlignment
    Mov Ebx, lastSection.Misc.VirtualSize
    Add Ebx, Eax
    Mov Eax, lastSection.VirtualAddress
    Add Ebx, Eax
    Mov newSection.VirtualAddress, Ebx
  
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
    Mov Eax, [Esi]      				; Move to the number of sections
    Inc Eax             				; Increment the number of sections
    Mov NumberOfSections, Ax 				; Load the updated value
    Sub Esi, viewOfFile					; Get the actual offset on the disk
    Invoke SetFilePointer, fileHandle, Esi, NULL, FILE_BEGIN ; Set file pointer to the location of NumberOfSections
    Invoke WriteFile, fileHandle, Offset NumberOfSections, SizeOf Word, Addr BytesWritten, NULL ; Write the updated value


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

