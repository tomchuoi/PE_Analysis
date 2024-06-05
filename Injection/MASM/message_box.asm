; This windows shellcode will pop up a simple message box
; For that, it will do the following:
; Get base address of kernel32.dll
; Get the address of GetProcAddress
; Load LoadLibraryA using GetProcAddress
; Load user32.dll using LoadLibraryA
; Get the address of MessageBoxA in user32.dll using GetProcAddress
; Call MessageBoxA

Option CaseMap:None

.Code
start:
Assume Fs:Nothing
	Xor Eax, Eax
	Mov [Ebp - 4H], Eax				; This will store the number of exported functions in kernel32.dll
	Mov [Ebp - 8H], Eax				; This will store the address of exported table
	Mov [Ebp - 0CH], Eax				; This will store the address of exported name table
	Mov [Ebp - 10H], Eax				; This will store the address of ordinal table
	Mov [Ebp - 14H], Eax

	Push 00007373H
	Push 65726464H
	Push 41636F72H
	Push 50746547H
	Mov [Ebp - 14H], Esp				; Push GetProcAddress

	Mov Eax, [Fs:30H]				; PEB
	Mov Eax, [Eax + 0CH]				; PEB_LDR_DATA
	Mov Eax, [Eax + 14H]				; InMemoryOrderModuleList
	Mov Eax, [Eax]					; Get pointer to the second (ntdll.dll) entry in InMemoryOrderModuleList
	Mov Eax, [Eax]					; Get pointer to the third (kernel32.dll) list in InMemoryOrderModuleList
	Mov Eax, [Eax + 10H]
	Mov Ebx, Eax					; Store kernel32.dll base address in ebx

	Mov Eax, [Ebx + 3CH]
	Add Eax, Ebx					; PE signature

	Mov Eax, [Eax + 78H]
	Add Eax, Ebx					; Address of Export Table

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

	Xor Eax, Eax					; Counter for loop
	Xor Ecx, Ecx

getFunctionPosition:
	Mov Esi, [Ebp - 14H]				; Name of Function
	Mov Edi, [Ebp - 0CH]				; Pointer points to the start of name table
	Mov Edi, [Edi + Eax * 4]			; RVA of next function name
	Add Edi, Ebx

	Mov Cx, 8
	Repe Cmpsb					; Compare edi, esi
	Jz getFunctionAddress				; If found the name then jump to getFunctionAddress
	Inc Eax
	Cmp Eax, [Ebp - 4H]				; Check for if counter < number of functions
	Jne getFunctionPosition 			; Loop

; Calculate the ordinal of the function: (Address of ordinal table + position * sizeof(Ordinal))
; After got the ordinal then calculate the RVA of the function address: (RVA AddressOfFunction + ordinal * sizeof(FunctionRVA))
getFunctionAddress:
	Xor Ecx, Ecx
	Mov Ecx, [Ebp - 10H]			 	; Address of ordinal table
	Mov Edx, [Ebp - 8H]				; Address of function

	Mov Ax, [Ecx + Eax * 2]				; Get the function ordinal
	Mov Eax, [Edx + Eax * 4]
	Add Eax, Ebx					; Function address
	Jmp invokeFunction

; Using GetProcAddress to get the address of LoadLibraryA
invokeFunction:
	Xor Ecx, Ecx
	Xor Edx, Edx
	Mov Esi, Eax					; esi = GetProcAddress
	Push Ecx
	Push 41797261H					; aryA
	Push 7262694CH					; Libr
	Push 64616F4CH					; Load
	Push Esp					; LoadLibraryA
	Push Ebx
	Call Esi					; Call GetProcAddress

	; The returned data is saved to eax register
	; Load User32.dll using LoadLibraryA
	Add Esp, 0CH					; Clear LoadLibraryA from the stack
	Xor Ecx, Ecx
	Push Ecx
	Mov Cx, 6C6CH					; ll
	Push Ecx
	Push 642E3233H					; 32.d
	Push 72657375H					; user
	Push Esp					; user32.dll
	Call Eax

	; Get MessageBoxA address
	Add Esp, 10H					; Clear user32.dll from the stack
	Xor Ecx, Ecx
	Push Eax					; user32.dll base address
	Push Edx					; GetProcAddress
	Push Ecx
	Mov Ecx, 6141786FH
	Push Ecx
	Sub DWord Ptr[Esp + 3H], 61H
	Push 42656761H
	Push 7373654DH
	Push Esp 					; MessageBoxA
	Push Eax					; user32.dll base address
	Call Esi					; GetProcAddress

	; Invoke MessageBoxA
	Add Esp, 0EH
	Mov Ecx, 74736554H
	Push Ecx
	Mov Ecx, Esp						; ecx = caption
	Xor Ebx, Ebx
	Push Ebx
	Push 64657463H
	Push 65666E69H
	Push 20746F67H
	Push 20756F59H
	Mov Edx, Esp						; edx = message
	Push 0							; uType
	Push Ecx						; lpCaption
	Push Edx						; lpText
	Push 0							; hWnd
	Call Eax						; MessageBoxA

End start
