#include <Windows.h>
#include <iostream>

int main() {
	const char* filePath = "C:\\Program Files\\Common Files\\System\\wab32.dll";

	HANDLE fileHandle = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (fileHandle == INVALID_HANDLE_VALUE) {
		std::cerr << "Can't open file" << std::endl;
		return 1;
	}
	DWORD fileSize = GetFileSize(fileHandle, NULL);

	// Allocate the memory
	BYTE* file_buffer = new BYTE[fileSize];
	if (file_buffer == NULL) {
		std::cerr<< "Error allocating memory" <<std::endl;
		CloseHandle(fileHandle);
		return 1;
	}

	// File allocation
	DWORD bytesRead;
	if (!ReadFile(fileHandle, file_buffer, fileSize, &bytesRead, NULL)) {
		std::cerr<< "Error loading file" <<std::endl;
		delete[] file_buffer;
		CloseHandle(fileHandle);
		return 1;
	}

	CloseHandle(fileHandle);

	// Change the pointer type of file_buffer to suitable type to get the DOS Header
	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)(file_buffer);
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(file_buffer + dosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeader);
	
	// Checking for MZ Signature
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		std::cerr << "That's not PE file!" << std::endl;
		delete[] dosHeader;
		CloseHandle(fileHandle);
		return 1;
	}
	
	std::cout << "Number of sections: " << ntHeader->FileHeader.NumberOfSections << std::endl;
	std::cout << "PointertoEntryPoint: 0x" << std::hex << ntHeader->OptionalHeader.AddressOfEntryPoint << std::endl;
	std::cout << "ImageBase: 0x>" << std::hex << ntHeader->OptionalHeader.ImageBase << std::endl;
	std::cout << "ImportDataDirectory: " << std::hex << ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress << std::endl;
	std::cout << "ExportDataDirectory: " << std::hex << ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress << std::endl;
	printf("SectionAlignment: %d\n", ntHeader->OptionalHeader.SectionAlignment);
	printf("FileAlignment: %d\n", ntHeader->OptionalHeader.FileAlignment);
	printf("Size of Image: 0x%x\n", ntHeader->OptionalHeader.SizeOfImage);

	DWORD importDirectoryRVA = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	PIMAGE_SECTION_HEADER import_section = NULL;
	for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
		std::cout << "\nSection Name: " << sectionHeader[i].Name << std::endl;
		std::cout << "Raw Size: " << std::dec << sectionHeader[i].SizeOfRawData << std::endl;
		std::cout << "Characteristic: 0x" << std::hex << sectionHeader[i].Characteristics << std::endl;
		std::cout << "VirtualAddress: 0x" << std::hex << sectionHeader[i].VirtualAddress << std::endl;
		std::cout << "VirtualSize: 0x" << std::hex << sectionHeader[i].Misc.VirtualSize << std::endl;
		std::cout << "RawAddress: 0x" << std::hex << sectionHeader[i].PointerToRawData << std::endl;

		if (importDirectoryRVA >= sectionHeader[i].VirtualAddress && importDirectoryRVA < sectionHeader[i].VirtualAddress + sectionHeader[i].Misc.VirtualSize) {
			import_section = &sectionHeader[i];
		}
	}

	//DWORD imageBase = ntHeader->OptionalHeader.ImageBase;
	DWORD rawOffSet = import_section->PointerToRawData;
	
	// Pointer point to the beginning of the import directory
	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(
		(DWORD)file_buffer + rawOffSet + importDirectoryRVA - import_section->VirtualAddress);

	while (importDescriptor->Name != 0) {
		const char* moduleName = reinterpret_cast<const char*>(file_buffer + rawOffSet + importDescriptor->Name - import_section->VirtualAddress);
		std::cout << "\t" << moduleName << std::endl;
		
		// Imported functions
		PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)(file_buffer + rawOffSet + importDescriptor->OriginalFirstThunk - import_section->VirtualAddress);
		while (thunk->u1.AddressOfData != 0) {
			// Checking if the function is imported by ordinal or by name
			if (!(thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
				PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)(file_buffer + rawOffSet + thunk->u1.AddressOfData - import_section->VirtualAddress);
				std::cout << "\tImported Function: " << importByName->Name << std::endl;
			}
			else {
				std::cout << "\tImported Ordinal: " << std::hex << IMAGE_ORDINAL(thunk->u1.Ordinal) << std::endl;
			}
			thunk++;
		}
		importDescriptor++;
	}
	delete[] file_buffer;
	return 0;
}

