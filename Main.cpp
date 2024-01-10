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
	IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(file_buffer);

	// Checking for MZ Signature
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		std::cerr << "That's not PE file!" << std::endl;
		delete[] dosHeader;
		CloseHandle(fileHandle);
		return 1;
	}
	
	// Looking for PE Header
	IMAGE_NT_HEADERS* ntHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(file_buffer + dosHeader -> e_lfanew);

	std::cout << "Number of sections: " << ntHeader->FileHeader.NumberOfSections << std::endl;
	std::cout << "PointertoEntryPoint: 0x" << std::hex << ntHeader->OptionalHeader.AddressOfEntryPoint << std::endl;
	std::cout << "ImageBase: 0x>" << std::hex << ntHeader->OptionalHeader.ImageBase << std::endl;
	std::cout << "ImportDataDirectory: " << std::hex << ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress << std::endl;
	std::cout << "ExportDataDirectory: " << std::hex << ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress << std::endl;
	printf("SectionAlignment: %d\n", ntHeader->OptionalHeader.SectionAlignment);
	printf("FileAlignment: %d\n", ntHeader->OptionalHeader.FileAlignment);
	printf("Size of Image: 0x%x\n", ntHeader->OptionalHeader.SizeOfImage);

	IMAGE_SECTION_HEADER* sectionHeader =IMAGE_FIRST_SECTION(ntHeader);
	for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
		std::cout << "\nSection Name: " << sectionHeader[i].Name << std::endl;
		std::cout << "Raw Size: " << std::dec << sectionHeader[i].SizeOfRawData << std::endl;
		std::cout << "Characteristic: 0x" << std::hex << sectionHeader[i].Characteristics << std::endl;
		std::cout << "VirtualAddress: 0x" << std::hex << sectionHeader[i].VirtualAddress << std::endl;
		std::cout << "VirtualSize: 0x" << std::hex << sectionHeader[i].Misc.VirtualSize << std::endl;
		std::cout << "RawAddress: 0x" << std::hex << sectionHeader[i].PointerToRawData << std::endl;

	}

	delete[] file_buffer;

	return 0;
}