#include "my_loader.h"
#include <iostream>


PVOID my_loader::MyGetProcAddress(HMODULE hModule, LPCSTR name) {
    if (!hModule || !name || !IsValidPE(hModule)) return nullptr;

    IMAGE_DOS_HEADER* dosHeaders = (IMAGE_DOS_HEADER*)hModule;
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)dosHeaders + dosHeaders->e_lfanew);

    // IMAGE_OPTIONAL_HEADER contains DataDirectory array
    IMAGE_DATA_DIRECTORY exportEntry = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    IMAGE_EXPORT_DIRECTORY* exportDirectory = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)dosHeaders + exportEntry.VirtualAddress);
    DWORD functionCount = exportDirectory->NumberOfFunctions;
    // Ensure export directory exists
    if (!exportEntry.Size || !exportDirectory || !functionCount) {
        return nullptr;
    }
    // Get by ordinal, if possible
    DWORD* functionArray = (DWORD*)((BYTE*)dosHeaders + exportDirectory->AddressOfFunctions);
    unsigned long ordinalBase = exportDirectory->Base;

    // If passed, ordinal value must be in the low-order word; the high-order word must be zero
    if ((ULONG_PTR)name < 0xFFFF) {
        unsigned short ordinal = (ULONG_PTR)name & 0xFFFF;
        // Return function by ordinal
        if (ordinal - ordinalBase < functionCount) {
            return (PVOID)((BYTE*)dosHeaders + functionArray[ordinal - ordinalBase]);
        }
    }

    // Get by name
    DWORD* nameArray = (DWORD*)((BYTE*)dosHeaders + exportDirectory->AddressOfNames);
    WORD* ordinalArray = (WORD*)((BYTE*)dosHeaders + exportDirectory->AddressOfNameOrdinals);
    // Iterate to find function by name
    for (DWORD i = 0; i < functionCount; i++) {
        // Check name
        LPCSTR functionName = (LPCSTR)((BYTE*)dosHeaders + nameArray[i]);
        if (strcmp(functionName, name) == 0) {
            DWORD funcOffset = functionArray[ordinalArray[i]];
            return (PVOID)((BYTE*)dosHeaders + funcOffset);
        }
    }

    return nullptr;
}

HMODULE my_loader::MyLoadLibrary(LPCSTR path) {
    // Load file content into memory
    HANDLE hDllContent = MyLoadFileContent(path);
    if (hDllContent == INVALID_HANDLE_VALUE || hDllContent == nullptr) {
        std::cerr << "Can't load DLL data." << std::endl;
        return nullptr;
    }

    // Check validity
    if (!IsValidPE(hDllContent)) {
        std::cerr << "Not a valid PE file." << std::endl;
        HeapFree(GetProcessHeap(), 0, hDllContent);
        return nullptr;
    }
    IMAGE_DOS_HEADER* dosHeaders = (IMAGE_DOS_HEADER*)hDllContent;
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)dosHeaders + dosHeaders->e_lfanew);

    // Try to reserve at requested address
    LPVOID baseAddress = VirtualAlloc(
        (LPVOID)(ntHeaders->OptionalHeader.ImageBase),
        ntHeaders->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    // If failed, reserve at another address instead
    if (baseAddress == nullptr) {
        baseAddress = VirtualAlloc(
            nullptr,
            ntHeaders->OptionalHeader.SizeOfImage,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
    }
    if (baseAddress == nullptr) {
        std::cerr << "Can't allocate virtual memory." << std::endl;
        HeapFree(GetProcessHeap(), 0, hDllContent);
        return nullptr;
    }

    // Copy header
    RtlCopyMemory(baseAddress, hDllContent, ntHeaders->OptionalHeader.SizeOfHeaders);
    dosHeaders = (IMAGE_DOS_HEADER*)baseAddress;
    ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)dosHeaders + dosHeaders->e_lfanew);
    IMAGE_SECTION_HEADER* sectionHeaders = IMAGE_FIRST_SECTION(ntHeaders);
    // Copy sections
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, sectionHeaders++) {
        RtlCopyMemory(
            (LPVOID)((BYTE*)baseAddress + sectionHeaders->VirtualAddress),
            (LPVOID)((BYTE*)hDllContent + sectionHeaders->PointerToRawData),
            sectionHeaders->SizeOfRawData
        );
    }

    // Relocate if new address is different from expected
    if (baseAddress != (LPVOID) ntHeaders->OptionalHeader.ImageBase) {
        DWORD_PTR addressDifference = (DWORD_PTR)baseAddress - (DWORD_PTR)ntHeaders->OptionalHeader.ImageBase;
        IMAGE_DATA_DIRECTORY relocTable = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		PIMAGE_BASE_RELOCATION relocBase = (PIMAGE_BASE_RELOCATION)((PBYTE)baseAddress + relocTable.VirtualAddress);

        while (relocBase->VirtualAddress) {
            int nEntries = (relocBase->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            unsigned short* relocOffset = (unsigned short*)((PBYTE)relocBase + sizeof(IMAGE_BASE_RELOCATION));
            for (int i = 0; i < nEntries; i++, relocOffset++) {
                // First 4 bits is type, followed by next 12 bits representing offset
				unsigned char type = *relocOffset >> 12;
				unsigned short offset = *relocOffset & 0x0FFF;
				DWORD_PTR newLocation = (DWORD_PTR)baseAddress + relocBase->VirtualAddress + offset;
                switch (type) {
				case IMAGE_REL_BASED_ABSOLUTE:
				    break;
                case IMAGE_REL_BASED_HIGHLOW:
					*(DWORD*) newLocation += (DWORD)addressDifference;
                    break;
                case IMAGE_REL_BASED_DIR64:
                    *(DWORD_PTR*) newLocation += (DWORD_PTR)addressDifference;
                    break;
                // TODO: Implement the rest:
                // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#base-relocation-types
                default:
					VirtualFree(baseAddress, 0, MEM_RELEASE);
					std::cerr << "WARNING: Unsupported relocation type: " << std::hex << (int)type << std::endl;
                    return nullptr;
                }
            }
            relocBase = (PIMAGE_BASE_RELOCATION)((PBYTE)relocBase + relocBase->SizeOfBlock);
        }
		ntHeaders->OptionalHeader.ImageBase = (DWORD_PTR)baseAddress;
    }

    // Resolve imports
    IMAGE_DATA_DIRECTORY importsDir = (IMAGE_DATA_DIRECTORY)(ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
    if (importsDir.Size) {
        for (
            PIMAGE_IMPORT_DESCRIPTOR baseImport = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)baseAddress + importsDir.VirtualAddress);
            baseImport->OriginalFirstThunk; baseImport++
        ) {
            char* libName = (char*)((PBYTE)baseAddress + baseImport->Name);
            HMODULE hLib = MyLoadLibrary(libName);
            if (hLib == nullptr) {
                std::cout << "WARNING: Can't load library " << libName << std::endl;
                continue;
            }
			// Resolve import functions
            for (
                PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)baseAddress + baseImport->FirstThunk);
                thunk->u1.AddressOfData != 0; thunk++
            ) {
                if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal)) {
                    unsigned int ord = (unsigned int)IMAGE_ORDINAL(thunk->u1.Ordinal);
                    thunk->u1.Function = (DWORD_PTR)MyGetProcAddress(hLib, MAKEINTRESOURCEA(ord));
                }
                else {
                    PIMAGE_IMPORT_BY_NAME imports = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)baseAddress + thunk->u1.AddressOfData);
                    DWORD_PTR functionAddress = (DWORD_PTR)MyGetProcAddress(hLib, imports->Name);
                    thunk->u1.Function = functionAddress;
                }
            }
        }
    }
    HeapFree(GetProcessHeap(), 0, hDllContent);
    return (HMODULE)baseAddress;
}

HANDLE my_loader::MyLoadFileContent(LPCSTR path) {
    // Get executing directory and filename path
    char execPath[MAX_PATH], sysPath[MAX_PATH];
    GetModuleFileNameA(NULL, execPath, MAX_PATH);
    size_t pos = std::string(execPath).find_last_of("\\/");
    execPath[pos + 1] = '\0';
    strncat_s(execPath, path, MAX_PATH - pos - 1);

    // Get system directory append filename path
    GetSystemDirectoryA(sysPath, MAX_PATH - 1);
    strcat_s(sysPath, "\\");
    strncat_s(sysPath, path, MAX_PATH - strlen(path) - 1);

    HANDLE hFile = INVALID_HANDLE_VALUE;

    // Try get file assuming path relative to current directory, execute directory and system directory, respectively.
    LPCSTR pathsToTry[] = { path, execPath, sysPath };
    for (LPCSTR testPath : pathsToTry) {
        hFile = CreateFileA(testPath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
        if (hFile != INVALID_HANDLE_VALUE) {
            break;
        }
    }
    // Can't open file
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Can't find " << path << "." << std::endl;
        return nullptr;
    }

    // Get file size
    const DWORD fileSize = GetFileSize(hFile, nullptr);
    if (fileSize == INVALID_FILE_SIZE) {
        std::cerr << path << " file is empty or invalid." << std::endl;
        CloseHandle(hFile);
        return nullptr;
    }

    // Allocate memory for file content
    const HANDLE hFileContent = HeapAlloc(GetProcessHeap(), 0, fileSize);
    if (hFileContent == INVALID_HANDLE_VALUE) {
        std::cerr << "Can't load " << path << " into memory." << std::endl;
        CloseHandle(hFile);
        CloseHandle(hFileContent);
        return nullptr;
    }

    // Read file into memory
    const BOOL bFileRead = ReadFile(hFile, hFileContent, fileSize, nullptr, nullptr);
    if (!bFileRead) {
        std::cerr << "Can't read content of " << path << "." << std::endl;
        CloseHandle(hFile);
        if (hFileContent != nullptr) {
            CloseHandle(hFileContent);
        }
        return nullptr;
    }

    CloseHandle(hFile);
    return hFileContent;
}

BOOL my_loader::IsValidPE(PVOID hModule) {
    // IMAGE_DOS_HEADER is at the very beginning of file
    IMAGE_DOS_HEADER* dosHeaders = (IMAGE_DOS_HEADER*)hModule;
    // For valid PE, e_magic must have IMAGE_DOS_SIGNATURE value
    if (!dosHeaders || dosHeaders->e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }

    // IMAGE_NT_HEADERS is offset by e_lfanew in IMAGE_DOS_HEADER
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)dosHeaders + dosHeaders->e_lfanew);
    // For valid PE, Signature must have IMAGE_NT_SIGNATURE
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }
    return true;
}

CHAR* my_loader::DeObfuscate(const char* input) {
    // Simple de-obfuscate function
	const char key = 'a';
    size_t length = strlen(input);
    char* obfuscated = new char[length + 1];

    for (size_t i = 0; i < length; ++i) {
        obfuscated[i] = input[i] ^ key;
    }
    obfuscated[length] = '\0';

    return obfuscated;
}
