#include "my_loader.h"


PVOID my_loader::MyGetProcAddress(HMODULE hModule, LPCSTR name)
{
    if (!hModule || !name) return nullptr;

    // IMAGE_DOS_HEADER is at the very beginning of file
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)hModule;
    // For valid PE, e_magic must have IMAGE_DOS_SIGNATURE value
    if (!dosHeader || dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

    // IMAGE_NT_HEADERS is offset by e_lfanew in IMAGE_DOS_HEADER
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)dosHeader + dosHeader->e_lfanew);
    // For valid PE, Signature must have IMAGE_NT_SIGNATURE
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return nullptr;

    // IMAGE_OPTIONAL_HEADER contains DataDirectory array
    IMAGE_DATA_DIRECTORY exportEntry = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    IMAGE_EXPORT_DIRECTORY* exportDirectory = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)dosHeader + exportEntry.VirtualAddress);
    DWORD functionCount = exportDirectory->NumberOfFunctions;
    // Ensure export directory exists
    if (!exportEntry.Size || !exportDirectory  || !functionCount) return nullptr;

    // Get by ordinal, if possible
    DWORD* functionArray = (DWORD*)((BYTE*)dosHeader + exportDirectory->AddressOfFunctions);
    unsigned long ordinalBase = exportDirectory->Base;

    // If passed, ordinal value must be in the low-order word; the high-order word must be zero
    if ((ULONG_PTR)name < 0xFFFF) {
        unsigned short ordinal = (ULONG_PTR)name & 0xFFFF;
        // Return function by ordinal
        if (ordinal - ordinalBase < functionCount)
            return (PVOID)((BYTE*)dosHeader + functionArray[ordinal - ordinalBase]);
    }

    // Get by name
    DWORD* nameArray = (DWORD*)((BYTE*)dosHeader + exportDirectory->AddressOfNames);
    WORD* ordinalArray = (WORD*)((BYTE*)dosHeader + exportDirectory->AddressOfNameOrdinals);
    // Iterate to find function by name
    for (DWORD i = 0; i < functionCount; i++) {
        // Check name
        LPCSTR functionName = (LPCSTR)((BYTE*)dosHeader + nameArray[i]);
        if (strcmp(functionName, name) == 0)
        {
            DWORD funcOffset = functionArray[ordinalArray[i]];
            return (PVOID)((BYTE*)dosHeader + funcOffset);
        }
    }

    return nullptr;
}

HMODULE my_loader::MyLoadLibrary(LPCSTR path)
{
    return LoadLibraryA(path);
}