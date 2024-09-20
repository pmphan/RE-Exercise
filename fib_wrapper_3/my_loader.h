#pragma once
#include <windows.h>

PVOID MyGetProcAddress(HMODULE hModule, LPCSTR name);

HMODULE MyLoadLibrary(LPCSTR path);