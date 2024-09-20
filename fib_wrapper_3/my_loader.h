#pragma once
#include <windows.h>

class my_loader {
public:
	static PVOID MyGetProcAddress(HMODULE hModule, LPCSTR name);
	static HMODULE MyLoadLibrary(LPCSTR path);
};
