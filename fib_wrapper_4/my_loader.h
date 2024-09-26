#pragma once
#include <windows.h>

class my_loader {
public:
	static PVOID MyGetProcAddress(HMODULE hModule, LPCSTR name);
	static HMODULE MyLoadLibrary(LPCSTR path);
	static CHAR* DeObfuscate(const char* input);

private:
	static HANDLE MyLoadFileContent(LPCSTR path);
	static BOOL IsValidPE(PVOID hModule);
};
