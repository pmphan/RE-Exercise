#include <iostream>
#include "my_loader.h"

// Fib function signature
typedef unsigned long long (__stdcall* t_func)(int n);

int main()
{
    const char fibDll[8] = {0x07, 0x08, 0x03, 0x4F, 0x05, 0x0D, 0x0D};
    // Dynamically load dll
    HINSTANCE hModule = my_loader::MyLoadLibrary(my_loader::DeObfuscate(fibDll));
    if (!hModule) {
        std::cerr << "Could not dynamically load fib.dll" << std::endl;
        return EXIT_FAILURE;
    }

    // Load the function
    PVOID procAddress = my_loader::MyGetProcAddress(hModule, MAKEINTRESOURCEA(1));
    if (!procAddress) {
        FreeLibrary(hModule);
        std::cerr << "Could not load function from fib.dll" << std::endl;
        return EXIT_FAILURE;
    }

    // Call the function
    t_func func = reinterpret_cast<t_func>(procAddress);
    std::cout << "Result: " << func(11);

    // Clean up
    FreeLibrary(hModule);
    return EXIT_SUCCESS;
}
