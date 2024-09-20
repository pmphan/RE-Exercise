#include <iostream>
#include <windows.h>
#include "my_loader.h"

// Fib function signature
typedef unsigned long (__stdcall* t_func)(int n);

int main()
{
    // Dynamically load dll
    HINSTANCE hModule = LoadLibraryA("fib.dll");
    if (!hModule) {
        std::cerr << "Could not dynamically load fib.dll" << std::endl;
        return EXIT_FAILURE;
    }

    // Load the function
    PVOID procAddress = MyGetProcAddress(hModule, MAKEINTRESOURCEA(2));
    if (!procAddress) {
        FreeLibrary(hModule);
        std::cerr << "Could not load function from fib.dll" << std::endl;
        return EXIT_FAILURE;
    }

    // Call the function
    t_func func = reinterpret_cast<t_func>(procAddress);
    std::cout << "Result: " << func(10);

    // Clean up
    FreeLibrary(hModule);
    return EXIT_SUCCESS;
}
