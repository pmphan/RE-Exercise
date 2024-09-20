#include <iostream>
#include "my_loader.h"

// Fib function signature
typedef unsigned long long (__stdcall* t_func)(int n);

int main()
{
    // Dynamically load dll
    HINSTANCE hModule = my_loader::MyLoadLibrary("fib.dll");
    if (!hModule) {
        std::cerr << "Could not dynamically load fib.dll" << std::endl;
        return EXIT_FAILURE;
    }

    // Load the function
    PVOID procAddress = my_loader::MyGetProcAddress(hModule, MAKEINTRESOURCEA(3));
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
