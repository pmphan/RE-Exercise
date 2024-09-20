#pragma once

#ifdef FIB_EXPORTS
#define FIB_DECLSPEC __declspec(dllexport)
#else
#define FIB_DECLSPEC __declspec(dllimport)
#endif

#ifdef __cplusplus
extern "C" {
#endif

FIB_DECLSPEC unsigned long long fib(int n);

FIB_DECLSPEC unsigned long long fib_noname(int n) {
    return fib(n);
}

#ifdef __cplusplus
}
#endif