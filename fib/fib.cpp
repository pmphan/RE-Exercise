#include "fib.h"

unsigned long long fib(int n) {
    if (n < 0) {
        return 0;
    }
    if (n <= 1) {
        return n;
    }
    return fib(n-1) + fib(n-2);
}