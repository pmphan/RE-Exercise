# Exercise 1: Image loading

## Q1 - fib.dll

1. Analyze `fib.dll` using static analysis tools.

   Remarks:
   * The import list is quite long despite the function being relatively simple and doesn't really import anything on its own.
   * Subsystem is `IMAGE_SUBSYSTEM_WINDOWS_GUI`. Must be the default option since the dll is definitely not using any GUI.
   * There are a lot of strings that look like exception messages.

2. Analyze `fib.dll` using IDA.

   Remarks on Debug build:
   * All "main" functions have the following structure. `ProcedureName_0` would hold the main execution logic. Not sure why it has to be done this way instead of just having `ProcedureName` hold the logic directly.
     ```assembly
     ; =============== S U B R O U T I N E =======================================
     ; Attributes: thunk
     ProcedureName   proc near               ; CODE XREF: sub_180012C00+4↓p
                     jmp     ProcedureName_0
     ProcedureName   endp
     ; ---------------------------------------------------------------------------
     ```
   * There's a lot of extra functions.
   * There's a weird call to another function before the main logic of `fib`. This function seemingly does something about exception handling behavior.
   * If `fib` uses recursion, `ecx` is used to hold the parameter instead of pushing to the stack, presumably for optimization reason.

    Remarks on Release build:
    * The redundant `jmp` structure in every procedure is gone. This lead me to believe the `jmp` thing is there for debugging purpose (maybe to breakpoint before procedure call).
    * The extra call at the beginning of `fib` is gone. `fib` now only contains the main logic.
    * Much much fewer extra functions.
    * Much smarter code, possibly because of /O2 (Maximum Optimization (Favor Speed)). Some example:
      * If the for loop has a small fixed number of iterations, it can pre-calculate some part of it. However it doesn't seem to do the same for recursion.
      * This snippet of code is executed purely on registers in Release build, while Debug build wastes a lot of time moving value around in local variables.
        ```cpp
        long a = 0;
        long b = 1;
        long temp = b;
        b += a;
        a = temp;
        ```

3. Can you export a function without a name?

   It's possible to export function by ordinal only instead of by name. Relevant Microsoft's documentation: [Exporting Functions from a DLL by Ordinal Rather Than by Name](https://learn.microsoft.com/en-us/cpp/build/exporting-functions-from-a-dll-by-ordinal-rather-than-by-name?view=msvc-170).

   In this exercise, `fib_noname` is exported with `NONAME` option. See [fib.def](fib/fib.def)

4. Can you make a dll without the dll name as a string somewhere in the binary?

   The `IMAGE_EXPORT_DIRECTORY` structure will always contain a `Name` field that has the name of the dll. However, this field can be modified after compilation. As Windows does not check for this when loading, this doesn't affect anything.

5. Can you change the image base?

   Presumably by using the `/BASE` linking option: https://learn.microsoft.com/en-us/cpp/build/reference/base-base-address?view=msvc-170

   In this exercise, `/BASE` is set to 0x60000000. See [fib.vcxproj](fib/fib.vcxproj#L88).

6. How can you reduce the image size?

   Build it with Release configuration reduces its size quite considerably.

## Q2 - fib_wrapper.exe

1. Analyze `fib_wrapper.exe` using static analysis tools and IDA.

   Remark:
   * IDA couldn't recognize operator `<<`. It is decompiled into a `sub_address` function.

2. How would you detect dynamic DLL loading?

   In this case, the dead giveaways are imports and calls to `LoadLibrary` and `GetProcAddress`.

## Q3 - fib_wrapper_2.exe

Useful references:
  * [Header structure](https://learn.microsoft.com/en-us/archive/msdn-magazine/2002/february/inside-windows-win32-portable-executable-file-format-in-detail)
  * [`GetProcAddress` documentation](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress)
  * [How ordinal works and other stuff](https://www.infosecinstitute.com/resources/malware-analysis/malware-researchers-handbook/)

Remark: It feels impossible to figure out what this function does just by looking at the Assembly file and without any prior knowledge or context.

## Q4 - fib_wrapper_3.exe

1. How would you detect dynamic loading?

   In this case, calls to `CreateFile`, `ReadFile` and `VirtualAlloc` with the DLL's name are easy signifier.

2. How can you evade detection?

   Perhaps obfuscating the DLL names so that it wouldn't immediately show up in the string list and only de-obfuscating it during runtime would be a good idea. Calls to `CreateFile`, `ReadFile` and `VirtualAlloc` can also be dynamically loaded.

   [`fib_wrapper_4`](./fib_wrapper_4/) contains a simple deobfuscation function. In this exe, the `fib.dll` string is obfuscated.
