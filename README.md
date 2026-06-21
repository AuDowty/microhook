# microhook

Modern C++20 x64 inline-hooking library for Windows. ~600 LOC, no external deps.

## Intended use

Built for legitimate Windows internals work — same audience as [Detours](https://github.com/microsoft/Detours), [MinHook](https://github.com/TsudaKageyu/minhook), and [Frida](https://frida.re/):

- **Security research / EDR development** — exercising endpoint detection products with known hooking techniques
- **Debugger and profiler tooling** — function-call interception is a core debugger primitive
- **Game modding** — Windows modding ecosystems (Minecraft, Skyrim, etc.) commonly load DLL mods that hook game functions
- **Learning** — inline hooking is a classic Windows-internals topic; this is a clean reference implementation

**Don't hook code in processes you don't own or aren't authorized to test.**

## What it does

Patches the first instructions of an x64 function with a `jmp` to your detour function. Saves the original instructions to a trampoline so you can still call the unhooked version.

- Length disassembly: hand-rolled mini x64 LDE (~250 LOC) that covers the common prologue instruction set (MOV/SUB/PUSH/CALL/JMP/conditional jumps/etc.)
- Trampoline allocation: VirtualAlloc'd within ±2GB of the target so a 5-byte `jmp rel32` works (falls back to a 14-byte `jmp [rip+0]; .qword target` absolute when the detour is far)
- Header-only public API: include `microhook/microhook.hpp`

## Use

```cpp
#include <microhook/microhook.hpp>

using AddFn = int(int, int);

microhook::Hook g_hook{};
int real_add(int a, int b) { return a + b; }

int my_add(int a, int b) {
    auto original = microhook::trampoline_as<AddFn>(g_hook);
    return original(a, b) + 1000;
}

int main() {
    microhook::install_t<AddFn>(real_add, my_add, g_hook);
    // real_add(2, 3) now returns 1005

    microhook::uninstall(g_hook);
    // real_add(2, 3) returns 5 again
}
```

## Build

```
cmake -B build -A x64
cmake --build build --config Release
.\build\Release\selfhook.exe
```

Expected output:

```
before hook: add(2, 3) = 5
[hook] add(2, 3) -> 5  (returning real+1000)
after hook:  add(2, 3) = 1005
after unhook: add(2, 3) = 5
OK
```

## Status

**v0.1**: x64 inline hooks. No x86, no ARM64, no IAT/VTable shortcuts, no thread-safe atomic patching (just `VirtualProtect` + `memcpy`). Plenty for single-threaded RE/dev work; not yet hardened for multi-thread production use.

**Roadmap**: thread-suspension during patch (atomic-ish), IAT helper, VTable helper, ARM64, x86 32-bit, `wait-free` hot patching via double-CAS.

## License

MIT.
