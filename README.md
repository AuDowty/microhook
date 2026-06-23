# microhook

C++20 inline hooking library for Windows. x86 and x64, ~700 LOC, zero dependencies.

Patches function prologues with a `jmp` to your detour, saves the originals to a trampoline with full instruction relocation. Thread IP adjustment, RIP-relative addressing (x64), VEX/SSE4 instruction support, short branch expansion, relay stubs for far detours, and slab-allocated trampolines with slot reuse out of the box.

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
    auto s = microhook::install_t<AddFn>(real_add, my_add, g_hook);
    // real_add(2, 3) now returns 1005

    microhook::disable(g_hook);
    // real_add(2, 3) returns 5 — hook paused, trampoline kept

    microhook::enable(g_hook);
    // real_add(2, 3) returns 1005 again

    microhook::uninstall(g_hook);
    // hook fully removed
}
```

Works on local functions, vtable entries, and Win32 APIs (`GetTickCount64`, `MessageBoxA`, etc.).

## How it works

1. **Length disassembly** — hand-rolled LDE walks the prologue to find instruction boundaries. Dual-mode: handles x86 (`INC`/`DEC` reg, `[disp32]`) and x64 (REX prefixes, `[RIP+disp32]`, `MOV r64,imm64`) natively via compile-time selection. Supports VEX-prefixed AVX instructions (2-byte `C5` and 3-byte `C4`) and three-byte escape maps (`0F 38`, `0F 3A`) for SSSE3/SSE4.

2. **Instruction relocation** — stolen bytes are copied to a trampoline one instruction at a time. On x64, `[RIP+disp32]` displacements are adjusted (including inside VEX and three-byte escape instructions). Short branches (`Jcc rel8`, `JMP rel8`) expand to `rel32` equivalents, and `CALL`/`JMP rel32` offsets are recalculated.

3. **Trampoline allocation** — a slab allocator carves 96-byte slots from shared 4KB pages with a free-list for slot reuse. On x64, pages are allocated within ±2GB of the target. If the detour is beyond ±2GB, a relay stub (14-byte `jmp abs`) is placed in the near-allocated slot so the patch site always uses a compact 5-byte `jmp rel32`. On x86, any page works since `rel32` covers the full address space.

4. **Thread-safe patching with IP adjustment** — all other threads are suspended during patch/unpatch. If a suspended thread's instruction pointer is inside the patch zone, it's relocated to the corresponding trampoline offset (or back on uninstall). This prevents crashes when a thread is mid-prologue during the patch.

5. **INT3 padding** — remaining stolen bytes after the jump are filled with `0xCC` so a stale jump into the middle crashes cleanly.

## API

| Function | Description |
|----------|-------------|
| `install(target, detour, hook)` | Hook a function. Returns `Status::Ok` on success. |
| `uninstall(hook)` | Remove hook and poison the trampoline. |
| `enable(hook)` / `disable(hook)` | Toggle the patch without destroying the trampoline. |
| `install_t<Fn>(target, detour, hook)` | Type-safe `install` wrapper. |
| `trampoline_as<Fn>(hook)` | Cast the trampoline to a callable function pointer. |
| `status_to_string(status)` | `Status` enum to string for diagnostics. |
| `ScopedHook` | RAII wrapper — calls `uninstall` on destruction. Movable, not copyable. |

## Build

```
# x64
cmake -B build -A x64
cmake --build build --config Release
.\build\Release\selfhook.exe
.\build\Release\apitest.exe

# x86
cmake -B build32 -A Win32
cmake --build build32 --config Release
.\build32\Release\selfhook.exe
.\build32\Release\apitest.exe
```

## License

MIT
