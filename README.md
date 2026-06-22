# microhook

C++20 x64 inline hooking library for Windows. ~550 LOC, zero dependencies.

Patches function prologues with a `jmp` to your detour, saves the originals to a trampoline with full instruction relocation. Handles RIP-relative addressing, short branch expansion, and thread-safe patching out of the box.

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

1. **Length disassembly** — hand-rolled LDE walks the prologue to find instruction boundaries. Covers all common x64 opcodes including two-byte `0F xx`, x87, and `F6`/`F7` TEST-with-immediate.

2. **Instruction relocation** — stolen bytes are copied to a trampoline one instruction at a time. `[RIP+disp32]` addressing gets its displacement adjusted, short branches (`Jcc rel8`, `JMP rel8`) expand to their `rel32` equivalents, and `CALL`/`JMP rel32` offsets are recalculated.

3. **Trampoline allocation** — a slab allocator carves 96-byte slots from shared 4KB pages within ±2GB of the target, so the patch site uses a compact 5-byte `jmp rel32`. Falls back to 14-byte absolute when needed.

4. **Thread-safe patching** — all other threads are suspended during patch and unpatch via `CreateToolhelp32Snapshot` + `SuspendThread`, preventing torn reads of the partially-written jump.

5. **INT3 padding** — any remaining stolen bytes after the jump are filled with `0xCC` so a stale jump into the middle crashes cleanly instead of running garbage.

## API

| Function | Description |
|----------|-------------|
| `install(target, detour, hook)` | Hook a function. Returns `Status::Ok` on success. |
| `uninstall(hook)` | Remove hook and poison the trampoline. |
| `enable(hook)` / `disable(hook)` | Toggle the patch without destroying the trampoline. |
| `install_t<Fn>(target, detour, hook)` | Type-safe `install` wrapper. |
| `trampoline_as<Fn>(hook)` | Cast the trampoline to a callable function pointer. |
| `status_to_string(status)` | `Status` enum to string for diagnostics. |

## Build

```
cmake -B build -A x64
cmake --build build --config Release
.\build\Release\selfhook.exe
.\build\Release\apitest.exe
```

## License

MIT
