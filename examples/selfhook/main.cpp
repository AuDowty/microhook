#include <microhook/microhook.hpp>

#include <cstdio>
#include <cstdlib>

using AddFn = int(int, int);

static int __declspec(noinline) add(int a, int b) {
    volatile int x = a;
    volatile int y = b;
    return x + y;
}

static microhook::Hook g_hook{};

static int my_add(int a, int b) {
    auto original = microhook::trampoline_as<AddFn>(g_hook);
    int real = original(a, b);
    std::fprintf(stderr, "[hook] add(%d, %d) -> %d  (returning real+1000)\n", a, b, real);
    return real + 1000;
}

int main() {
    std::fprintf(stderr, "before hook: add(2, 3) = %d\n", add(2, 3));

    auto status = microhook::install_t<AddFn>(add, my_add, g_hook);
    if (status != microhook::Status::Ok) {
        std::fprintf(stderr, "install failed: %d\n", static_cast<int>(status));
        return 1;
    }

    int hooked = add(2, 3);
    std::fprintf(stderr, "after hook:  add(2, 3) = %d\n", hooked);
    if (hooked != 1005) {
        std::fprintf(stderr, "FAIL: expected 1005 (real 5 + 1000), got %d\n", hooked);
        return 2;
    }

    if (microhook::uninstall(g_hook) != microhook::Status::Ok) {
        std::fprintf(stderr, "uninstall failed\n");
        return 3;
    }

    int unhooked = add(2, 3);
    std::fprintf(stderr, "after unhook: add(2, 3) = %d\n", unhooked);
    if (unhooked != 5) {
        std::fprintf(stderr, "FAIL: expected 5 after unhook, got %d\n", unhooked);
        return 4;
    }

    std::fprintf(stderr, "OK\n");
    return 0;
}
