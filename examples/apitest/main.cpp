#include <microhook/microhook.hpp>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <utility>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

// --- test 1: hook a local function (same as selfhook) ---

using AddFn = int(int, int);
static microhook::Hook g_add_hook{};

static int __declspec(noinline) add(int a, int b) {
    volatile int x = a;
    volatile int y = b;
    return x + y;
}

static int my_add(int a, int b) {
    auto original = microhook::trampoline_as<AddFn>(g_add_hook);
    return original(a, b) + 1000;
}

// --- test 2: hook GetTickCount64 (RIP-relative prologue on most Windows) ---

using GetTickCount64Fn = ULONGLONG(WINAPI)();
static microhook::Hook g_tick_hook{};
static ULONGLONG g_fake_tick = 42;

static ULONGLONG WINAPI my_tick() {
    auto original = microhook::trampoline_as<GetTickCount64Fn>(g_tick_hook);
    (void)original();
    return g_fake_tick;
}

static int failures = 0;

static void check(bool cond, const char* msg) {
    if (!cond) {
        std::fprintf(stderr, "  FAIL: %s\n", msg);
        failures++;
    }
}

int main() {
    std::fprintf(stderr, "--- local function hook ---\n");
    {
        auto s = microhook::install_t<AddFn>(add, my_add, g_add_hook);
        check(s == microhook::Status::Ok, "install add hook");
        check(add(2, 3) == 1005, "hooked add returns 1005");

        // double install guard
        microhook::Hook dup{};
        dup.installed = true;
        check(microhook::install(nullptr, nullptr, dup) == microhook::Status::AlreadyHooked,
              "AlreadyHooked guard");

        // enable/disable
        check(microhook::disable(g_add_hook) == microhook::Status::Ok, "disable ok");
        check(add(2, 3) == 5, "disabled add returns 5");
        check(microhook::disable(g_add_hook) == microhook::Status::AlreadyDisabled,
              "double disable returns AlreadyDisabled");
        check(microhook::enable(g_add_hook) == microhook::Status::Ok, "enable ok");
        check(add(2, 3) == 1005, "re-enabled add returns 1005");
        check(microhook::enable(g_add_hook) == microhook::Status::AlreadyEnabled,
              "double enable returns AlreadyEnabled");

        check(microhook::uninstall(g_add_hook) == microhook::Status::Ok, "uninstall add");
        check(add(2, 3) == 5, "unhooked add returns 5");
    }

    std::fprintf(stderr, "--- win32 api hook (GetTickCount64) ---\n");
    {
        auto* fn = reinterpret_cast<void*>(&GetTickCount64);
        auto s = microhook::install(fn, reinterpret_cast<void*>(&my_tick), g_tick_hook);
        if (s != microhook::Status::Ok) {
            std::fprintf(stderr, "  SKIP: install returned %s\n", microhook::status_to_string(s));
        } else {
            ULONGLONG t = GetTickCount64();
            check(t == g_fake_tick, "hooked GetTickCount64 returns fake value");
            check(microhook::uninstall(g_tick_hook) == microhook::Status::Ok,
                  "uninstall GetTickCount64");
            check(GetTickCount64() != g_fake_tick, "unhooked GetTickCount64 returns real value");
        }
    }

    std::fprintf(stderr, "--- status_to_string ---\n");
    {
        check(std::strcmp(microhook::status_to_string(microhook::Status::Ok), "Ok") == 0,
              "Ok string");
        check(std::strcmp(microhook::status_to_string(microhook::Status::RelocationFailed),
                          "RelocationFailed") == 0, "RelocationFailed string");
    }

    std::fprintf(stderr, "--- null guards ---\n");
    {
        microhook::Hook h{};
        check(microhook::install(nullptr, (void*)1, h) == microhook::Status::NullTarget,
              "NullTarget");
        check(microhook::install((void*)1, nullptr, h) == microhook::Status::NullDetour,
              "NullDetour");
    }

    std::fprintf(stderr, "--- hook/unhook cycle (slab reuse) ---\n");
    {
        for (int i = 0; i < 200; i++) {
            auto s = microhook::install_t<AddFn>(add, my_add, g_add_hook);
            check(s == microhook::Status::Ok, "cycle install");
            check(add(2, 3) == 1005, "cycle hooked");
            check(microhook::uninstall(g_add_hook) == microhook::Status::Ok, "cycle uninstall");
            check(add(2, 3) == 5, "cycle unhooked");
        }
    }

    std::fprintf(stderr, "--- scoped hook ---\n");
    {
        {
            microhook::ScopedHook sh;
            auto s = microhook::install_t<AddFn>(add, my_add, sh.hook);
            check(s == microhook::Status::Ok, "scoped install");
            check(sh.hook.installed, "scoped is installed");
        }
        check(add(2, 3) == 5, "scoped auto-uninstall");

        {
            microhook::ScopedHook a;
            microhook::install_t<AddFn>(add, my_add, a.hook);
            microhook::ScopedHook b = std::move(a);
            check(!a.hook.installed, "source cleared after move");
            check(b.hook.installed, "dest has the hook");
        }
        check(add(2, 3) == 5, "moved hook auto-uninstalled");
    }

    if (failures == 0)
        std::fprintf(stderr, "\nALL PASSED\n");
    else
        std::fprintf(stderr, "\n%d FAILED\n", failures);

    return failures;
}
