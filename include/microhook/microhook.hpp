#pragma once

#include <cstddef>
#include <cstdint>

namespace microhook {

enum class Status {
    Ok = 0,
    AlreadyHooked,
    NotHooked,
    UnsupportedPrologue,
    AllocationFailed,
    ProtectFailed,
    NullTarget,
    NullDetour,
};

struct Hook {
    void* target;
    void* detour;
    void* trampoline;
    void* trampoline_region;
    std::size_t stolen_bytes;
    std::uint8_t original_prologue[32];
    bool installed;
};

Status install(void* target, void* detour, Hook& out);
Status uninstall(Hook& hook);

template <typename Fn>
Status install_t(Fn* target, Fn* detour, Hook& out) {
    return install(reinterpret_cast<void*>(target), reinterpret_cast<void*>(detour), out);
}

template <typename Fn>
Fn* trampoline_as(const Hook& hook) {
    return reinterpret_cast<Fn*>(hook.trampoline);
}

}
