#include <microhook/microhook.hpp>

#include <cstring>
#include <new>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace microhook {
namespace {

constexpr std::size_t kJmpRel32Size = 5;
constexpr std::size_t kJmpAbsSize = 14;
constexpr std::size_t kTrampolineSize = 64;
constexpr std::size_t kAllocSize = 0x1000;
constexpr std::int64_t kRel32MaxDistance = 0x7fff'ffff;

std::size_t lde_x64(const std::uint8_t* code);

bool within_rel32(const void* from, const void* to) {
    auto delta = reinterpret_cast<std::int64_t>(to) - reinterpret_cast<std::int64_t>(from);
    return delta >= -kRel32MaxDistance && delta <= kRel32MaxDistance;
}

void* alloc_near(void* target_addr) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    auto granularity = static_cast<std::uintptr_t>(si.dwAllocationGranularity);
    auto target = reinterpret_cast<std::uintptr_t>(target_addr);

    std::uintptr_t low = target > kRel32MaxDistance ? target - kRel32MaxDistance : 0;
    std::uintptr_t high = target + kRel32MaxDistance;

    low = (low + granularity - 1) & ~(granularity - 1);
    high = high & ~(granularity - 1);

    for (auto addr = low; addr < high; addr += granularity) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == 0) {
            continue;
        }
        if (mbi.State != MEM_FREE) {
            addr = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            addr = (addr + granularity - 1) & ~(granularity - 1);
            addr -= granularity;
            continue;
        }
        void* p = VirtualAlloc(
            reinterpret_cast<LPVOID>(addr),
            kAllocSize,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE);
        if (p) return p;
    }
    return nullptr;
}

bool patch_bytes(void* dst, const void* src, std::size_t n) {
    DWORD old = 0;
    if (!VirtualProtect(dst, n, PAGE_EXECUTE_READWRITE, &old)) return false;
    std::memcpy(dst, src, n);
    DWORD ignored;
    VirtualProtect(dst, n, old, &ignored);
    FlushInstructionCache(GetCurrentProcess(), dst, n);
    return true;
}

void emit_jmp_rel32(std::uint8_t* write_to, const void* runtime_at, const void* to) {
    auto rel = static_cast<std::int32_t>(
        reinterpret_cast<std::int64_t>(to) -
        reinterpret_cast<std::int64_t>(runtime_at) - kJmpRel32Size);
    write_to[0] = 0xE9;
    std::memcpy(write_to + 1, &rel, 4);
}

void emit_jmp_abs(std::uint8_t* at, const void* to) {
    at[0] = 0xFF;
    at[1] = 0x25;
    std::int32_t zero = 0;
    std::memcpy(at + 2, &zero, 4);
    std::uint64_t target = reinterpret_cast<std::uint64_t>(to);
    std::memcpy(at + 6, &target, 8);
}

}

Status install(void* target, void* detour, Hook& out) {
    if (!target) return Status::NullTarget;
    if (!detour) return Status::NullDetour;
    if (target == detour) return Status::NullDetour;

    auto* src = static_cast<std::uint8_t*>(target);

    auto* detour_bytes = static_cast<const std::uint8_t*>(detour);
    const std::size_t min_stolen =
        within_rel32(src + kJmpRel32Size, detour_bytes) ? kJmpRel32Size : kJmpAbsSize;
    std::size_t stolen = 0;
    while (stolen < min_stolen) {
        auto n = lde_x64(src + stolen);
        if (n == 0 || n > 15) return Status::UnsupportedPrologue;
        stolen += n;
        if (stolen > 32) return Status::UnsupportedPrologue;
    }

    void* tramp_region = alloc_near(target);
    if (!tramp_region) return Status::AllocationFailed;

    auto* tramp = static_cast<std::uint8_t*>(tramp_region);
    std::memcpy(tramp, src, stolen);

    auto* jump_back = src + stolen;
    auto* after_stolen = tramp + stolen;
    if (within_rel32(after_stolen + kJmpRel32Size, jump_back)) {
        emit_jmp_rel32(after_stolen, after_stolen, jump_back);
    } else {
        emit_jmp_abs(after_stolen, jump_back);
    }

    std::uint8_t patch[kJmpRel32Size]{};
    if (within_rel32(src + kJmpRel32Size, detour)) {
        emit_jmp_rel32(patch, src, detour);
    } else {
        std::uint8_t fat[kJmpAbsSize]{};
        emit_jmp_abs(fat, detour);
        if (stolen < kJmpAbsSize) {
            VirtualFree(tramp_region, 0, MEM_RELEASE);
            return Status::UnsupportedPrologue;
        }
        Hook h{};
        h.target = target;
        h.detour = detour;
        h.trampoline = tramp_region;
        h.trampoline_region = tramp_region;
        h.stolen_bytes = stolen;
        std::memcpy(h.original_prologue, src, stolen);
        if (!patch_bytes(src, fat, kJmpAbsSize)) {
            VirtualFree(tramp_region, 0, MEM_RELEASE);
            return Status::ProtectFailed;
        }
        h.installed = true;
        out = h;
        return Status::Ok;
    }

    Hook h{};
    h.target = target;
    h.detour = detour;
    h.trampoline = tramp_region;
    h.trampoline_region = tramp_region;
    h.stolen_bytes = stolen;
    std::memcpy(h.original_prologue, src, stolen);

    if (!patch_bytes(src, patch, kJmpRel32Size)) {
        VirtualFree(tramp_region, 0, MEM_RELEASE);
        return Status::ProtectFailed;
    }
    h.installed = true;
    out = h;
    return Status::Ok;
}

Status uninstall(Hook& hook) {
    if (!hook.installed) return Status::NotHooked;
    if (!patch_bytes(hook.target, hook.original_prologue, hook.stolen_bytes)) {
        return Status::ProtectFailed;
    }
    if (hook.trampoline_region) {
        VirtualFree(hook.trampoline_region, 0, MEM_RELEASE);
    }
    hook.installed = false;
    hook.trampoline = nullptr;
    hook.trampoline_region = nullptr;
    return Status::Ok;
}

namespace {

bool has_modrm(std::uint8_t op);
std::size_t modrm_extra(const std::uint8_t* code);

std::size_t lde_x64(const std::uint8_t* code) {
    std::size_t i = 0;
    bool has_operand_override = false;
    while (true) {
        std::uint8_t b = code[i];
        bool is_prefix =
            b == 0xF0 || b == 0xF2 || b == 0xF3 ||
            b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 ||
            b == 0x64 || b == 0x65 ||
            b == 0x66 || b == 0x67;
        if (!is_prefix) break;
        if (b == 0x66) has_operand_override = true;
        i++;
        if (i > 4) return 0;
    }
    if ((code[i] & 0xF0) == 0x40) {
        i++;
    }

    std::uint8_t op = code[i++];

    if (op == 0x0F) {
        std::uint8_t op2 = code[i++];
        if ((op2 >= 0x80 && op2 <= 0x8F)) {
            return i + 4;
        }
        if (op2 == 0x05 || op2 == 0x06 || op2 == 0x07 || op2 == 0x08 ||
            op2 == 0x09 || op2 == 0x0B || op2 == 0x0D || op2 == 0x1F) {
            i += modrm_extra(code + i);
            return i;
        }
        if (op2 >= 0x40 && op2 <= 0x4F) {
            i += modrm_extra(code + i);
            return i;
        }
        if (has_modrm(op2)) {
            i += modrm_extra(code + i);
            return i;
        }
        return 0;
    }

    if (op == 0xE8 || op == 0xE9) {
        return i + 4;
    }
    if (op == 0xEB) {
        return i + 1;
    }
    if ((op >= 0x70 && op <= 0x7F) || op == 0xE0 || op == 0xE1 || op == 0xE2 || op == 0xE3) {
        return i + 1;
    }
    if (op == 0xC3 || op == 0xCB || op == 0xC9 || op == 0xCC || op == 0xCD || op == 0x90) {
        if (op == 0xCD) return i + 1;
        return i;
    }
    if (op >= 0x50 && op <= 0x5F) {
        return i;
    }
    if (op == 0x68) {
        return i + 4;
    }
    if (op == 0x6A) {
        return i + 1;
    }
    if (op == 0xC2 || op == 0xCA) {
        return i + 2;
    }

    if (op == 0xC6 || op == 0xC7) {
        std::size_t extra = modrm_extra(code + i);
        std::size_t imm = op == 0xC6 ? 1 : (has_operand_override ? 2 : 4);
        return i + extra + imm;
    }

    if (op == 0x80 || op == 0x82 || op == 0x83) {
        std::size_t extra = modrm_extra(code + i);
        std::size_t imm = op == 0x80 || op == 0x82 || op == 0x83 ? (op == 0x83 ? 1 : 1) : 0;
        return i + extra + imm;
    }
    if (op == 0x81) {
        std::size_t extra = modrm_extra(code + i);
        std::size_t imm = has_operand_override ? 2 : 4;
        return i + extra + imm;
    }

    if (has_modrm(op)) {
        i += modrm_extra(code + i);
        return i;
    }

    if (op == 0xB8 || (op >= 0xB8 && op <= 0xBF)) {
        std::size_t imm = has_operand_override ? 2 : 8;
        return i + imm;
    }
    if (op >= 0xB0 && op <= 0xB7) {
        return i + 1;
    }

    if (op == 0x04 || op == 0x0C || op == 0x14 || op == 0x1C ||
        op == 0x24 || op == 0x2C || op == 0x34 || op == 0x3C) {
        return i + 1;
    }
    if (op == 0x05 || op == 0x0D || op == 0x15 || op == 0x1D ||
        op == 0x25 || op == 0x2D || op == 0x35 || op == 0x3D) {
        return i + (has_operand_override ? 2 : 4);
    }

    return 0;
}

bool has_modrm(std::uint8_t op) {
    if (op <= 0x03) return true;
    if (op == 0x08 || op == 0x09 || op == 0x0A || op == 0x0B) return true;
    if (op == 0x10 || op == 0x11 || op == 0x12 || op == 0x13) return true;
    if (op == 0x18 || op == 0x19 || op == 0x1A || op == 0x1B) return true;
    if (op == 0x20 || op == 0x21 || op == 0x22 || op == 0x23) return true;
    if (op == 0x28 || op == 0x29 || op == 0x2A || op == 0x2B) return true;
    if (op == 0x30 || op == 0x31 || op == 0x32 || op == 0x33) return true;
    if (op == 0x38 || op == 0x39 || op == 0x3A || op == 0x3B) return true;
    if (op == 0x84 || op == 0x85 || op == 0x86 || op == 0x87 ||
        op == 0x88 || op == 0x89 || op == 0x8A || op == 0x8B ||
        op == 0x8C || op == 0x8D || op == 0x8E || op == 0x8F) return true;
    if (op == 0xC0 || op == 0xC1) return true;
    if (op == 0xD0 || op == 0xD1 || op == 0xD2 || op == 0xD3) return true;
    if (op == 0xFE || op == 0xFF) return true;
    if (op == 0xF6 || op == 0xF7) return true;
    return false;
}

std::size_t modrm_extra(const std::uint8_t* code) {
    std::uint8_t modrm = code[0];
    std::uint8_t mod = modrm >> 6;
    std::uint8_t rm = modrm & 0x07;
    std::size_t extra = 1;

    if (mod != 3) {
        if (mod == 0 && rm == 5) {
            extra += 4;
        } else {
            if (rm == 4) {
                extra += 1;
                std::uint8_t sib = code[1];
                std::uint8_t base = sib & 0x07;
                if (mod == 0 && base == 5) {
                    extra += 4;
                }
            }
            if (mod == 1) extra += 1;
            if (mod == 2) extra += 4;
        }
    }
    return extra;
}

}

}
