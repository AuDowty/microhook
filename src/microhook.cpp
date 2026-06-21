#include <microhook/microhook.hpp>
#include <cstring>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>

namespace microhook {
namespace {

constexpr std::size_t kJmpRel32 = 5;
constexpr std::size_t kJmpAbs   = 14;
constexpr std::size_t kSlotSize = 96;
constexpr std::size_t kPageSize = 0x1000;
constexpr std::int64_t kRel32Max = 0x7FFF'FFFF;

// ---- jump emission ----

void emit_jmp_rel32(std::uint8_t* buf, const void* from, const void* to) {
    auto rel = static_cast<std::int32_t>(
        reinterpret_cast<std::intptr_t>(to) -
        (reinterpret_cast<std::intptr_t>(from) + kJmpRel32));
    buf[0] = 0xE9;
    std::memcpy(buf + 1, &rel, 4);
}

void emit_jmp_abs(std::uint8_t* buf, const void* to) {
    buf[0] = 0xFF; buf[1] = 0x25;
    std::int32_t zero = 0;
    std::memcpy(buf + 2, &zero, 4);
    auto addr = reinterpret_cast<std::uint64_t>(to);
    std::memcpy(buf + 6, &addr, 8);
}

bool within_rel32(const void* from, const void* to) {
    auto d = reinterpret_cast<std::intptr_t>(to) - reinterpret_cast<std::intptr_t>(from);
    return d >= -kRel32Max && d <= kRel32Max;
}

// ---- memory patching ----

bool patch_bytes(void* dst, const void* src, std::size_t n) {
    DWORD old = 0;
    if (!VirtualProtect(dst, n, PAGE_EXECUTE_READWRITE, &old)) return false;
    std::memcpy(dst, src, n);
    DWORD tmp;
    VirtualProtect(dst, n, old, &tmp);
    FlushInstructionCache(GetCurrentProcess(), dst, n);
    return true;
}

// ---- slab allocator: share 4KB pages across trampolines ----

struct Slab { std::uint8_t* base; std::size_t used; };
Slab g_slabs[64]{};
std::size_t g_slab_count = 0;

void* alloc_near(void* target) {
    for (std::size_t i = 0; i < g_slab_count; i++) {
        auto& s = g_slabs[i];
        if (s.used + kSlotSize <= kPageSize && within_rel32(target, s.base + s.used)) {
            void* p = s.base + s.used;
            s.used += kSlotSize;
            return p;
        }
    }

    SYSTEM_INFO si; GetSystemInfo(&si);
    auto gran = static_cast<std::uintptr_t>(si.dwAllocationGranularity);
    auto tgt = reinterpret_cast<std::uintptr_t>(target);
    std::uintptr_t lo = tgt > static_cast<std::uintptr_t>(kRel32Max) ? tgt - kRel32Max : 0;
    std::uintptr_t hi = tgt + kRel32Max;
    lo = (lo + gran - 1) & ~(gran - 1);
    hi &= ~(gran - 1);

    for (auto addr = lo; addr < hi; addr += gran) {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof mbi)) continue;
        if (mbi.State != MEM_FREE) {
            addr = (reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize
                    + gran - 1) & ~(gran - 1);
            addr -= gran;
            continue;
        }
        void* p = VirtualAlloc(reinterpret_cast<LPVOID>(addr), kPageSize,
                               MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (!p) continue;
        if (g_slab_count < 64)
            g_slabs[g_slab_count++] = { static_cast<std::uint8_t*>(p), kSlotSize };
        return p;
    }
    return nullptr;
}

// ---- modrm decoder ----

std::size_t modrm_extra(const std::uint8_t* code) {
    std::uint8_t modrm = code[0];
    std::uint8_t mod = modrm >> 6;
    std::uint8_t rm  = modrm & 7;
    std::size_t n = 1;

    if (mod == 3) return n;
    if (mod == 0 && rm == 5) { n += 4; return n; }
    if (rm == 4) {
        n++;
        if (mod == 0 && (code[1] & 7) == 5) n += 4;
    }
    if (mod == 1) n++;
    if (mod == 2) n += 4;
    return n;
}

bool opcode_has_modrm(std::uint8_t op) {
    if (op <= 0x3B && (op & 7) <= 3) return true;
    if (op == 0x63) return true;
    if (op == 0x69 || op == 0x6B) return true;
    if (op >= 0x80 && op <= 0x8F) return true;
    if (op == 0xC0 || op == 0xC1) return true;
    if (op == 0xC4 || op == 0xC5) return true;
    if (op == 0xC6 || op == 0xC7) return true;
    if (op >= 0xD0 && op <= 0xD3) return true;
    if (op >= 0xD8 && op <= 0xDF) return true;
    if (op == 0xF6 || op == 0xF7) return true;
    if (op == 0xFE || op == 0xFF) return true;
    return false;
}

// ---- length disassembly engine ----

std::size_t lde_x64(const std::uint8_t* code) {
    std::size_t i = 0;
    bool has_66 = false, has_67 = false, has_rexw = false;

    // legacy prefixes
    while (true) {
        std::uint8_t b = code[i];
        if (b == 0xF0 || b == 0xF2 || b == 0xF3 ||
            b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 ||
            b == 0x64 || b == 0x65) { i++; continue; }
        if (b == 0x66) { has_66 = true; i++; continue; }
        if (b == 0x67) { has_67 = true; i++; continue; }
        break;
    }
    if ((code[i] & 0xF0) == 0x40) { has_rexw = (code[i] & 8) != 0; i++; }

    std::uint8_t op = code[i++];

    // two-byte escape
    if (op == 0x0F) {
        std::uint8_t op2 = code[i++];
        if (op2 >= 0x80 && op2 <= 0x8F) return i + 4;     // Jcc rel32
        if (op2 >= 0xC8 && op2 <= 0xCF) return i;          // BSWAP
        // zero-operand
        if (op2 == 0x05 || op2 == 0x06 || op2 == 0x07 ||
            op2 == 0x08 || op2 == 0x09 || op2 == 0x0B ||
            op2 == 0x31 || op2 == 0x34 || op2 == 0x35 ||
            op2 == 0xA2) return i;
        // modrm + imm8
        if (op2 == 0x70 || op2 == 0x71 || op2 == 0x72 || op2 == 0x73 ||
            op2 == 0xC2 || op2 == 0xC4 || op2 == 0xC5 || op2 == 0xC6 ||
            op2 == 0xA4 || op2 == 0xAC)
            return i + modrm_extra(code + i) + 1;
        // modrm-only (covers most 0F xx: CMOV, SETcc, MOVZX, BT, SSE, etc.)
        if ((op2 >= 0x10 && op2 <= 0x2F) || (op2 >= 0x40 && op2 <= 0x6F) ||
            (op2 >= 0x74 && op2 <= 0x7F) ||
            (op2 >= 0x90 && op2 <= 0x9F) || (op2 >= 0xA3 && op2 <= 0xAF) ||
            (op2 >= 0xB0 && op2 <= 0xBF) || op2 == 0xC0 || op2 == 0xC1 ||
            op2 == 0xC7 ||
            (op2 >= 0xD0 && op2 <= 0xFF) ||
            op2 == 0x0D || op2 == 0x0E || (op2 >= 0x18 && op2 <= 0x1F))
            return i + modrm_extra(code + i);
        return 0;
    }

    // branches
    if (op == 0xE8 || op == 0xE9) return i + 4;
    if (op == 0xEB) return i + 1;
    if (op >= 0x70 && op <= 0x7F) return i + 1;
    if (op == 0xE0 || op == 0xE1 || op == 0xE2 || op == 0xE3) return i + 1;

    // no-operand
    if (op == 0x90) return i;
    if (op == 0xC3 || op == 0xCB) return i;
    if (op == 0xC9) return i;
    if (op == 0xCC) return i;
    if (op == 0xCF) return i;
    if (op == 0xF4 || op == 0xF5) return i;
    if (op >= 0x50 && op <= 0x5F) return i;
    if (op >= 0x91 && op <= 0x97) return i;
    if (op == 0x98 || op == 0x99) return i;
    if (op == 0x9C || op == 0x9D) return i;
    if (op == 0x9E || op == 0x9F) return i;
    if (op >= 0xF8 && op <= 0xFD) return i;
    if (op == 0xCD) return i + 1;
    if (op == 0xE4 || op == 0xE5 || op == 0xE6 || op == 0xE7) return i + 1;

    // immediate-only
    if (op == 0x68) return i + (has_66 ? 2 : 4);
    if (op == 0x6A) return i + 1;
    if (op == 0xC2 || op == 0xCA) return i + 2;
    if (op == 0xC8) return i + 3;  // ENTER imm16, imm8

    // MOV moffs (A0-A3): 8-byte offset in 64-bit, 4 with 67h
    if (op >= 0xA0 && op <= 0xA3) return i + (has_67 ? 4 : 8);

    // TEST AL/AX, imm
    if (op == 0xA8) return i + 1;
    if (op == 0xA9) return i + (has_66 ? 2 : 4);

    // AL/AX immediate forms (04,0C,...,3C)
    if (op <= 0x3D && (op & 7) == 4) return i + 1;
    if (op <= 0x3D && (op & 7) == 5) return i + (has_66 ? 2 : 4);

    // MOV reg, imm
    if (op >= 0xB0 && op <= 0xB7) return i + 1;
    if (op >= 0xB8 && op <= 0xBF) {
        if (has_rexw) return i + 8;
        return i + (has_66 ? 2 : 4);
    }

    // modrm + immediate groups
    if (op == 0xC6) return i + modrm_extra(code + i) + 1;
    if (op == 0xC7) return i + modrm_extra(code + i) + (has_66 ? 2 : 4);
    if (op == 0x80 || op == 0x82 || op == 0x83) return i + modrm_extra(code + i) + 1;
    if (op == 0x81) return i + modrm_extra(code + i) + (has_66 ? 2 : 4);
    if (op == 0x69) return i + modrm_extra(code + i) + (has_66 ? 2 : 4);
    if (op == 0x6B) return i + modrm_extra(code + i) + 1;
    if (op == 0xC0 || op == 0xC1) return i + modrm_extra(code + i) + 1;

    // F6/F7: TEST has immediate, NOT/NEG/MUL/DIV don't
    if (op == 0xF6) {
        std::size_t extra = modrm_extra(code + i);
        std::uint8_t reg = (code[i] >> 3) & 7;
        return i + extra + (reg == 0 ? 1 : 0);
    }
    if (op == 0xF7) {
        std::size_t extra = modrm_extra(code + i);
        std::uint8_t reg = (code[i] >> 3) & 7;
        return i + extra + (reg == 0 ? (has_66 ? 2 : 4) : 0);
    }

    // plain modrm
    if (opcode_has_modrm(op)) return i + modrm_extra(code + i);

    return 0;
}

// ---- instruction relocation ----

enum class BranchType : std::uint8_t {
    None, CallRel32, JmpRel32, JmpRel8, JccRel8, JccRel32
};

struct InsnInfo {
    BranchType branch = BranchType::None;
    bool rip_modrm = false;
    std::size_t disp_offset = 0;
    std::uint8_t cc = 0;
};

InsnInfo analyze_insn(const std::uint8_t* code, std::size_t len) {
    InsnInfo info{};
    std::size_t i = 0;

    while (i < len) {
        std::uint8_t b = code[i];
        if (b == 0xF0 || b == 0xF2 || b == 0xF3 ||
            b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 ||
            b == 0x64 || b == 0x65 || b == 0x66 || b == 0x67) { i++; continue; }
        break;
    }
    if (i < len && (code[i] & 0xF0) == 0x40) i++;
    if (i >= len) return info;

    std::uint8_t op = code[i++];

    if (op == 0xE8) { info.branch = BranchType::CallRel32; info.disp_offset = i; return info; }
    if (op == 0xE9) { info.branch = BranchType::JmpRel32;  info.disp_offset = i; return info; }
    if (op == 0xEB) { info.branch = BranchType::JmpRel8;   info.disp_offset = i; return info; }
    if (op >= 0x70 && op <= 0x7F) {
        info.branch = BranchType::JccRel8; info.cc = op & 0x0F;
        info.disp_offset = i; return info;
    }

    if (op == 0x0F && i < len) {
        std::uint8_t op2 = code[i++];
        if (op2 >= 0x80 && op2 <= 0x8F) {
            info.branch = BranchType::JccRel32; info.cc = op2 & 0x0F;
            info.disp_offset = i; return info;
        }
        if (i < len && (code[i] >> 6) == 0 && (code[i] & 7) == 5) {
            info.rip_modrm = true; info.disp_offset = i + 1;
        }
        return info;
    }

    if (opcode_has_modrm(op) && i < len) {
        if ((code[i] >> 6) == 0 && (code[i] & 7) == 5) {
            info.rip_modrm = true; info.disp_offset = i + 1;
        }
    }
    return info;
}

// relocate one instruction, returns bytes written (or 0 on overflow)
std::size_t relocate_one(const std::uint8_t* src, std::size_t src_len,
                          std::uintptr_t src_addr,
                          std::uint8_t* dst, std::uintptr_t dst_addr) {
    InsnInfo info = analyze_insn(src, src_len);
    auto src_end = static_cast<std::intptr_t>(src_addr + src_len);

    switch (info.branch) {
    case BranchType::JmpRel8: {
        auto disp8 = static_cast<std::int8_t>(src[info.disp_offset]);
        auto target = src_end + disp8;
        auto new_rel = target - static_cast<std::intptr_t>(dst_addr + 5);
        if (new_rel > kRel32Max || new_rel < -kRel32Max) return 0;
        dst[0] = 0xE9;
        auto r = static_cast<std::int32_t>(new_rel);
        std::memcpy(dst + 1, &r, 4);
        return 5;
    }
    case BranchType::JccRel8: {
        auto disp8 = static_cast<std::int8_t>(src[info.disp_offset]);
        auto target = src_end + disp8;
        auto new_rel = target - static_cast<std::intptr_t>(dst_addr + 6);
        if (new_rel > kRel32Max || new_rel < -kRel32Max) return 0;
        dst[0] = 0x0F; dst[1] = 0x80 | info.cc;
        auto r = static_cast<std::int32_t>(new_rel);
        std::memcpy(dst + 2, &r, 4);
        return 6;
    }
    case BranchType::CallRel32:
    case BranchType::JmpRel32:
    case BranchType::JccRel32: {
        std::int32_t old_rel;
        std::memcpy(&old_rel, src + info.disp_offset, 4);
        auto target = src_end + old_rel;
        auto new_rel = target - static_cast<std::intptr_t>(dst_addr + src_len);
        if (new_rel > kRel32Max || new_rel < -kRel32Max) return 0;
        std::memcpy(dst, src, src_len);
        auto r = static_cast<std::int32_t>(new_rel);
        std::memcpy(dst + info.disp_offset, &r, 4);
        return src_len;
    }
    default: break;
    }

    if (info.rip_modrm) {
        std::int32_t old_disp;
        std::memcpy(&old_disp, src + info.disp_offset, 4);
        auto delta = static_cast<std::int64_t>(src_addr) - static_cast<std::int64_t>(dst_addr);
        auto new_disp = static_cast<std::int64_t>(old_disp) + delta;
        if (new_disp > kRel32Max || new_disp < -kRel32Max) return 0;
        std::memcpy(dst, src, src_len);
        auto d = static_cast<std::int32_t>(new_disp);
        std::memcpy(dst + info.disp_offset, &d, 4);
        return src_len;
    }

    std::memcpy(dst, src, src_len);
    return src_len;
}

// ---- thread freezer ----

struct FrozenThreads {
    static constexpr std::size_t kMax = 4096;
    HANDLE handles[kMax];
    std::size_t count = 0;
};

void freeze_threads(FrozenThreads& ft) {
    ft.count = 0;
    DWORD pid = GetCurrentProcessId();
    DWORD tid = GetCurrentThreadId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid || te.th32ThreadID == tid) continue;
            if (ft.count >= FrozenThreads::kMax) break;
            HANDLE h = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
            if (!h) continue;
            if (SuspendThread(h) == static_cast<DWORD>(-1)) { CloseHandle(h); continue; }
            ft.handles[ft.count++] = h;
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
}

void thaw_threads(FrozenThreads& ft) {
    for (std::size_t i = 0; i < ft.count; i++) {
        ResumeThread(ft.handles[i]);
        CloseHandle(ft.handles[i]);
    }
    ft.count = 0;
}

} // anonymous namespace

// ---- public api ----

Status install(void* target, void* detour, Hook& out) {
    if (out.installed) return Status::AlreadyHooked;
    if (!target) return Status::NullTarget;
    if (!detour) return Status::NullDetour;
    if (target == detour) return Status::NullDetour;

    auto* src = static_cast<std::uint8_t*>(target);
    auto src_addr = reinterpret_cast<std::uintptr_t>(src);
    bool use_rel32 = within_rel32(src + kJmpRel32, detour);
    std::size_t min_stolen = use_rel32 ? kJmpRel32 : kJmpAbs;
    std::size_t stolen = 0;

    while (stolen < min_stolen) {
        auto n = lde_x64(src + stolen);
        if (n == 0 || n > 15) return Status::UnsupportedPrologue;
        stolen += n;
        if (stolen > 32) return Status::UnsupportedPrologue;
    }

    void* tramp_mem = alloc_near(target);
    if (!tramp_mem) return Status::AllocationFailed;
    auto* tramp = static_cast<std::uint8_t*>(tramp_mem);
    auto tramp_addr = reinterpret_cast<std::uintptr_t>(tramp);

    // relocate stolen instructions one by one
    std::size_t src_off = 0, dst_off = 0;
    while (src_off < stolen) {
        auto n = lde_x64(src + src_off);
        if (n == 0) return Status::UnsupportedPrologue;
        auto written = relocate_one(src + src_off, n,
                                     src_addr + src_off,
                                     tramp + dst_off,
                                     tramp_addr + dst_off);
        if (written == 0) return Status::RelocationFailed;
        src_off += n;
        dst_off += written;
        if (dst_off > kSlotSize - kJmpAbs) return Status::AllocationFailed;
    }

    // jump back to original code after stolen region
    auto* jump_back = src + stolen;
    if (within_rel32(tramp + dst_off + kJmpRel32, jump_back))
        emit_jmp_rel32(tramp + dst_off, tramp + dst_off, jump_back);
    else
        emit_jmp_abs(tramp + dst_off, jump_back);

    // save original bytes
    std::uint8_t original[32]{};
    std::memcpy(original, src, stolen);

    // build patch (jmp to detour + int3 padding)
    std::uint8_t patch[32];
    std::memset(patch, 0xCC, sizeof patch);
    if (use_rel32) emit_jmp_rel32(patch, src, detour);
    else           emit_jmp_abs(patch, detour);

    FrozenThreads ft;
    freeze_threads(ft);
    bool ok = patch_bytes(src, patch, stolen);
    thaw_threads(ft);
    if (!ok) return Status::ProtectFailed;

    out.target = target;
    out.detour = detour;
    out.trampoline = tramp_mem;
    out.trampoline_region = tramp_mem;
    out.stolen_bytes = stolen;
    out.trampoline_len = dst_off;
    std::memcpy(out.original_prologue, original, stolen);
    out.installed = true;
    out.enabled = true;
    return Status::Ok;
}

Status uninstall(Hook& hook) {
    if (!hook.installed) return Status::NotHooked;

    FrozenThreads ft;
    freeze_threads(ft);
    bool ok = patch_bytes(hook.target, hook.original_prologue, hook.stolen_bytes);
    thaw_threads(ft);
    if (!ok) return Status::ProtectFailed;

    if (hook.trampoline_region)
        std::memset(hook.trampoline_region, 0xCC, kSlotSize);

    hook.installed = false;
    hook.enabled = false;
    hook.trampoline = nullptr;
    hook.trampoline_region = nullptr;
    return Status::Ok;
}

Status enable(Hook& hook) {
    if (!hook.installed) return Status::NotHooked;
    if (hook.enabled) return Status::AlreadyEnabled;

    auto* src = static_cast<std::uint8_t*>(hook.target);
    bool use_rel32 = within_rel32(src + kJmpRel32, hook.detour);

    std::uint8_t patch[32];
    std::memset(patch, 0xCC, sizeof patch);
    if (use_rel32) emit_jmp_rel32(patch, src, hook.detour);
    else           emit_jmp_abs(patch, hook.detour);

    FrozenThreads ft;
    freeze_threads(ft);
    bool ok = patch_bytes(src, patch, hook.stolen_bytes);
    thaw_threads(ft);
    if (!ok) return Status::ProtectFailed;

    hook.enabled = true;
    return Status::Ok;
}

Status disable(Hook& hook) {
    if (!hook.installed) return Status::NotHooked;
    if (!hook.enabled) return Status::AlreadyDisabled;

    FrozenThreads ft;
    freeze_threads(ft);
    bool ok = patch_bytes(hook.target, hook.original_prologue, hook.stolen_bytes);
    thaw_threads(ft);
    if (!ok) return Status::ProtectFailed;

    hook.enabled = false;
    return Status::Ok;
}

const char* status_to_string(Status s) {
    switch (s) {
    case Status::Ok:                  return "Ok";
    case Status::AlreadyHooked:       return "AlreadyHooked";
    case Status::NotHooked:           return "NotHooked";
    case Status::AlreadyEnabled:      return "AlreadyEnabled";
    case Status::AlreadyDisabled:     return "AlreadyDisabled";
    case Status::UnsupportedPrologue: return "UnsupportedPrologue";
    case Status::RelocationFailed:    return "RelocationFailed";
    case Status::AllocationFailed:    return "AllocationFailed";
    case Status::ProtectFailed:       return "ProtectFailed";
    case Status::NullTarget:          return "NullTarget";
    case Status::NullDetour:          return "NullDetour";
    default:                          return "Unknown";
    }
}

}
