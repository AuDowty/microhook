#include <microhook/microhook.hpp>
#include <cstring>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>

namespace microhook {
namespace {

// ---- constants ----

constexpr std::size_t kJmpRel32 = 5;
#ifdef _WIN64
constexpr std::size_t kJmpAbs   = 14;   // FF 25 00000000 <addr64>
constexpr std::size_t kRelayOff = 96 - kJmpAbs; // relay stub at end of slot
#else
constexpr std::size_t kJmpAbs   = 6;    // 68 <addr32> C3 (push/ret)
#endif
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
#ifdef _WIN64
    buf[0] = 0xFF; buf[1] = 0x25;
    std::int32_t zero = 0;
    std::memcpy(buf + 2, &zero, 4);
    auto addr = reinterpret_cast<std::uint64_t>(to);
    std::memcpy(buf + 6, &addr, 8);
#else
    buf[0] = 0x68;
    auto addr = reinterpret_cast<std::uint32_t>(to);
    std::memcpy(buf + 1, &addr, 4);
    buf[5] = 0xC3;
#endif
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

// ---- slab allocator with free-list ----

struct Slab { std::uint8_t* base; std::size_t used; };
Slab g_slabs[64]{};
std::size_t g_slab_count = 0;

struct FreeSlot { FreeSlot* next; };
FreeSlot* g_free_list = nullptr;

void* alloc_trampoline(void* target) {
    // check free-list first
#ifdef _WIN64
    FreeSlot* prev = nullptr;
    for (auto* slot = g_free_list; slot; prev = slot, slot = slot->next) {
        if (!within_rel32(target, slot)) continue;
        if (prev) prev->next = slot->next;
        else g_free_list = slot->next;
        return slot;
    }
#else
    (void)target;
    if (g_free_list) {
        auto* slot = g_free_list;
        g_free_list = slot->next;
        return slot;
    }
#endif

    // check existing slabs
    for (std::size_t i = 0; i < g_slab_count; i++) {
        auto& s = g_slabs[i];
        if (s.used + kSlotSize > kPageSize) continue;
#ifdef _WIN64
        if (!within_rel32(target, s.base + s.used)) continue;
#endif
        void* p = s.base + s.used;
        s.used += kSlotSize;
        return p;
    }

    // allocate new page
#ifdef _WIN64
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
#else
    void* p = VirtualAlloc(nullptr, kPageSize,
                           MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (p) {
        if (g_slab_count < 64)
            g_slabs[g_slab_count++] = { static_cast<std::uint8_t*>(p), kSlotSize };
        return p;
    }
#endif
    return nullptr;
}

void free_trampoline(void* slot) {
    std::memset(slot, 0xCC, kSlotSize);
    auto* fs = static_cast<FreeSlot*>(slot);
    fs->next = g_free_list;
    g_free_list = fs;
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
    if (op == 0x62 || op == 0x63) return true;
    if (op == 0x69 || op == 0x6B) return true;
    if (op >= 0x80 && op <= 0x8F) return true;
    if (op == 0xC0 || op == 0xC1) return true;
#ifndef _WIN64
    if (op == 0xC4 || op == 0xC5) return true; // LES/LDS (x86 only; x64 = VEX)
#endif
    if (op == 0xC6 || op == 0xC7) return true;
    if (op >= 0xD0 && op <= 0xD3) return true;
    if (op >= 0xD8 && op <= 0xDF) return true;
    if (op == 0xF6 || op == 0xF7) return true;
    if (op == 0xFE || op == 0xFF) return true;
    return false;
}

// ---- VEX helpers ----

bool vex_has_imm8(std::uint8_t op, std::uint8_t map) {
    if (map == 3) return true;   // 0F 3A: all have imm8
    if (map != 1) return false;  // 0F 38 etc: no imm8
    // map 1 (0F): specific opcodes
    return op == 0xC2 || op == 0xC4 || op == 0xC5 || op == 0xC6 ||
           op == 0x70 || op == 0x71 || op == 0x72 || op == 0x73 ||
           op == 0xA4 || op == 0xAC;
}

// ---- length disassembly engine (x86 + x64) ----

std::size_t lde(const std::uint8_t* code) {
    std::size_t i = 0;
    bool has_66 = false, has_67 = false;
#ifdef _WIN64
    bool has_rexw = false;
#endif

    while (true) {
        std::uint8_t b = code[i];
        if (b == 0xF0 || b == 0xF2 || b == 0xF3 ||
            b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 ||
            b == 0x64 || b == 0x65) { i++; continue; }
        if (b == 0x66) { has_66 = true; i++; continue; }
        if (b == 0x67) { has_67 = true; i++; continue; }
        break;
    }

#ifdef _WIN64
    if ((code[i] & 0xF0) == 0x40) { has_rexw = (code[i] & 8) != 0; i++; }
#endif

    std::uint8_t op = code[i++];

#ifndef _WIN64
    if (op >= 0x40 && op <= 0x4F) return i; // x86: INC/DEC reg
#endif

    // ---- VEX prefix ----
#ifdef _WIN64
    if (op == 0xC5) {
        i++;
        std::uint8_t vex_op = code[i++];
        std::size_t n = i + modrm_extra(code + i);
        if (vex_has_imm8(vex_op, 1)) n++;
        return n;
    }
    if (op == 0xC4) {
        std::uint8_t map = code[i] & 0x1F;
        i += 2;
        std::uint8_t vex_op = code[i++];
        std::size_t n = i + modrm_extra(code + i);
        if (vex_has_imm8(vex_op, map)) n++;
        return n;
    }
#else
    // x86: VEX if second byte has mod=11 (invalid for LES/LDS)
    if (op == 0xC5 && (code[i] & 0xC0) == 0xC0) {
        i++;
        std::uint8_t vex_op = code[i++];
        std::size_t n = i + modrm_extra(code + i);
        if (vex_has_imm8(vex_op, 1)) n++;
        return n;
    }
    if (op == 0xC4 && (code[i] & 0xC0) == 0xC0) {
        std::uint8_t map = code[i] & 0x1F;
        i += 2;
        std::uint8_t vex_op = code[i++];
        std::size_t n = i + modrm_extra(code + i);
        if (vex_has_imm8(vex_op, map)) n++;
        return n;
    }
#endif

    // ---- two-byte escape ----
    if (op == 0x0F) {
        std::uint8_t op2 = code[i++];

        // three-byte escape maps
        if (op2 == 0x38) {
            i++;
            return i + modrm_extra(code + i);
        }
        if (op2 == 0x3A) {
            i++;
            return i + modrm_extra(code + i) + 1;
        }

        if (op2 >= 0x80 && op2 <= 0x8F) return i + 4;
        if (op2 >= 0xC8 && op2 <= 0xCF) return i;
        if (op2 == 0x05 || op2 == 0x06 || op2 == 0x07 ||
            op2 == 0x08 || op2 == 0x09 || op2 == 0x0B ||
            op2 == 0x31 || op2 == 0x34 || op2 == 0x35 ||
            op2 == 0xA2) return i;
        if (op2 == 0x70 || op2 == 0x71 || op2 == 0x72 || op2 == 0x73 ||
            op2 == 0xC2 || op2 == 0xC4 || op2 == 0xC5 || op2 == 0xC6 ||
            op2 == 0xA4 || op2 == 0xAC)
            return i + modrm_extra(code + i) + 1;
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

    if (op == 0xE8 || op == 0xE9) return i + 4;
    if (op == 0xEB) return i + 1;
    if (op >= 0x70 && op <= 0x7F) return i + 1;
    if (op == 0xE0 || op == 0xE1 || op == 0xE2 || op == 0xE3) return i + 1;

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

    if (op == 0x68) return i + (has_66 ? 2 : 4);
    if (op == 0x6A) return i + 1;
    if (op == 0xC2 || op == 0xCA) return i + 2;
    if (op == 0xC8) return i + 3;

#ifdef _WIN64
    if (op >= 0xA0 && op <= 0xA3) return i + (has_67 ? 4 : 8);
#else
    if (op >= 0xA0 && op <= 0xA3) return i + (has_67 ? 2 : 4);
#endif

    if (op == 0xA8) return i + 1;
    if (op == 0xA9) return i + (has_66 ? 2 : 4);

    if (op <= 0x3D && (op & 7) == 4) return i + 1;
    if (op <= 0x3D && (op & 7) == 5) return i + (has_66 ? 2 : 4);

    if (op >= 0xB0 && op <= 0xB7) return i + 1;
    if (op >= 0xB8 && op <= 0xBF) {
#ifdef _WIN64
        if (has_rexw) return i + 8;
#endif
        return i + (has_66 ? 2 : 4);
    }

    if (op == 0xC6) return i + modrm_extra(code + i) + 1;
    if (op == 0xC7) return i + modrm_extra(code + i) + (has_66 ? 2 : 4);
    if (op == 0x80 || op == 0x82 || op == 0x83) return i + modrm_extra(code + i) + 1;
    if (op == 0x81) return i + modrm_extra(code + i) + (has_66 ? 2 : 4);
    if (op == 0x69) return i + modrm_extra(code + i) + (has_66 ? 2 : 4);
    if (op == 0x6B) return i + modrm_extra(code + i) + 1;
    if (op == 0xC0 || op == 0xC1) return i + modrm_extra(code + i) + 1;

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
#ifdef _WIN64
    if (i < len && (code[i] & 0xF0) == 0x40) i++;
#endif
    if (i >= len) return info;

    std::uint8_t op = code[i++];

    // ---- VEX: skip to ModRM for RIP-relative check ----
#ifdef _WIN64
    if (op == 0xC5) {
        i += 2; // payload + opcode
        if (i < len && (code[i] >> 6) == 0 && (code[i] & 7) == 5) {
            info.rip_modrm = true; info.disp_offset = i + 1;
        }
        return info;
    }
    if (op == 0xC4) {
        i += 3; // 2 payloads + opcode
        if (i < len && (code[i] >> 6) == 0 && (code[i] & 7) == 5) {
            info.rip_modrm = true; info.disp_offset = i + 1;
        }
        return info;
    }
#else
    if ((op == 0xC5 || op == 0xC4) && i < len && (code[i] & 0xC0) == 0xC0) {
        return info; // VEX on x86: no RIP-relative
    }
#endif

    if (op == 0xE8) { info.branch = BranchType::CallRel32; info.disp_offset = i; return info; }
    if (op == 0xE9) { info.branch = BranchType::JmpRel32;  info.disp_offset = i; return info; }
    if (op == 0xEB) { info.branch = BranchType::JmpRel8;   info.disp_offset = i; return info; }
    if (op >= 0x70 && op <= 0x7F) {
        info.branch = BranchType::JccRel8; info.cc = op & 0x0F;
        info.disp_offset = i; return info;
    }

    if (op == 0x0F && i < len) {
        std::uint8_t op2 = code[i++];

        // three-byte escape
        if (op2 == 0x38 || op2 == 0x3A) {
            i++;
#ifdef _WIN64
            if (i < len && (code[i] >> 6) == 0 && (code[i] & 7) == 5) {
                info.rip_modrm = true; info.disp_offset = i + 1;
            }
#endif
            return info;
        }

        if (op2 >= 0x80 && op2 <= 0x8F) {
            info.branch = BranchType::JccRel32; info.cc = op2 & 0x0F;
            info.disp_offset = i; return info;
        }
#ifdef _WIN64
        if (i < len && (code[i] >> 6) == 0 && (code[i] & 7) == 5) {
            info.rip_modrm = true; info.disp_offset = i + 1;
        }
#endif
        return info;
    }

#ifdef _WIN64
    if (opcode_has_modrm(op) && i < len) {
        if ((code[i] >> 6) == 0 && (code[i] & 7) == 5) {
            info.rip_modrm = true; info.disp_offset = i + 1;
        }
    }
#endif
    return info;
}

std::size_t relocated_insn_size(const std::uint8_t* insn, std::size_t len) {
    InsnInfo info = analyze_insn(insn, len);
    if (info.branch == BranchType::JmpRel8) return 5;
    if (info.branch == BranchType::JccRel8) return 6;
    return len;
}

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

#ifdef _WIN64
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
#endif

    std::memcpy(dst, src, src_len);
    return src_len;
}

// ---- thread IP mapping ----

struct IpEntry { std::uintptr_t old_ip, new_ip; };
constexpr std::size_t kMaxIpEntries = 33;

std::size_t build_ip_map(const Hook& hook, IpEntry* map) {
    auto target_addr = reinterpret_cast<std::uintptr_t>(hook.target);
    auto tramp_addr  = reinterpret_cast<std::uintptr_t>(hook.trampoline);
    std::size_t count = 0, src_off = 0, dst_off = 0;

    while (src_off < hook.stolen_bytes && count < kMaxIpEntries - 1) {
        map[count++] = { target_addr + src_off, tramp_addr + dst_off };
        auto n = lde(hook.original_prologue + src_off);
        if (n == 0) break;
        dst_off += relocated_insn_size(hook.original_prologue + src_off, n);
        src_off += n;
    }
    map[count++] = { target_addr + src_off, target_addr + src_off };
    return count;
}

// ---- thread freezer with IP adjustment ----

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
            HANDLE h = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
                                  THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
            if (!h) continue;
            if (SuspendThread(h) == static_cast<DWORD>(-1)) { CloseHandle(h); continue; }
            ft.handles[ft.count++] = h;
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
}

void adjust_ips(const FrozenThreads& ft, const IpEntry* map, std::size_t map_count,
                bool forward) {
    for (std::size_t i = 0; i < ft.count; i++) {
        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_CONTROL;
        if (!GetThreadContext(ft.handles[i], &ctx)) continue;

#ifdef _WIN64
        auto ip = static_cast<std::uintptr_t>(ctx.Rip);
#else
        auto ip = static_cast<std::uintptr_t>(ctx.Eip);
#endif

        for (std::size_t j = 0; j + 1 < map_count; j++) {
            std::uintptr_t lo = forward ? map[j].old_ip : map[j].new_ip;
            std::uintptr_t hi = forward ? map[j + 1].old_ip : map[j + 1].new_ip;
            if (ip >= lo && ip < hi) {
#ifdef _WIN64
                ctx.Rip = forward ? map[j].new_ip : map[j].old_ip;
#else
                ctx.Eip = static_cast<DWORD>(forward ? map[j].new_ip : map[j].old_ip);
#endif
                SetThreadContext(ft.handles[i], &ctx);
                break;
            }
        }
    }
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

#ifdef _WIN64
    std::size_t min_stolen = kJmpRel32; // relay handles far detours
#else
    bool use_rel32 = within_rel32(src + kJmpRel32, detour);
    std::size_t min_stolen = use_rel32 ? kJmpRel32 : kJmpAbs;
#endif

    std::size_t stolen = 0;
    while (stolen < min_stolen) {
        auto n = lde(src + stolen);
        if (n == 0 || n > 15) return Status::UnsupportedPrologue;
        stolen += n;
        if (stolen > 32) return Status::UnsupportedPrologue;
    }

    void* tramp_mem = alloc_trampoline(target);
    if (!tramp_mem) return Status::AllocationFailed;
    auto* tramp = static_cast<std::uint8_t*>(tramp_mem);
    auto tramp_addr = reinterpret_cast<std::uintptr_t>(tramp);

    std::size_t src_off = 0, dst_off = 0;
    while (src_off < stolen) {
        auto n = lde(src + src_off);
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

    auto* jump_back = src + stolen;
    if (within_rel32(tramp + dst_off + kJmpRel32, jump_back))
        emit_jmp_rel32(tramp + dst_off, tramp + dst_off, jump_back);
    else
        emit_jmp_abs(tramp + dst_off, jump_back);

    std::uint8_t original[32]{};
    std::memcpy(original, src, stolen);

    std::uint8_t patch[32];
    std::memset(patch, 0xCC, sizeof patch);

#ifdef _WIN64
    if (!within_rel32(src + kJmpRel32, detour)) {
        emit_jmp_abs(tramp + kRelayOff, detour);
        emit_jmp_rel32(patch, src, tramp + kRelayOff);
    } else {
        emit_jmp_rel32(patch, src, detour);
    }
#else
    if (use_rel32) emit_jmp_rel32(patch, src, detour);
    else           emit_jmp_abs(patch, detour);
#endif

    out.target = target;
    out.detour = detour;
    out.trampoline = tramp_mem;
    out.trampoline_region = tramp_mem;
    out.stolen_bytes = stolen;
    out.trampoline_len = dst_off;
    std::memcpy(out.original_prologue, original, stolen);

    IpEntry map[kMaxIpEntries];
    auto map_count = build_ip_map(out, map);

    FrozenThreads ft;
    freeze_threads(ft);
    adjust_ips(ft, map, map_count, true);
    bool ok = patch_bytes(src, patch, stolen);
    thaw_threads(ft);

    if (!ok) return Status::ProtectFailed;

    out.installed = true;
    out.enabled = true;
    return Status::Ok;
}

Status uninstall(Hook& hook) {
    if (!hook.installed) return Status::NotHooked;

    IpEntry map[kMaxIpEntries];
    auto map_count = build_ip_map(hook, map);

    FrozenThreads ft;
    freeze_threads(ft);
    adjust_ips(ft, map, map_count, false);
    bool ok = patch_bytes(hook.target, hook.original_prologue, hook.stolen_bytes);
    thaw_threads(ft);

    if (!ok) return Status::ProtectFailed;

    if (hook.trampoline_region)
        free_trampoline(hook.trampoline_region);

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

    std::uint8_t patch[32];
    std::memset(patch, 0xCC, sizeof patch);

#ifdef _WIN64
    if (!within_rel32(src + kJmpRel32, hook.detour)) {
        auto* relay = static_cast<std::uint8_t*>(hook.trampoline) + kRelayOff;
        emit_jmp_abs(relay, hook.detour);
        emit_jmp_rel32(patch, src, relay);
    } else {
        emit_jmp_rel32(patch, src, hook.detour);
    }
#else
    bool use_rel32 = within_rel32(src + kJmpRel32, hook.detour);
    if (use_rel32) emit_jmp_rel32(patch, src, hook.detour);
    else           emit_jmp_abs(patch, hook.detour);
#endif

    IpEntry map[kMaxIpEntries];
    auto map_count = build_ip_map(hook, map);

    FrozenThreads ft;
    freeze_threads(ft);
    adjust_ips(ft, map, map_count, true);
    bool ok = patch_bytes(src, patch, hook.stolen_bytes);
    thaw_threads(ft);

    if (!ok) return Status::ProtectFailed;

    hook.enabled = true;
    return Status::Ok;
}

Status disable(Hook& hook) {
    if (!hook.installed) return Status::NotHooked;
    if (!hook.enabled) return Status::AlreadyDisabled;

    IpEntry map[kMaxIpEntries];
    auto map_count = build_ip_map(hook, map);

    FrozenThreads ft;
    freeze_threads(ft);
    adjust_ips(ft, map, map_count, false);
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
