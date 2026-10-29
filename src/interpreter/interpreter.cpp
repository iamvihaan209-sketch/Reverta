#include "interpreter/interpreter.h"
#include "jit/jit_compiler.h"
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <cmath>
#include <cerrno>
#include <limits>
#include <sys/mman.h>
#include <unistd.h>

namespace {
uint64_t width_mask(unsigned width) {
    return width >= 64 ? ~0ULL : ((1ULL << width) - 1);
}

// Rotate right within a width-bit value; v must already be masked to width.
uint64_t rotate_right(uint64_t v, unsigned amount, unsigned width) {
    amount %= width;
    if (amount == 0) return v;
    return ((v >> amount) | (v << (width - amount))) & width_mask(width);
}

uint64_t sign_extend(uint64_t v, unsigned bits) {
    const unsigned shift = 64 - bits;
    return static_cast<uint64_t>(static_cast<int64_t>(v << shift) >> shift);
}

// Shifted-register operand: LSL, LSR, ASR or ROR by amount, within width bits.
uint64_t shift_operand(uint64_t v, unsigned kind, unsigned amount, unsigned width) {
    const uint64_t mask = width_mask(width);
    v &= mask;
    switch (kind) {
    case 0:  // LSL
        return amount >= width ? 0 : ((v << amount) & mask);
    case 1:  // LSR
        return amount >= width ? 0 : (v >> amount);
    case 2: { // ASR: shifting past the width leaves only sign bits
        const unsigned a = amount >= width ? width - 1 : amount;
        return static_cast<uint64_t>(static_cast<int64_t>(sign_extend(v, width)) >> a) & mask;
    }
    default: // ROR
        return rotate_right(v, amount, width);
    }
}

// Extended-register operand: the extend option, then a left shift of 0..4.
uint64_t extend_operand(uint64_t v, unsigned option, unsigned shift, unsigned width) {
    v &= width_mask(width);
    uint64_t e = v;
    switch (option) {
    case 0: e = v & 0xFF; break;                         // UXTB
    case 1: e = v & 0xFFFF; break;                       // UXTH
    case 2: e = v & 0xFFFFFFFFULL; break;                // UXTW
    case 3: e = v; break;                                // UXTX
    case 4: e = sign_extend(v & 0xFF, 8); break;         // SXTB
    case 5: e = sign_extend(v & 0xFFFF, 16); break;      // SXTH
    case 6: e = sign_extend(v & 0xFFFFFFFFULL, 32); break; // SXTW
    default: e = v; break;                               // SXTX
    }
    return e << shift;
}

// Byte and bit permutations within a width-bit value.
uint64_t reverse_bits(uint64_t v, unsigned width) {
    uint64_t out = 0;
    for (unsigned i = 0; i < width; ++i) {
        out = (out << 1) | ((v >> i) & 1);
    }
    return out;
}

uint64_t reverse_bytes16(uint64_t v, unsigned width) {
    uint64_t out = 0;
    for (unsigned i = 0; i < width; i += 16) {
        const uint64_t half = (v >> i) & 0xFFFF;
        out |= ((half & 0xFF) << 8 | (half >> 8)) << i;
    }
    return out;
}
} // namespace

Interpreter::Interpreter(const LoadedBinary& binary)
    : binary_(binary)
{
    state_.pc = binary.entry_point;
    state_.sp = binary.stack_top;
    // Align SP to 16 bytes (AArch64 ABI requirement)
    state_.sp &= ~0xFULL;
}

Interpreter::~Interpreter() {
    for (const auto& mapping : dynamic_mappings_)
        if (mapping.host && mapping.size) ::munmap(mapping.host, mapping.size);
}

bool Interpreter::guest_range_overlaps(uint64_t address, size_t size) const {
    if (size == 0 || address > UINT64_MAX - size) return true;
    const uint64_t end = address + size;
    auto overlaps = [&](uint64_t base, uint64_t extent) {
        if (extent == 0 || base > UINT64_MAX - extent) return false;
        return address < base + extent && base < end;
    };
    for (const auto& seg : binary_.segments) {
        const uint64_t base = seg.mapped_vmaddr ? seg.mapped_vmaddr : seg.vmaddr;
        if (overlaps(base, seg.vmsize)) return true;
    }
    if (overlaps(binary_.stack_base, binary_.stack_size)) return true;
    for (const auto& mapping : dynamic_mappings_)
        if (overlaps(mapping.guest_base, mapping.size)) return true;
    return false;
}

int64_t Interpreter::mmap_guest(uint64_t requested_address, size_t length, int prot,
                                int flags, int fd, int64_t offset) {
    if (length == 0 || offset < 0) return -EINVAL;
    const long page_result = ::sysconf(_SC_PAGESIZE);
    const size_t page_size = page_result > 0 ? static_cast<size_t>(page_result) : 4096;
    if (length > std::numeric_limits<size_t>::max() - (page_size - 1))
        return -ENOMEM;
    const size_t map_size = (length + page_size - 1) & ~(page_size - 1);
    if ((flags & MAP_FIXED) && (requested_address == 0 || requested_address % page_size != 0))
        return -EINVAL;
    if (offset % static_cast<int64_t>(page_size) != 0) return -EINVAL;

    uint64_t guest_address = 0;
    if (requested_address != 0 && requested_address % page_size == 0 &&
        map_size <= static_cast<size_t>(INT64_MAX) &&
        requested_address <= static_cast<uint64_t>(INT64_MAX) - map_size &&
        !guest_range_overlaps(requested_address, map_size)) {
        guest_address = requested_address;
    } else if (flags & MAP_FIXED) {
        return -EINVAL;
    } else {
        guest_address = (next_guest_mapping_ + page_size - 1) &
                        ~(static_cast<uint64_t>(page_size) - 1);
        if (map_size > UINT64_MAX - page_size) return -ENOMEM;
        const uint64_t advance = static_cast<uint64_t>(map_size) + page_size;
        if (advance > static_cast<uint64_t>(INT64_MAX)) return -ENOMEM;
        while (guest_range_overlaps(guest_address, map_size)) {
            if (guest_address > static_cast<uint64_t>(INT64_MAX) - advance) return -ENOMEM;
            guest_address += advance;
        }
        if (guest_address > static_cast<uint64_t>(INT64_MAX) - advance) return -ENOMEM;
        next_guest_mapping_ = guest_address + advance;
    }

    // Guest addresses are virtual IDs; never pass them to host mmap as a fixed
    // address. Keep the host mapping readable/writable and track guest prot
    // separately so interpreter accesses cannot crash the host on guest faults.
    void* host = ::mmap(nullptr, map_size, PROT_READ | PROT_WRITE,
                        flags & ~MAP_FIXED, fd, static_cast<off_t>(offset));
    if (host == MAP_FAILED) return -errno;
    dynamic_mappings_.push_back({guest_address, map_size,
                                 static_cast<uint8_t*>(host), prot});
    return static_cast<int64_t>(guest_address);
}

int64_t Interpreter::munmap_guest(uint64_t address, size_t length) {
    if (length == 0) return -EINVAL;
    const long page_result = ::sysconf(_SC_PAGESIZE);
    const size_t page_size = page_result > 0 ? static_cast<size_t>(page_result) : 4096;
    if (address % page_size != 0 ||
        length > std::numeric_limits<size_t>::max() - (page_size - 1))
        return -EINVAL;
    const size_t map_size = (length + page_size - 1) & ~(page_size - 1);
    if (address > UINT64_MAX - map_size) return -EINVAL;

    for (size_t i = 0; i < dynamic_mappings_.size(); ++i) {
        auto& mapping = dynamic_mappings_[i];
        if (address < mapping.guest_base) continue;
        const uint64_t offset64 = address - mapping.guest_base;
        if (offset64 > mapping.size || map_size > mapping.size - offset64) continue;
        const size_t offset = static_cast<size_t>(offset64);
        uint8_t* host_start = mapping.host + offset;
        if (::munmap(host_start, map_size) != 0) return -errno;

        const size_t old_size = mapping.size;
        const uint64_t old_base = mapping.guest_base;
        uint8_t* const old_host = mapping.host;
        const int old_prot = mapping.prot;
        if (offset == 0 && map_size == old_size) {
            dynamic_mappings_.erase(dynamic_mappings_.begin() + static_cast<std::ptrdiff_t>(i));
        } else if (offset == 0) {
            mapping.guest_base += map_size;
            mapping.host += map_size;
            mapping.size -= map_size;
        } else if (offset + map_size == old_size) {
            mapping.size = offset;
        } else {
            mapping.size = offset;
            dynamic_mappings_.push_back({old_base + offset + map_size,
                                         old_size - offset - map_size,
                                         old_host + offset + map_size, old_prot});
        }
        return 0;
    }
    return -EINVAL;
}

uint8_t* Interpreter::guest_to_host(uint64_t vaddr, size_t access_size, GuestAccess access) const {
    if (access_size == 0) return nullptr;
    for (const auto& seg : binary_.segments) {
        if (!seg.mapped) continue;
        const uint64_t guest_base = seg.mapped_vmaddr ? seg.mapped_vmaddr : seg.vmaddr;
        if (vaddr < guest_base) continue;
        const uint64_t offset = vaddr - guest_base;
        if (offset < seg.vmsize && access_size <= seg.vmsize - offset) {
            const int prot = static_cast<int>(seg.initprot);
            const bool permitted =
                (access == GuestAccess::Read && (prot & PROT_READ)) ||
                (access == GuestAccess::Write && (prot & PROT_WRITE)) ||
                (access == GuestAccess::Execute && (prot & PROT_EXEC));
            if (permitted) return seg.mapped + offset;
        }
    }
    if (access != GuestAccess::Execute && binary_.stack_size && vaddr >= binary_.stack_base) {
        const uint64_t offset = vaddr - binary_.stack_base;
        if (offset < binary_.stack_size && access_size <= binary_.stack_size - offset)
            return reinterpret_cast<uint8_t*>(vaddr);
    }
    for (const auto& mapping : dynamic_mappings_) {
        if (vaddr < mapping.guest_base) continue;
        const uint64_t offset = vaddr - mapping.guest_base;
        if (offset < mapping.size && access_size <= mapping.size - offset) {
            const bool permitted =
                (access == GuestAccess::Read && (mapping.prot & PROT_READ)) ||
                (access == GuestAccess::Write && (mapping.prot & PROT_WRITE)) ||
                (access == GuestAccess::Execute && (mapping.prot & PROT_EXEC));
            if (permitted) return mapping.host + offset;
        }
    }
    return nullptr;
}

RunResult Interpreter::run() {
    running_ = true;
    faulted_ = false;
    JitCompiler jit(binary_);

    while (running_) {
        if (!guest_to_host(state_.pc, sizeof(uint32_t), GuestAccess::Execute)) {
            if (pc_hook_ && pc_hook_(state_)) continue;
            std::fprintf(stderr, "[reverta] FAULT: PC 0x%llx is not executable\n",
                         (unsigned long long)state_.pc);
            return RunResult::FAULT;
        }
        // Phase 2 JIT handles safe straight-line integer blocks. Anything it
        // cannot compile falls through to the existing interpreter.
        if (jit.run(state_))
            continue;

        uint8_t* host_pc = guest_to_host(state_.pc, sizeof(uint32_t), GuestAccess::Execute);
        if (!host_pc) {
            std::fprintf(stderr, "[reverta] FAULT: PC 0x%llx unmapped\n",
                         (unsigned long long)state_.pc);
            return RunResult::FAULT;
        }

        Arm64Insn insn = decoder_.decode(host_pc, state_.pc);

        if (insn.op == Arm64Op::UNKNOWN) {
            std::fprintf(stderr,
                "[reverta] UNSUPPORTED insn 0x%08x at PC 0x%llx\n",
                insn.raw, (unsigned long long)state_.pc);
            return RunResult::UNSUPPORTED;
        }

        if (insn.op == Arm64Op::SVC) {
            state_.pc += 4;
            if (syscall_handler_) {
                if (!syscall_handler_(state_)) {
                    running_ = false;
                    return RunResult::OK;
                }
            }
            continue;
        }

        uint64_t old_pc = state_.pc;
        execute(insn);
        if (faulted_) return RunResult::FAULT;

        // If execute didn't change PC (non-branch), advance it
        if (state_.pc == old_pc) {
            state_.pc += 4;
        }
    }
    return RunResult::OK;
}

bool Interpreter::step() {
    if (faulted_) return false;
    uint8_t* host_pc = guest_to_host(state_.pc, sizeof(uint32_t), GuestAccess::Execute);
    if (!host_pc) return pc_hook_ && pc_hook_(state_);
    Arm64Insn insn = decoder_.decode(host_pc, state_.pc);
    uint64_t old_pc = state_.pc;
    execute(insn);
    if (faulted_) return false;
    if (state_.pc == old_pc) state_.pc += 4;
    return true;
}

// ── Condition evaluation ──────────────────────────────────────────────────────
bool Interpreter::eval_cond(Arm64Cond cond) const {
    bool n = state_.n, z = state_.z, c = state_.c, v = state_.v;
    switch (cond) {
    case Arm64Cond::EQ: return z;
    case Arm64Cond::NE: return !z;
    case Arm64Cond::CS: return c;
    case Arm64Cond::CC: return !c;
    case Arm64Cond::MI: return n;
    case Arm64Cond::PL: return !n;
    case Arm64Cond::VS: return v;
    case Arm64Cond::VC: return !v;
    case Arm64Cond::HI: return c && !z;
    case Arm64Cond::LS: return !c || z;
    case Arm64Cond::GE: return n == v;
    case Arm64Cond::LT: return n != v;
    case Arm64Cond::GT: return !z && (n == v);
    case Arm64Cond::LE: return z || (n != v);
    case Arm64Cond::AL: return true;
    case Arm64Cond::NV: return true;   // NV behaves as AL in every conditional instruction
    }
    return false;
}

void Interpreter::update_flags_add(uint64_t a, uint64_t b, uint64_t result) {
    state_.n = (result >> 63) & 1;
    state_.z = result == 0;
    // Carry: unsigned overflow
    state_.c = (result < a);
    // Overflow: signed overflow
    state_.v = (~(a ^ b) & (a ^ result)) >> 63;
}

void Interpreter::update_flags_sub(uint64_t a, uint64_t b, uint64_t result) {
    state_.n = (result >> 63) & 1;
    state_.z = result == 0;
    state_.c = (a >= b); // borrow
    state_.v = ((a ^ b) & (a ^ result)) >> 63;
}

// ── Main dispatch ─────────────────────────────────────────────────────────────
void Interpreter::execute(const Arm64Insn& insn) {
    switch (insn.op) {
    // Branches
    case Arm64Op::B:
    case Arm64Op::BL:
    case Arm64Op::BLR:
    case Arm64Op::BR:
    case Arm64Op::RET:
    case Arm64Op::B_COND:
    case Arm64Op::CBZ:
    case Arm64Op::CBNZ:
    case Arm64Op::TBZ:
    case Arm64Op::TBNZ:
        execute_branch(insn);
        break;

    // Loads / stores
    case Arm64Op::LDR_IMM: case Arm64Op::STR_IMM:
    case Arm64Op::LDRSB: case Arm64Op::LDRSH: case Arm64Op::LDRSW:
    case Arm64Op::LDP: case Arm64Op::STP: case Arm64Op::LDPSW:
    case Arm64Op::LDEX: case Arm64Op::STEX: case Arm64Op::LDEXP: case Arm64Op::STEXP:
    case Arm64Op::CAS: case Arm64Op::SWP:
    case Arm64Op::LDADD: case Arm64Op::LDCLR: case Arm64Op::LDEOR: case Arm64Op::LDSET:
    case Arm64Op::LDSMAX: case Arm64Op::LDSMIN: case Arm64Op::LDUMAX: case Arm64Op::LDUMIN:
        execute_load_store(insn);
        break;

    // Scalar floating-point operations use the SIMD/FP register bank.
    case Arm64Op::FADD: case Arm64Op::FSUB:
    case Arm64Op::FMUL: case Arm64Op::FDIV: case Arm64Op::FABS: case Arm64Op::FNEG: case Arm64Op::FCVT_SD: case Arm64Op::FCVT_DS:
    case Arm64Op::FCMP: case Arm64Op::FCMPE: case Arm64Op::FCSEL: case Arm64Op::FMOV: case Arm64Op::FMOV_IMM:
    case Arm64Op::FMOV_TO_GPR: case Arm64Op::FMOV_FROM_GPR:
    case Arm64Op::FSQRT: case Arm64Op::FMAX: case Arm64Op::FMIN:
    case Arm64Op::FCMP_ZERO: case Arm64Op::FCMPE_ZERO:
    case Arm64Op::SCVTF: case Arm64Op::UCVTF:
    case Arm64Op::FCVTZS: case Arm64Op::FCVTZU:
    case Arm64Op::FMADD: case Arm64Op::FMSUB: case Arm64Op::FNMADD: case Arm64Op::FNMSUB:
        execute_fp(insn);
        break;

    // Data processing
    default:
        execute_data_proc(insn);
        break;
    }
}

// ── Branch execution ──────────────────────────────────────────────────────────
void Interpreter::execute_branch(const Arm64Insn& insn) {
    uint64_t next = insn.pc + 4;
    switch (insn.op) {
    case Arm64Op::B:
        state_.pc = insn.pc + insn.imm;
        break;
    case Arm64Op::BL:
        state_.x[30] = next;
        state_.pc    = insn.pc + insn.imm;
        break;
    case Arm64Op::BLR:
        state_.x[30] = next;
        state_.pc    = state_.reg(insn.rn);
        break;
    case Arm64Op::BR:
        state_.pc = state_.reg(insn.rn);
        break;
    case Arm64Op::RET:
        state_.pc = state_.x[30]; // link register
        break;
    case Arm64Op::B_COND:
        state_.pc = eval_cond(insn.cond) ? insn.pc + insn.imm : next;
        break;
    case Arm64Op::CBZ:
        state_.pc = (state_.reg(insn.rd) == 0) ? insn.pc + insn.imm : next;
        break;
    case Arm64Op::CBNZ:
        state_.pc = (state_.reg(insn.rd) != 0) ? insn.pc + insn.imm : next;
        break;
    case Arm64Op::TBZ:
        state_.pc = ((state_.reg(insn.rd) >> insn.bit_pos) & 1) == 0
            ? insn.pc + insn.imm : next;
        break;
    case Arm64Op::TBNZ:
        state_.pc = ((state_.reg(insn.rd) >> insn.bit_pos) & 1) != 0
            ? insn.pc + insn.imm : next;
        break;
    default:
        break;
    }
}

// ── Load/store execution ──────────────────────────────────────────────────────
// ── Loads and stores ──────────────────────────────────────────────────────────
namespace {
// Element accesses are little-endian. These helpers copy host bytes directly,
// which is correct on the little-endian hosts Reverta runs on.
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "Reverta's memory helpers assume a little-endian host"
#endif
uint64_t read_le(const uint8_t* p, unsigned n) {
    uint64_t v = 0;
    std::memcpy(&v, p, n);   // n <= 8
    return v;
}
void write_le(uint8_t* p, unsigned n, uint64_t v) {
    std::memcpy(p, &v, n);   // n <= 8
}
uint64_t bytes_mask(unsigned n) {
    return n >= 8 ? ~0ULL : ((1ULL << (8 * n)) - 1);
}
} // namespace

void Interpreter::execute_load_store(const Arm64Insn& insn) {
    const unsigned n = insn.access_bytes;                    // bytes per element
    const Arm64Op op = insn.op;
    const bool pair = op == Arm64Op::LDP || op == Arm64Op::STP || op == Arm64Op::LDPSW
                   || op == Arm64Op::LDEXP || op == Arm64Op::STEXP;
    const unsigned total = pair ? 2 * n : n;
    const bool atomic = op == Arm64Op::CAS || op == Arm64Op::SWP || op == Arm64Op::LDADD
                     || op == Arm64Op::LDCLR || op == Arm64Op::LDEOR || op == Arm64Op::LDSET
                     || op == Arm64Op::LDSMAX || op == Arm64Op::LDSMIN
                     || op == Arm64Op::LDUMAX || op == Arm64Op::LDUMIN;
    const bool stores = op == Arm64Op::STR_IMM || op == Arm64Op::STP || op == Arm64Op::STEX
                     || op == Arm64Op::STEXP;
    const bool fp = insn.is_fp;

    // Base: the PC for literal loads, otherwise Rn, where register 31 is SP.
    const uint64_t base = insn.pc_literal ? insn.pc
                        : (insn.rn == 31 ? state_.sp : state_.reg(insn.rn));
    const uint64_t offset = insn.reg_offset
        ? extend_operand(state_.reg(insn.rm), insn.shift_kind, insn.shift_amount, 64)
        : static_cast<uint64_t>(insn.imm);
    // Post-index accesses at the base; pre-index and offset forms at base + offset.
    const uint64_t addr = insn.index_mode == 2 ? base : base + offset;

    const bool writes = stores || atomic;
    uint8_t* host = guest_to_host(addr, total, writes ? GuestAccess::Write : GuestAccess::Read);
    if (!host) {
        std::fprintf(stderr, "[reverta] FAULT: memory access 0x%llx (%u bytes) unmapped\n",
                     static_cast<unsigned long long>(addr), total);
        faulted_ = true;
        return;
    }

    const auto load_int = [&](uint8_t reg, const uint8_t* p, unsigned bytes, bool sign) {
        uint64_t v = read_le(p, bytes);
        if (sign) v = sign_extend(v, bytes * 8);
        state_.set_reg(reg, insn.is64 ? v : (v & 0xFFFFFFFFULL));
    };
    const auto store_int = [&](uint8_t reg, uint8_t* p, unsigned bytes) {
        write_le(p, bytes, state_.reg(reg));
    };
    const auto load_fp = [&](uint8_t reg, const uint8_t* p, unsigned bytes) {
        state_.q[reg][0] = 0;
        state_.q[reg][1] = 0;
        if (bytes == 16) std::memcpy(&state_.q[reg][0], p, 16);
        else state_.q[reg][0] = read_le(p, bytes);
    };
    const auto store_fp = [&](uint8_t reg, uint8_t* p, unsigned bytes) {
        if (bytes == 16) std::memcpy(p, &state_.q[reg][0], 16);
        else write_le(p, bytes, state_.q[reg][0]);
    };

    switch (op) {
    case Arm64Op::LDR_IMM:
    case Arm64Op::LDRSB: case Arm64Op::LDRSH: case Arm64Op::LDRSW:
        if (fp) load_fp(insn.rd, host, n);
        else load_int(insn.rd, host, n, op != Arm64Op::LDR_IMM);
        break;
    case Arm64Op::STR_IMM:
        if (fp) store_fp(insn.rd, host, n);
        else store_int(insn.rd, host, n);
        break;

    case Arm64Op::LDP: case Arm64Op::LDPSW:
        if (fp) {
            load_fp(insn.rd, host, n);
            load_fp(insn.ra, host + n, n);
        } else {
            const bool sign = op == Arm64Op::LDPSW;
            load_int(insn.rd, host, n, sign);
            load_int(insn.ra, host + n, n, sign);
        }
        break;
    case Arm64Op::STP:
        if (fp) {
            store_fp(insn.rd, host, n);
            store_fp(insn.ra, host + n, n);
        } else {
            store_int(insn.rd, host, n);
            store_int(insn.ra, host + n, n);
        }
        break;

    // Exclusive access: a single-core monitor. LDXR/LDXP arm it; STXR/STXP
    // succeed only when it still covers the same address and size, and always
    // clear it. The status register receives 0 on success and 1 on failure.
    case Arm64Op::LDEX: case Arm64Op::LDEXP:
        load_int(insn.rd, host, n, false);
        if (pair) load_int(insn.ra, host + n, n, false);
        excl_valid_ = true;
        excl_addr_ = addr;
        excl_bytes_ = total;
        break;
    case Arm64Op::STEX: case Arm64Op::STEXP: {
        const bool ok = excl_valid_ && excl_addr_ == addr && excl_bytes_ == total;
        if (ok) {
            store_int(insn.rd, host, n);
            if (pair) store_int(insn.ra, host + n, n);
        }
        excl_valid_ = false;
        state_.set_reg(insn.rm, ok ? 0 : 1);
        break;
    }

    // Compare and swap: if memory equals Rs, store Rt; Rs always receives the old value.
    case Arm64Op::CAS: {
        const uint64_t expected = state_.reg(insn.rm) & bytes_mask(n);
        const uint64_t old = read_le(host, n);
        if (old == expected) write_le(host, n, state_.reg(insn.rd));
        state_.set_reg(insn.rm, old);
        break;
    }
    // Swap: Rt receives the old value; memory receives Rs.
    case Arm64Op::SWP: {
        const uint64_t old = read_le(host, n);
        write_le(host, n, state_.reg(insn.rm));
        state_.set_reg(insn.rd, old);
        break;
    }
    // Load-and-operate atomics: Rt receives the old value; memory receives old OP Rs.
    case Arm64Op::LDADD: case Arm64Op::LDCLR: case Arm64Op::LDEOR: case Arm64Op::LDSET:
    case Arm64Op::LDSMAX: case Arm64Op::LDSMIN: case Arm64Op::LDUMAX: case Arm64Op::LDUMIN: {
        const uint64_t old = read_le(host, n);
        const uint64_t operand = state_.reg(insn.rm) & bytes_mask(n);
        const int64_t old_s = static_cast<int64_t>(sign_extend(old, n * 8));
        const int64_t operand_s = static_cast<int64_t>(sign_extend(operand, n * 8));
        uint64_t result = old;
        switch (op) {
        case Arm64Op::LDADD:  result = old + operand; break;
        case Arm64Op::LDCLR:  result = old & ~operand; break;
        case Arm64Op::LDEOR:  result = old ^ operand; break;
        case Arm64Op::LDSET:  result = old | operand; break;
        case Arm64Op::LDSMAX: result = old_s > operand_s ? old : operand; break;
        case Arm64Op::LDSMIN: result = old_s < operand_s ? old : operand; break;
        case Arm64Op::LDUMAX: result = old > operand ? old : operand; break;
        default:              result = old < operand ? old : operand; break;   // LDUMIN
        }
        write_le(host, n, result);
        state_.set_reg(insn.rd, old);
        break;
    }

    default:
        std::fprintf(stderr, "[reverta] unhandled memory op at 0x%llx\n",
                     static_cast<unsigned long long>(insn.pc));
        faulted_ = true;
        running_ = false;
        return;
    }

    // Pre- and post-index update the base register with the immediate offset.
    if (insn.index_mode != 0) {
        const uint64_t updated = base + static_cast<uint64_t>(insn.imm);
        if (insn.rn == 31) state_.sp = updated;
        else state_.set_reg(insn.rn, updated);
    }
}

// ── Scalar floating-point execution ──────────────────────────────────────────
namespace {

// Read a scalar FP register as a double. Single-precision values widen exactly.
double read_fp_scalar(const CpuState& s, uint8_t reg, bool is64) {
    if (is64) {
        double v = 0.0;
        std::memcpy(&v, &s.q[reg][0], sizeof(v));
        return v;
    }
    const uint32_t bits = static_cast<uint32_t>(s.q[reg][0]);
    float f = 0.0f;
    std::memcpy(&f, &bits, sizeof(f));
    return f;
}

// Write a scalar FP register, rounding to single precision when !is64.
void write_fp_scalar(CpuState& s, uint8_t reg, bool is64, double v) {
    if (is64) {
        std::memcpy(&s.q[reg][0], &v, sizeof(v));
    } else {
        const float f = static_cast<float>(v);
        uint32_t bits = 0;
        std::memcpy(&bits, &f, sizeof(bits));
        s.q[reg][0] = bits;
    }
    s.q[reg][1] = 0;
}

// FCMP/FCMPE flags: unordered (either NaN) gives NZCV = 0011; otherwise ordinary compare.
void set_fp_compare_flags(CpuState& s, double a, double b) {
    if (std::isnan(a) || std::isnan(b)) {
        s.n = false; s.z = false; s.c = true; s.v = true;
    } else {
        s.n = a < b;
        s.z = a == b;
        s.c = a >= b;
        s.v = false;
    }
}

} // namespace

void Interpreter::execute_fp(const Arm64Insn& insn) {
    switch (insn.op) {
    case Arm64Op::FCMP_ZERO:
    case Arm64Op::FCMPE_ZERO:
        set_fp_compare_flags(state_, read_fp_scalar(state_, insn.rn, insn.is64), 0.0);
        return;

    case Arm64Op::FMADD:
    case Arm64Op::FMSUB:
    case Arm64Op::FNMADD:
    case Arm64Op::FNMSUB: {
        // Fused: one rounding. Single precision uses fmaf so the result is not
        // rounded through double.
        if (insn.is64) {
            const double n = read_fp_scalar(state_, insn.rn, true);
            const double m = read_fp_scalar(state_, insn.rm, true);
            const double a = read_fp_scalar(state_, insn.ra, true);
            double r = 0.0;
            switch (insn.op) {
            case Arm64Op::FMADD:  r = std::fma(n, m, a); break;
            case Arm64Op::FMSUB:  r = std::fma(-n, m, a); break;   // Ra - Rn*Rm
            case Arm64Op::FNMADD: r = std::fma(-n, m, -a); break;  // -Ra - Rn*Rm
            default:              r = std::fma(n, m, -a); break;   // -Ra + Rn*Rm (FNMSUB)
            }
            write_fp_scalar(state_, insn.rd, true, r);
        } else {
            const float n = static_cast<float>(read_fp_scalar(state_, insn.rn, false));
            const float m = static_cast<float>(read_fp_scalar(state_, insn.rm, false));
            const float a = static_cast<float>(read_fp_scalar(state_, insn.ra, false));
            float r = 0.0f;
            switch (insn.op) {
            case Arm64Op::FMADD:  r = std::fma(n, m, a); break;
            case Arm64Op::FMSUB:  r = std::fma(-n, m, a); break;   // Ra - Rn*Rm
            case Arm64Op::FNMADD: r = std::fma(-n, m, -a); break;  // -Ra - Rn*Rm
            default:              r = std::fma(n, m, -a); break;   // -Ra + Rn*Rm (FNMSUB)
            }
            write_fp_scalar(state_, insn.rd, false, static_cast<double>(r));
        }
        return;
    }

    case Arm64Op::SCVTF:
    case Arm64Op::UCVTF: {
        // Integer source width comes from sf (gpr64); precision from the type field (is64).
        const uint64_t src = state_.reg(insn.rn);
        const bool is_signed = insn.op == Arm64Op::SCVTF;
        double value = 0.0;
        if (insn.is64) {
            value = insn.gpr64
                ? (is_signed ? static_cast<double>(static_cast<int64_t>(src)) : static_cast<double>(src))
                : (is_signed ? static_cast<double>(static_cast<int32_t>(src)) : static_cast<double>(static_cast<uint32_t>(src)));
            write_fp_scalar(state_, insn.rd, true, value);
        } else {
            // Convert straight to float: going through double could round twice.
            const float f = insn.gpr64
                ? (is_signed ? static_cast<float>(static_cast<int64_t>(src)) : static_cast<float>(src))
                : (is_signed ? static_cast<float>(static_cast<int32_t>(src)) : static_cast<float>(static_cast<uint32_t>(src)));
            uint32_t bits = 0;
            std::memcpy(&bits, &f, sizeof(bits));
            state_.q[insn.rd][0] = bits;
            state_.q[insn.rd][1] = 0;
        }
        return;
    }

    case Arm64Op::FCVTZS:
    case Arm64Op::FCVTZU: {
        // Round toward zero and saturate to the destination range; NaN becomes 0.
        const double v = read_fp_scalar(state_, insn.rn, insn.is64);
        uint64_t result = 0;
        if (!std::isnan(v)) {
            const double t = std::trunc(v);
            if (insn.op == Arm64Op::FCVTZS) {
                if (insn.gpr64) {
                    if (t >= 9223372036854775808.0) result = static_cast<uint64_t>(INT64_MAX);
                    else if (t < -9223372036854775808.0) result = static_cast<uint64_t>(INT64_MIN);
                    else result = static_cast<uint64_t>(static_cast<int64_t>(t));
                } else {
                    if (t >= 2147483648.0) result = static_cast<uint32_t>(INT32_MAX);
                    else if (t < -2147483648.0) result = static_cast<uint32_t>(INT32_MIN);
                    else result = static_cast<uint32_t>(static_cast<int32_t>(t));
                }
            } else {
                if (t < 0.0) {
                    result = 0;
                } else if (insn.gpr64) {
                    result = t >= 18446744073709551616.0 ? UINT64_MAX : static_cast<uint64_t>(t);
                } else {
                    result = t >= 4294967296.0 ? UINT32_MAX : static_cast<uint64_t>(t);
                }
            }
        }
        state_.set_reg(insn.rd, result);
        return;
    }

    case Arm64Op::FSQRT: {
        const double v = read_fp_scalar(state_, insn.rn, insn.is64);
        // NaN inputs propagate; sqrt of a negative number is the default (positive) NaN.
        const double r = std::isnan(v) ? v : (v < 0.0 ? std::nan("") : std::sqrt(v));
        write_fp_scalar(state_, insn.rd, insn.is64, r);
        return;
    }

    case Arm64Op::FMAX:
    case Arm64Op::FMIN: {
        const double a = read_fp_scalar(state_, insn.rn, insn.is64);
        const double b = read_fp_scalar(state_, insn.rm, insn.is64);
        const bool is_max = insn.op == Arm64Op::FMAX;
        double r = 0.0;
        if (std::isnan(a) || std::isnan(b)) {
            r = std::isnan(a) ? a : b;                 // NaN operand propagates
        } else if (a == b) {
            // +0 and -0 compare equal: FMAX prefers +0, FMIN prefers -0.
            const bool pick_a = is_max ? !std::signbit(a) : std::signbit(a);
            r = pick_a ? a : b;
        } else {
            r = is_max ? (a > b ? a : b) : (a < b ? a : b);
        }
        write_fp_scalar(state_, insn.rd, insn.is64, r);
        return;
    }

    default:
        break;
    }

    if (insn.op == Arm64Op::FCSEL) {
        const uint8_t source = eval_cond(insn.cond) ? insn.rn : insn.rm;
        state_.q[insn.rd][0] = insn.is64
            ? state_.q[source][0]
            : static_cast<uint32_t>(state_.q[source][0]);
        state_.q[insn.rd][1] = 0;
        return;
    }
    if (insn.op == Arm64Op::FCVT_SD) {
        double source = 0.0;
        std::memcpy(&source, &state_.q[insn.rn][0], sizeof(source));
        const float result = static_cast<float>(source);
        uint32_t result_bits = 0;
        std::memcpy(&result_bits, &result, sizeof(result));
        state_.q[insn.rd][0] = result_bits;
        state_.q[insn.rd][1] = 0;
        return;
    }
    if (insn.op == Arm64Op::FCVT_DS) {
        const uint32_t source_bits = static_cast<uint32_t>(state_.q[insn.rn][0]);
        float source = 0.0f;
        std::memcpy(&source, &source_bits, sizeof(source));
        const double result = static_cast<double>(source);
        std::memcpy(&state_.q[insn.rd][0], &result, sizeof(result));
        state_.q[insn.rd][1] = 0;
        return;
    }
    if (insn.op == Arm64Op::FMOV_TO_GPR) {
        state_.x[insn.rd] = insn.is64 ? state_.q[insn.rn][0]
                                      : static_cast<uint32_t>(state_.q[insn.rn][0]);
        return;
    }
    if (insn.op == Arm64Op::FMOV_FROM_GPR) {
        state_.q[insn.rd][0] = insn.is64 ? state_.x[insn.rn]
                                        : static_cast<uint32_t>(state_.x[insn.rn]);
        state_.q[insn.rd][1] = 0;
        return;
    }
    if (insn.op == Arm64Op::FMOV_IMM) {
        const uint8_t imm8 = static_cast<uint8_t>(insn.imm);
        const uint64_t sign = (imm8 >> 7) & 1;
        const uint64_t b = (imm8 >> 6) & 1;
        const uint64_t cd = (imm8 >> 4) & 3;
        const uint64_t frac = imm8 & 0x0f;
        const unsigned exponent_bits = insn.is64 ? 11 : 8;
        const unsigned fraction_bits = insn.is64 ? 52 : 23;
        uint64_t exponent = ((b ^ 1U) << (exponent_bits - 1)) | cd;
        for (unsigned bit = 2; bit < exponent_bits - 1; ++bit)
            exponent |= b << bit;
        const uint64_t expanded = (sign << (exponent_bits + fraction_bits)) |
            (exponent << fraction_bits) |
            (frac << (fraction_bits - 4));
        state_.q[insn.rd][0] = insn.is64 ? expanded : static_cast<uint32_t>(expanded);
        state_.q[insn.rd][1] = 0;
        return;
    }

    if (insn.op == Arm64Op::FABS || insn.op == Arm64Op::FNEG) {
        if (insn.is64) {
            double value = 0.0;
            std::memcpy(&value, &state_.q[insn.rn][0], sizeof(value));
            value = insn.op == Arm64Op::FABS ? std::fabs(value) : -value;
            std::memcpy(&state_.q[insn.rd][0], &value, sizeof(value));
        } else {
            uint32_t source_bits = static_cast<uint32_t>(state_.q[insn.rn][0]);
            float value = 0.0f;
            std::memcpy(&value, &source_bits, sizeof(value));
            value = insn.op == Arm64Op::FABS ? std::fabs(value) : -value;
            uint32_t result_bits = 0;
            std::memcpy(&result_bits, &value, sizeof(value));
            state_.q[insn.rd][0] = result_bits;
        }
        state_.q[insn.rd][1] = 0;
        return;
    }

    if (insn.op == Arm64Op::FMOV) {
        if (insn.is64) {
            state_.q[insn.rd][0] = state_.q[insn.rn][0];
        } else {
            state_.q[insn.rd][0] = static_cast<uint32_t>(state_.q[insn.rn][0]);
        }
        state_.q[insn.rd][1] = 0;
        return;
    }

    if (insn.is64) {
        double a = 0.0, b = 0.0, result = 0.0;
        std::memcpy(&a, &state_.q[insn.rn][0], sizeof(a));
        std::memcpy(&b, &state_.q[insn.rm][0], sizeof(b));
        if (insn.op == Arm64Op::FCMP || insn.op == Arm64Op::FCMPE) {
            if (std::isnan(a) || std::isnan(b)) {
                state_.n = false; state_.z = false; state_.c = true; state_.v = true;
            } else {
                state_.n = a < b;
                state_.z = a == b;
                state_.c = a >= b;
                state_.v = false;
            }
            return;
        }
        switch (insn.op) {
        case Arm64Op::FADD: result = a + b; break;
        case Arm64Op::FSUB: result = a - b; break;
        case Arm64Op::FMUL: result = a * b; break;
        case Arm64Op::FDIV: result = a / b; break;
        default: return;
        }
        std::memcpy(&state_.q[insn.rd][0], &result, sizeof(result));
        state_.q[insn.rd][1] = 0;
        return;
    }

    float a = 0.0f, b = 0.0f, result = 0.0f;
    const uint32_t a_bits = static_cast<uint32_t>(state_.q[insn.rn][0]);
    const uint32_t b_bits = static_cast<uint32_t>(state_.q[insn.rm][0]);
    std::memcpy(&a, &a_bits, sizeof(a));
    std::memcpy(&b, &b_bits, sizeof(b));
    if (insn.op == Arm64Op::FCMP || insn.op == Arm64Op::FCMPE) {
        if (std::isnan(a) || std::isnan(b)) {
            state_.n = false; state_.z = false; state_.c = true; state_.v = true;
        } else {
            state_.n = a < b;
            state_.z = a == b;
            state_.c = a >= b;
            state_.v = false;
        }
        return;
    }
    switch (insn.op) {
    case Arm64Op::FADD: result = a + b; break;
    case Arm64Op::FSUB: result = a - b; break;
    case Arm64Op::FMUL: result = a * b; break;
    case Arm64Op::FDIV: result = a / b; break;
    default: return;
    }
    uint32_t result_bits = 0;
    std::memcpy(&result_bits, &result, sizeof(result));
    state_.q[insn.rd][0] = result_bits;
    state_.q[insn.rd][1] = 0;
}

// ── Data processing execution ─────────────────────────────────────────────────
// ── Data processing ───────────────────────────────────────────────────────────

void Interpreter::execute_data_proc(const Arm64Insn& insn) {
    const unsigned width = insn.is64 ? 64 : 32;
    const uint64_t mask = width_mask(width);

    // Operand conventions: Rn of add/sub (immediate and extended) and Rd when
    // not setting flags are SP-form; everything else treats register 31 as XZR.
    const auto zr = [&](uint8_t r) -> uint64_t { return state_.reg(r) & mask; };
    const auto sp_src = [&](uint8_t r) -> uint64_t {
        return (r == 31 ? state_.sp : state_.reg(r)) & mask;
    };
    const auto write_zr = [&](uint8_t rd, uint64_t v) { state_.set_reg(rd, v & mask); };
    const auto write_sp = [&](uint8_t rd, uint64_t v) {
        if (rd == 31) state_.sp = v & mask;
        else state_.set_reg(rd, v & mask);
    };

    // a + b + carry_in with NZCV, the single definition for every add and subtract
    // (subtraction is a + ~b + 1; SBC/SBCS use the incoming carry).
    const auto add_with_flags = [&](uint64_t a, uint64_t b, uint64_t carry_in) -> uint64_t {
        a &= mask;
        b &= mask;
        const unsigned __int128 wide = static_cast<unsigned __int128>(a) + b + carry_in;
        const uint64_t res = static_cast<uint64_t>(wide) & mask;
        state_.n = (res >> (width - 1)) & 1;
        state_.z = res == 0;
        state_.c = static_cast<uint64_t>(wide >> width) & 1;
        state_.v = (((~(a ^ b)) & (a ^ res)) >> (width - 1)) & 1;
        return res;
    };
    const auto sub_with_flags = [&](uint64_t a, uint64_t b, uint64_t carry_in) -> uint64_t {
        return add_with_flags(a, ~(b & mask) & mask, carry_in);
    };
    const auto logic_flags = [&](uint64_t res) {
        state_.n = (res >> (width - 1)) & 1;
        state_.z = res == 0;
        state_.c = false;
        state_.v = false;
    };

    switch (insn.op) {
    case Arm64Op::NOP:
        break;

    case Arm64Op::MOV_REG:
        write_zr(insn.rd, zr(insn.rm));
        break;
    case Arm64Op::MOV_IMM:
        write_zr(insn.rd, static_cast<uint64_t>(insn.imm));
        break;
    case Arm64Op::MOVK: {
        // Replace one 16-bit field of Rd and keep every other bit.
        const uint64_t field_mask = 0xFFFFULL << insn.move_shift;
        const uint64_t old_value = state_.reg(insn.rd);
        write_zr(insn.rd, (old_value & ~field_mask)
                          | ((static_cast<uint64_t>(insn.imm) << insn.move_shift) & field_mask));
        break;
    }

    case Arm64Op::ADR:
        state_.set_reg(insn.rd, insn.pc + static_cast<uint64_t>(insn.imm));
        break;
    case Arm64Op::ADRP:
        state_.set_reg(insn.rd, (insn.pc & ~0xFFFULL) + static_cast<uint64_t>(insn.imm));
        break;

    // Add/subtract, immediate (Rn is SP-form; Rd is SP-form unless flags are set).
    case Arm64Op::ADD_IMM: {
        const uint64_t a = sp_src(insn.rn);
        const uint64_t b = static_cast<uint64_t>(insn.imm) & mask;
        if (insn.set_flags) write_zr(insn.rd, add_with_flags(a, b, 0));
        else write_sp(insn.rd, (a + b) & mask);
        break;
    }
    case Arm64Op::SUB_IMM: {
        const uint64_t a = sp_src(insn.rn);
        const uint64_t b = static_cast<uint64_t>(insn.imm) & mask;
        if (insn.set_flags) write_zr(insn.rd, sub_with_flags(a, b, 1));
        else write_sp(insn.rd, (a - b) & mask);
        break;
    }
    case Arm64Op::CMN_IMM:
        add_with_flags(sp_src(insn.rn), static_cast<uint64_t>(insn.imm) & mask, 0);
        break;
    case Arm64Op::CMP_IMM:
        sub_with_flags(sp_src(insn.rn), static_cast<uint64_t>(insn.imm) & mask, 1);
        break;

    // Add/subtract, shifted register (Rn and Rm are ZR-form).
    case Arm64Op::ADD_REG: {
        const uint64_t b = shift_operand(zr(insn.rm), insn.shift_kind, insn.shift_amount, width);
        const uint64_t a = zr(insn.rn);
        write_zr(insn.rd, insn.set_flags ? add_with_flags(a, b, 0) : (a + b) & mask);
        break;
    }
    case Arm64Op::SUB_REG: {
        const uint64_t b = shift_operand(zr(insn.rm), insn.shift_kind, insn.shift_amount, width);
        const uint64_t a = zr(insn.rn);
        write_zr(insn.rd, insn.set_flags ? sub_with_flags(a, b, 1) : (a - b) & mask);
        break;
    }
    case Arm64Op::CMN_REG:
        add_with_flags(zr(insn.rn),
                       shift_operand(zr(insn.rm), insn.shift_kind, insn.shift_amount, width), 0);
        break;
    case Arm64Op::CMP_REG:
        sub_with_flags(zr(insn.rn),
                       shift_operand(zr(insn.rm), insn.shift_kind, insn.shift_amount, width), 1);
        break;

    // Add/subtract, extended register (Rn is SP-form; Rd is SP-form unless flags).
    case Arm64Op::ADD_EXT: {
        const uint64_t a = sp_src(insn.rn);
        const uint64_t b = extend_operand(zr(insn.rm), insn.shift_kind, insn.shift_amount, width);
        if (insn.set_flags) write_zr(insn.rd, add_with_flags(a, b, 0));
        else write_sp(insn.rd, (a + b) & mask);
        break;
    }
    case Arm64Op::SUB_EXT: {
        const uint64_t a = sp_src(insn.rn);
        const uint64_t b = extend_operand(zr(insn.rm), insn.shift_kind, insn.shift_amount, width);
        if (insn.set_flags) write_zr(insn.rd, sub_with_flags(a, b, 1));
        else write_sp(insn.rd, (a - b) & mask);
        break;
    }

    case Arm64Op::ADC:
    case Arm64Op::SBC: {
        const uint64_t carry = state_.c ? 1 : 0;
        const uint64_t a = zr(insn.rn);
        const uint64_t b = zr(insn.rm);
        uint64_t res;
        if (insn.op == Arm64Op::ADC) {
            res = insn.set_flags ? add_with_flags(a, b, carry) : (a + b + carry) & mask;
        } else {
            res = insn.set_flags ? sub_with_flags(a, b, carry) : (a - b - (1 - carry)) & mask;
        }
        write_zr(insn.rd, res);
        break;
    }

    // Multiply and divide.
    case Arm64Op::MUL:
    case Arm64Op::MADD:
    case Arm64Op::MSUB: {
        const uint64_t addend = insn.ra == 31 ? 0 : (state_.reg(insn.ra) & mask);
        const uint64_t product = (zr(insn.rn) * zr(insn.rm)) & mask;
        write_zr(insn.rd, insn.op == Arm64Op::MSUB ? addend - product : addend + product);
        break;
    }
    case Arm64Op::SMULL:
    case Arm64Op::SMADDL:
    case Arm64Op::SMSUBL: {
        const int64_t product = static_cast<int64_t>(static_cast<int32_t>(state_.reg(insn.rn)))
                              * static_cast<int64_t>(static_cast<int32_t>(state_.reg(insn.rm)));
        const uint64_t addend = insn.ra == 31 ? 0 : state_.reg(insn.ra);
        const uint64_t p = static_cast<uint64_t>(product);
        write_zr(insn.rd, insn.op == Arm64Op::SMSUBL ? addend - p : addend + p);
        break;
    }
    case Arm64Op::UMULL:
    case Arm64Op::UMADDL:
    case Arm64Op::UMSUBL: {
        const uint64_t product = static_cast<uint64_t>(static_cast<uint32_t>(state_.reg(insn.rn)))
                               * static_cast<uint64_t>(static_cast<uint32_t>(state_.reg(insn.rm)));
        const uint64_t addend = insn.ra == 31 ? 0 : state_.reg(insn.ra);
        write_zr(insn.rd, insn.op == Arm64Op::UMSUBL ? addend - product : addend + product);
        break;
    }
    case Arm64Op::SMULH: {
        const __int128 p = static_cast<__int128>(static_cast<int64_t>(state_.reg(insn.rn)))
                         * static_cast<__int128>(static_cast<int64_t>(state_.reg(insn.rm)));
        write_zr(insn.rd, static_cast<uint64_t>(p >> 64));
        break;
    }
    case Arm64Op::UMULH: {
        const unsigned __int128 p = static_cast<unsigned __int128>(state_.reg(insn.rn))
                                  * state_.reg(insn.rm);
        write_zr(insn.rd, static_cast<uint64_t>(p >> 64));
        break;
    }
    case Arm64Op::UDIV: {
        const uint64_t d = zr(insn.rm);
        write_zr(insn.rd, d == 0 ? 0 : zr(insn.rn) / d);   // divide by zero yields 0
        break;
    }
    case Arm64Op::SDIV: {
        const int64_t d = static_cast<int64_t>(sign_extend(zr(insn.rm), width));
        const int64_t n = static_cast<int64_t>(sign_extend(zr(insn.rn), width));
        uint64_t res = 0;
        if (d != 0) {
            // INT_MIN / -1 overflows; the architecture wraps it to INT_MIN.
            const int64_t min_value = static_cast<int64_t>(sign_extend(1ULL << (width - 1), width));
            res = (n == min_value && d == -1) ? static_cast<uint64_t>(min_value)
                                              : static_cast<uint64_t>(n / d);
        }
        write_zr(insn.rd, res);
        break;
    }

    // Logical, shifted register. Setting flags (ANDS/BICS) sets N and Z only.
    case Arm64Op::AND_REG:
    case Arm64Op::BIC_REG:
    case Arm64Op::ORR_REG:
    case Arm64Op::ORN_REG:
    case Arm64Op::EOR_REG:
    case Arm64Op::EON_REG: {
        uint64_t b = shift_operand(zr(insn.rm), insn.shift_kind, insn.shift_amount, width);
        const bool invert = insn.op == Arm64Op::BIC_REG || insn.op == Arm64Op::ORN_REG
                         || insn.op == Arm64Op::EON_REG;
        if (invert) b = ~b & mask;
        const uint64_t a = zr(insn.rn);
        uint64_t res;
        if (insn.op == Arm64Op::AND_REG || insn.op == Arm64Op::BIC_REG) res = a & b;
        else if (insn.op == Arm64Op::ORR_REG || insn.op == Arm64Op::ORN_REG) res = a | b;
        else res = a ^ b;
        res &= mask;
        if (insn.set_flags) logic_flags(res);
        write_zr(insn.rd, res);
        break;
    }
    case Arm64Op::TST_REG: {
        const uint64_t b = shift_operand(zr(insn.rm), insn.shift_kind, insn.shift_amount, width);
        logic_flags(zr(insn.rn) & b);
        break;
    }

    // Logical, immediate. Rd is SP-form unless flags are set (ANDS).
    case Arm64Op::AND_IMM:
    case Arm64Op::ORR_IMM:
    case Arm64Op::EOR_IMM: {
        const uint64_t a = zr(insn.rn);
        const uint64_t b = static_cast<uint64_t>(insn.imm) & mask;
        uint64_t res = insn.op == Arm64Op::AND_IMM ? (a & b)
                     : insn.op == Arm64Op::ORR_IMM ? (a | b)
                     : (a ^ b);
        res &= mask;
        if (insn.set_flags) {
            logic_flags(res);
            write_zr(insn.rd, res);
        } else {
            write_sp(insn.rd, res);
        }
        break;
    }
    case Arm64Op::TST_IMM:
        logic_flags(zr(insn.rn) & (static_cast<uint64_t>(insn.imm) & mask));
        break;

    // Variable shifts, and the immediate forms if they are ever produced.
    case Arm64Op::LSL_REG: case Arm64Op::LSR_REG: case Arm64Op::ASR_REG: case Arm64Op::ROR_REG: {
        const unsigned kind = insn.op == Arm64Op::LSL_REG ? 0 : insn.op == Arm64Op::LSR_REG ? 1
                            : insn.op == Arm64Op::ASR_REG ? 2 : 3;
        const unsigned amount = static_cast<unsigned>(zr(insn.rm) & (width - 1));
        write_zr(insn.rd, shift_operand(zr(insn.rn), kind, amount, width));
        break;
    }
    case Arm64Op::LSL_IMM: case Arm64Op::LSR_IMM: case Arm64Op::ASR_IMM: case Arm64Op::ROR_IMM: {
        const unsigned kind = insn.op == Arm64Op::LSL_IMM ? 0 : insn.op == Arm64Op::LSR_IMM ? 1
                            : insn.op == Arm64Op::ASR_IMM ? 2 : 3;
        write_zr(insn.rd, shift_operand(zr(insn.rn), kind, static_cast<unsigned>(insn.imm), width));
        break;
    }

    // Bitfield move: BFM keeps the destination outside the field, UBFM and SBFM
    // clear it, and SBFM replicates the field's top bit. Aliases such as LSL,
    // LSR, ASR, UBFX, SBFX, BFI and SXTB all reduce to these three.
    case Arm64Op::UBFM:
    case Arm64Op::SBFM:
    case Arm64Op::BFM: {
        uint64_t wmask = 0, tmask = 0;
        arm64_decode_bit_masks(insn.is64, insn.is64 ? 1 : 0, insn.imms, insn.immr,
                               false, wmask, tmask);
        const uint64_t src = zr(insn.rn);
        const uint64_t dst = insn.op == Arm64Op::BFM ? zr(insn.rd) : 0;
        const uint64_t rotated = rotate_right(src, insn.immr, width);
        const uint64_t bot = (dst & ~wmask & mask) | (rotated & wmask);
        uint64_t top = dst;
        if (insn.op == Arm64Op::SBFM) {
            top = ((src >> insn.imms) & 1) ? mask : 0;
        }
        write_zr(insn.rd, ((top & ~tmask) | (bot & tmask)) & mask);
        break;
    }

    // EXTR: the bits of Rn:Rm starting at lsb (ROR when Rn == Rm).
    case Arm64Op::EXTR: {
        const unsigned lsb = static_cast<unsigned>(insn.imm);
        const uint64_t n = zr(insn.rn);
        const uint64_t m = zr(insn.rm);
        uint64_t res;
        if (lsb == 0) {
            res = m;
        } else if (width == 64) {
            res = (n << (64 - lsb)) | (m >> lsb);
        } else {
            res = (((n << 32) | m) >> lsb) & 0xFFFFFFFFULL;
        }
        write_zr(insn.rd, res);
        break;
    }

    case Arm64Op::CSEL:
    case Arm64Op::CSINC:
    case Arm64Op::CSINV:
    case Arm64Op::CSNEG: {
        uint64_t res;
        if (eval_cond(insn.cond)) {
            res = zr(insn.rn);
        } else {
            const uint64_t m = zr(insn.rm);
            if (insn.op == Arm64Op::CSINC) res = m + 1;
            else if (insn.op == Arm64Op::CSINV) res = ~m;
            else if (insn.op == Arm64Op::CSNEG) res = 0 - m;
            else res = m;
        }
        write_zr(insn.rd, res & mask);
        break;
    }

    // Conditional compare: compare when the condition holds, else load NZCV.
    case Arm64Op::CCMP_REG: case Arm64Op::CCMP_IMM:
    case Arm64Op::CCMN_REG: case Arm64Op::CCMN_IMM: {
        if (eval_cond(insn.cond)) {
            const uint64_t a = zr(insn.rn);
            const uint64_t b = (insn.op == Arm64Op::CCMP_IMM || insn.op == Arm64Op::CCMN_IMM)
                ? (static_cast<uint64_t>(insn.imm) & mask) : zr(insn.rm);
            if (insn.op == Arm64Op::CCMP_REG || insn.op == Arm64Op::CCMP_IMM) sub_with_flags(a, b, 1);
            else add_with_flags(a, b, 0);
        } else {
            state_.n = (insn.nzcv >> 3) & 1;
            state_.z = (insn.nzcv >> 2) & 1;
            state_.c = (insn.nzcv >> 1) & 1;
            state_.v = insn.nzcv & 1;
        }
        break;
    }

    // CRC32: accumulate the bytes of Rm (least significant first) into Rn, using
    // the reflected polynomial; the 32-bit result zero-extends into Rd.
    case Arm64Op::CRC32B: case Arm64Op::CRC32H: case Arm64Op::CRC32W: case Arm64Op::CRC32X:
    case Arm64Op::CRC32CB: case Arm64Op::CRC32CH: case Arm64Op::CRC32CW: case Arm64Op::CRC32CX: {
        const bool castagnoli = insn.op >= Arm64Op::CRC32CB;
        const Arm64Op base = castagnoli ? Arm64Op::CRC32CB : Arm64Op::CRC32B;
        const unsigned kind = static_cast<unsigned>(insn.op) - static_cast<unsigned>(base);
        const unsigned bytes = kind == 0 ? 1 : kind == 1 ? 2 : kind == 2 ? 4 : 8;
        const uint32_t poly = castagnoli ? 0x82F63B78u : 0xEDB88320u;
        uint32_t crc = static_cast<uint32_t>(state_.reg(insn.rn));
        const uint64_t data = state_.reg(insn.rm);
        for (unsigned i = 0; i < bytes; ++i) {
            crc ^= static_cast<uint32_t>((data >> (8 * i)) & 0xFF);
            for (int bit = 0; bit < 8; ++bit)
                crc = (crc & 1) ? (crc >> 1) ^ poly : crc >> 1;
        }
        state_.set_reg(insn.rd, crc);
        break;
    }

    // Bit and byte manipulation.
    case Arm64Op::RBIT:
        write_zr(insn.rd, reverse_bits(zr(insn.rn), width));
        break;
    case Arm64Op::REV16:
        write_zr(insn.rd, reverse_bytes16(zr(insn.rn), width));
        break;
    case Arm64Op::REV: {
        const uint64_t v = zr(insn.rn);
        write_zr(insn.rd, width == 64 ? __builtin_bswap64(v)
                                      : __builtin_bswap32(static_cast<uint32_t>(v)));
        break;
    }
    case Arm64Op::REV32: {
        const uint64_t v = zr(insn.rn);
        const uint64_t lo = __builtin_bswap32(static_cast<uint32_t>(v));
        const uint64_t hi = __builtin_bswap32(static_cast<uint32_t>(v >> 32));
        write_zr(insn.rd, lo | (hi << 32));
        break;
    }
    case Arm64Op::CLS: {
        // Leading bits equal to the sign bit, not counting the sign bit itself.
        const uint64_t v = zr(insn.rn);
        const uint64_t sign = (v >> (width - 1)) & 1;
        unsigned count = 0;
        for (int i = static_cast<int>(width) - 2; i >= 0; --i) {
            if (((v >> i) & 1) != sign) break;
            ++count;
        }
        write_zr(insn.rd, count);
        break;
    }
    case Arm64Op::CLZ: {
        const uint64_t v = zr(insn.rn);
        unsigned count = width;
        if (v != 0) count = static_cast<unsigned>(__builtin_clzll(v)) - (64 - width);
        write_zr(insn.rd, count);
        break;
    }

    default:
        // The decoder produced an op that this function does not implement.
        std::fprintf(stderr, "[reverta] unhandled op %d at 0x%llx\n",
                     (int)insn.op, (unsigned long long)insn.pc);
        faulted_ = true;
        running_ = false;
        break;
    }
}
