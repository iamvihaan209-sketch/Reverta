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
    if (!host_pc) return false;
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
    case Arm64Cond::NV: return false;
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
    case Arm64Op::LDR_IMM: case Arm64Op::LDR_REG:
    case Arm64Op::STR_IMM: case Arm64Op::STR_REG:
    case Arm64Op::LDP:     case Arm64Op::STP:
    case Arm64Op::LDRB:    case Arm64Op::STRB:
    case Arm64Op::LDRH:    case Arm64Op::STRH:
        execute_load_store(insn);
        break;

    // Scalar floating-point operations use the SIMD/FP register bank.
    case Arm64Op::FADD: case Arm64Op::FSUB:
    case Arm64Op::FMUL: case Arm64Op::FDIV: case Arm64Op::FABS: case Arm64Op::FNEG: case Arm64Op::FCVT_SD: case Arm64Op::FCVT_DS:
    case Arm64Op::FCMP: case Arm64Op::FCMPE: case Arm64Op::FCSEL: case Arm64Op::FMOV: case Arm64Op::FMOV_IMM:
    case Arm64Op::FMOV_TO_GPR: case Arm64Op::FMOV_FROM_GPR:
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
void Interpreter::execute_load_store(const Arm64Insn& insn) {
    uint64_t addr;
    // SP-relative or Xn-relative addressing
    if (insn.rn == 31)
        addr = state_.sp + insn.imm;
    else
        addr = state_.reg(insn.rn) + insn.imm;

    size_t access_size = insn.is64 ? sizeof(uint64_t) : sizeof(uint32_t);
    if (insn.op == Arm64Op::LDRB || insn.op == Arm64Op::STRB) access_size = 1;
    else if (insn.op == Arm64Op::LDRH || insn.op == Arm64Op::STRH) access_size = 2;
    else if (insn.op == Arm64Op::LDP || insn.op == Arm64Op::STP) access_size *= 2;
    uint8_t* host = guest_to_host(addr, access_size, is_load ? GuestAccess::Read : GuestAccess::Write);
    if (!host) {
        std::fprintf(stderr, "[reverta] FAULT: memory access 0x%llx (%zu bytes) unmapped\n",
                     static_cast<unsigned long long>(addr), access_size);
        faulted_ = true;
        return;
    }

    switch (insn.op) {
    case Arm64Op::LDR_IMM: case Arm64Op::LDR_REG: {
        if (insn.is_fp) {
            if (insn.is64) {
                std::memcpy(&state_.q[insn.rd][0], host, sizeof(uint64_t));
            } else {
                uint32_t value = 0;
                std::memcpy(&value, host, sizeof(value));
                state_.q[insn.rd][0] = value;
            }
            state_.q[insn.rd][1] = 0;
        } else {
            uint64_t val = insn.is64
                ? *reinterpret_cast<uint64_t*>(host)
                : *reinterpret_cast<uint32_t*>(host);
            state_.set_reg(insn.rd, val);
        }
        break;
    }
    case Arm64Op::STR_IMM: case Arm64Op::STR_REG: {
        if (insn.is_fp) {
            if (insn.is64) {
                std::memcpy(host, &state_.q[insn.rd][0], sizeof(uint64_t));
            } else {
                const uint32_t value = static_cast<uint32_t>(state_.q[insn.rd][0]);
                std::memcpy(host, &value, sizeof(value));
            }
        } else {
            uint64_t val = state_.reg(insn.rd);
            if (insn.is64) *reinterpret_cast<uint64_t*>(host) = val;
            else           *reinterpret_cast<uint32_t*>(host) = (uint32_t)val;
        }
        break;
    }
    case Arm64Op::LDRB:
        state_.set_reg(insn.rd, *host);
        break;
    case Arm64Op::STRB:
        *host = (uint8_t)state_.reg(insn.rd);
        break;
    case Arm64Op::LDRH:
        state_.set_reg(insn.rd, *reinterpret_cast<uint16_t*>(host));
        break;
    case Arm64Op::STRH:
        *reinterpret_cast<uint16_t*>(host) = (uint16_t)state_.reg(insn.rd);
        break;
    case Arm64Op::LDP: {
        // rd = Rt, rn = Rn, rm = Rt2
        uint64_t v1 = insn.is64
            ? *reinterpret_cast<uint64_t*>(host)
            : *reinterpret_cast<uint32_t*>(host);
        uint64_t v2 = insn.is64
            ? *reinterpret_cast<uint64_t*>(host + 8)
            : *reinterpret_cast<uint32_t*>(host + 4);
        state_.set_reg(insn.rd, v1);
        state_.set_reg(insn.rm, v2);
        break;
    }
    case Arm64Op::STP: {
        uint64_t v1 = state_.reg(insn.rd);
        uint64_t v2 = state_.reg(insn.rm);
        if (insn.is64) {
            *reinterpret_cast<uint64_t*>(host)     = v1;
            *reinterpret_cast<uint64_t*>(host + 8) = v2;
        } else {
            *reinterpret_cast<uint32_t*>(host)     = (uint32_t)v1;
            *reinterpret_cast<uint32_t*>(host + 4) = (uint32_t)v2;
        }
        break;
    }
    default:
        break;
    }
}

// ── Scalar floating-point execution ──────────────────────────────────────────
void Interpreter::execute_fp(const Arm64Insn& insn) {
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
void Interpreter::execute_data_proc(const Arm64Insn& insn) {
    const uint64_t width_mask = insn.is64 ? UINT64_MAX : 0xffffffffULL;
    const uint64_t rn = state_.reg(insn.rn) & width_mask;
    const uint64_t rm = state_.reg(insn.rm) & width_mask;
    const auto write_result = [&](uint8_t rd, uint64_t value) {
        state_.set_reg(rd, value & width_mask);
    };
    const auto add_flags = [&](uint64_t a, uint64_t b, uint64_t result) {
        if (insn.is64) {
            update_flags_add(a, b, result);
        } else {
            const uint32_t aa = static_cast<uint32_t>(a);
            const uint32_t bb = static_cast<uint32_t>(b);
            const uint32_t rr = static_cast<uint32_t>(result);
            state_.n = (rr >> 31) != 0;
            state_.z = rr == 0;
            state_.c = (static_cast<uint64_t>(aa) + bb) > UINT32_MAX;
            state_.v = ((~(aa ^ bb) & (aa ^ rr)) >> 31) != 0;
        }
    };
    const auto sub_flags = [&](uint64_t a, uint64_t b, uint64_t result) {
        if (insn.is64) {
            update_flags_sub(a, b, result);
        } else {
            const uint32_t aa = static_cast<uint32_t>(a);
            const uint32_t bb = static_cast<uint32_t>(b);
            const uint32_t rr = static_cast<uint32_t>(result);
            state_.n = (rr >> 31) != 0;
            state_.z = rr == 0;
            state_.c = aa >= bb;
            state_.v = (((aa ^ bb) & (aa ^ rr)) >> 31) != 0;
        }
    };

    switch (insn.op) {
    case Arm64Op::MOV_REG:
        write_result(insn.rd, rm);
        break;
    case Arm64Op::MOV_IMM:
        write_result(insn.rd, (uint64_t)insn.imm);
        break;

    case Arm64Op::ADD_REG: {
        uint64_t res = rn + rm;
        if (insn.set_flags) add_flags(rn, rm, res);
        write_result(insn.rd, res);
        break;
    }
    case Arm64Op::ADD_IMM: {
        uint64_t res = rn + (uint64_t)insn.imm;
        if (insn.set_flags) add_flags(rn, static_cast<uint64_t>(insn.imm) & width_mask, res);
        write_result(insn.rd, res);
        break;
    }
    case Arm64Op::SUB_REG: {
        uint64_t res = rn - rm;
        if (insn.set_flags) sub_flags(rn, rm, res);
        write_result(insn.rd, res);
        break;
    }
    case Arm64Op::SUB_IMM: {
        uint64_t b = (uint64_t)insn.imm;
        uint64_t res = rn - b;
        if (insn.set_flags) sub_flags(rn, b & width_mask, res);
        write_result(insn.rd, res);
        break;
    }
    case Arm64Op::CMP_REG:
        sub_flags(rn, rm, rn - rm);
        break;
    case Arm64Op::CMP_IMM:
        sub_flags(rn, static_cast<uint64_t>(insn.imm) & width_mask, rn - (static_cast<uint64_t>(insn.imm) & width_mask));
        break;

    case Arm64Op::MUL:
        write_result(insn.rd, rn * rm);
        break;

    case Arm64Op::AND_REG: write_result(insn.rd, rn & rm); break;
    case Arm64Op::AND_IMM: write_result(insn.rd, rn & (uint64_t)insn.imm); break;
    case Arm64Op::ORR_REG: write_result(insn.rd, rn | rm); break;
    case Arm64Op::ORR_IMM: write_result(insn.rd, rn | (uint64_t)insn.imm); break;
    case Arm64Op::EOR_REG: write_result(insn.rd, rn ^ rm); break;
    case Arm64Op::EOR_IMM: write_result(insn.rd, rn ^ (uint64_t)insn.imm); break;

    case Arm64Op::LSL_IMM: write_result(insn.rd, rn << insn.imm); break;
    case Arm64Op::LSR_IMM: write_result(insn.rd, rn >> insn.imm); break;
    case Arm64Op::ASR_IMM:
        if (insn.is64) {
            write_result(insn.rd, static_cast<uint64_t>(static_cast<int64_t>(rn) >> insn.imm));
        } else {
            write_result(insn.rd, static_cast<uint32_t>(
                static_cast<int32_t>(static_cast<uint32_t>(rn)) >> insn.imm));
        }
        break;

    case Arm64Op::NOP:
        break;

    default:
        std::fprintf(stderr, "[reverta] unhandled op %d at 0x%llx\n",
                     (int)insn.op, (unsigned long long)insn.pc);
        running_ = false;
        break;
    }
}
