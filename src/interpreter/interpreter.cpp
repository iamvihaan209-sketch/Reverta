#include "interpreter/interpreter.h"
#include "jit/jit_compiler.h"
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <cmath>

Interpreter::Interpreter(const LoadedBinary& binary)
    : binary_(binary)
{
    state_.pc = binary.entry_point;
    state_.sp = binary.stack_top;
    // Align SP to 16 bytes (AArch64 ABI requirement)
    state_.sp &= ~0xFULL;
}

uint8_t* Interpreter::guest_to_host(uint64_t vaddr) const {
    for (const auto& seg : binary_.segments) {
        if (!seg.mapped) continue;
        const uint64_t guest_base = seg.mapped_vmaddr ? seg.mapped_vmaddr : seg.vmaddr;
        if (vaddr >= guest_base && vaddr - guest_base < seg.vmsize) {
            return seg.mapped + (vaddr - guest_base);
        }
    }
    return nullptr;
}

RunResult Interpreter::run() {
    running_ = true;
    JitCompiler jit(binary_);

    while (running_) {
        // Phase 2 JIT handles safe straight-line integer blocks. Anything it
        // cannot compile falls through to the existing interpreter.
        if (jit.run(state_))
            continue;

        uint8_t* host_pc = guest_to_host(state_.pc);
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

        // If execute didn't change PC (non-branch), advance it
        if (state_.pc == old_pc) {
            state_.pc += 4;
        }
    }
    return RunResult::OK;
}

bool Interpreter::step() {
    uint8_t* host_pc = guest_to_host(state_.pc);
    if (!host_pc) return false;
    Arm64Insn insn = decoder_.decode(host_pc, state_.pc);
    uint64_t old_pc = state_.pc;
    execute(insn);
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
    case Arm64Op::FMUL: case Arm64Op::FDIV:
    case Arm64Op::FCMP: case Arm64Op::FMOV:
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

    uint8_t* host = guest_to_host(addr);
    // Fall back to stack
    if (!host) {
        // Try treating addr as a host pointer (for our mmap'd stack)
        host = reinterpret_cast<uint8_t*>(addr);
    }

    switch (insn.op) {
    case Arm64Op::LDR_IMM: case Arm64Op::LDR_REG: {
        uint64_t val = insn.is64
            ? *reinterpret_cast<uint64_t*>(host)
            : *reinterpret_cast<uint32_t*>(host);
        state_.set_reg(insn.rd, val);
        break;
    }
    case Arm64Op::STR_IMM: case Arm64Op::STR_REG: {
        uint64_t val = state_.reg(insn.rd);
        if (insn.is64) *reinterpret_cast<uint64_t*>(host) = val;
        else           *reinterpret_cast<uint32_t*>(host) = (uint32_t)val;
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
        if (insn.op == Arm64Op::FCMP) {
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
    if (insn.op == Arm64Op::FCMP) {
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
    case Arm64Op::ASR_IMM: write_result(insn.rd, (int64_t)rn >> insn.imm); break;

    case Arm64Op::NOP:
        break;

    default:
        std::fprintf(stderr, "[reverta] unhandled op %d at 0x%llx\n",
                     (int)insn.op, (unsigned long long)insn.pc);
        running_ = false;
        break;
    }
}
