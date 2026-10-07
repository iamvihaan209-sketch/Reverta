#include "interpreter/interpreter.h"
#include "jit/jit_compiler.h"
#include <cstdio>
#include <cstring>
#include <stdexcept>

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
        if (vaddr >= seg.vmaddr && vaddr < seg.vmaddr + seg.vmsize) {
            return seg.mapped + (vaddr - seg.vmaddr);
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

// ── Data processing execution ─────────────────────────────────────────────────
void Interpreter::execute_data_proc(const Arm64Insn& insn) {
    uint64_t rn = state_.reg(insn.rn);
    uint64_t rm = state_.reg(insn.rm);

    switch (insn.op) {
    case Arm64Op::MOV_REG:
        state_.set_reg(insn.rd, rm);
        break;
    case Arm64Op::MOV_IMM:
        state_.set_reg(insn.rd, (uint64_t)insn.imm);
        break;

    case Arm64Op::ADD_REG: {
        uint64_t res = rn + rm;
        if (insn.set_flags) update_flags_add(rn, rm, res);
        state_.set_reg(insn.rd, res);
        break;
    }
    case Arm64Op::ADD_IMM: {
        uint64_t res = rn + (uint64_t)insn.imm;
        if (insn.set_flags) update_flags_add(rn, (uint64_t)insn.imm, res);
        state_.set_reg(insn.rd, res);
        break;
    }
    case Arm64Op::SUB_REG: {
        uint64_t res = rn - rm;
        if (insn.set_flags) update_flags_sub(rn, rm, res);
        state_.set_reg(insn.rd, res);
        break;
    }
    case Arm64Op::SUB_IMM: {
        uint64_t b = (uint64_t)insn.imm;
        uint64_t res = rn - b;
        if (insn.set_flags) update_flags_sub(rn, b, res);
        state_.set_reg(insn.rd, res);
        break;
    }
    case Arm64Op::CMP_REG:
        update_flags_sub(rn, rm, rn - rm);
        break;
    case Arm64Op::CMP_IMM:
        update_flags_sub(rn, (uint64_t)insn.imm, rn - (uint64_t)insn.imm);
        break;

    case Arm64Op::MUL:
        state_.set_reg(insn.rd, rn * rm);
        break;

    case Arm64Op::AND_REG: state_.set_reg(insn.rd, rn & rm); break;
    case Arm64Op::AND_IMM: state_.set_reg(insn.rd, rn & (uint64_t)insn.imm); break;
    case Arm64Op::ORR_REG: state_.set_reg(insn.rd, rn | rm); break;
    case Arm64Op::ORR_IMM: state_.set_reg(insn.rd, rn | (uint64_t)insn.imm); break;
    case Arm64Op::EOR_REG: state_.set_reg(insn.rd, rn ^ rm); break;
    case Arm64Op::EOR_IMM: state_.set_reg(insn.rd, rn ^ (uint64_t)insn.imm); break;

    case Arm64Op::LSL_IMM: state_.set_reg(insn.rd, rn << insn.imm); break;
    case Arm64Op::LSR_IMM: state_.set_reg(insn.rd, rn >> insn.imm); break;
    case Arm64Op::ASR_IMM: state_.set_reg(insn.rd, (int64_t)rn >> insn.imm); break;

    case Arm64Op::NOP:
        break;

    default:
        std::fprintf(stderr, "[reverta] unhandled op %d at 0x%llx\n",
                     (int)insn.op, (unsigned long long)insn.pc);
        running_ = false;
        break;
    }
}
