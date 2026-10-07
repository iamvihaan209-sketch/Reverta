#include "jit/jit_compiler.h"
#include <sys/mman.h>
#include <unistd.h>
#include <cstring>
#include <vector>
#include <cstddef>

namespace {
constexpr size_t kPageSizeFallback = 4096;

static void emit8(std::vector<uint8_t>& c, uint8_t v) {
    c.push_back(v);
}

static void emit32(std::vector<uint8_t>& c, uint32_t v) {
    for (int i = 0; i < 4; ++i) c.push_back(static_cast<uint8_t>(v >> (i * 8)));
}

static void emit64(std::vector<uint8_t>& c, uint64_t v) {
    for (int i = 0; i < 8; ++i) c.push_back(static_cast<uint8_t>(v >> (i * 8)));
}

// mov rax, [rdi + disp32]
static void load_rax(std::vector<uint8_t>& c, uint8_t reg) {
    if (reg == 31) {
        emit8(c, 0x48); emit8(c, 0x31); emit8(c, 0xC0); // xor eax,eax
        return;
    }
    emit8(c, 0x48); emit8(c, 0x8B); emit8(c, 0x87);
    emit32(c, static_cast<uint32_t>(reg * 8));
}

// mov rcx, [rdi + disp32]
static void load_rcx(std::vector<uint8_t>& c, uint8_t reg) {
    if (reg == 31) {
        emit8(c, 0x48); emit8(c, 0x31); emit8(c, 0xC9); // xor ecx,ecx
        return;
    }
    emit8(c, 0x48); emit8(c, 0x8B); emit8(c, 0x8F);
    emit32(c, static_cast<uint32_t>(reg * 8));
}

// mov [rdi + disp32], rax
static void store_rax(std::vector<uint8_t>& c, uint8_t reg) {
    if (reg == 31) return; // XZR: writes are discarded
    emit8(c, 0x48); emit8(c, 0x89); emit8(c, 0x87);
    emit32(c, static_cast<uint32_t>(reg * 8));
}

static void mov_rax_imm64(std::vector<uint8_t>& c, uint64_t value) {
    emit8(c, 0x48); emit8(c, 0xB8); emit64(c, value);
}

// Return true only for operations whose current decoder semantics are safe
// to JIT without needing guest memory or flag materialization.
static bool jit_safe(const Arm64Insn& insn) {
    if (!insn.is64 || insn.set_flags) return false;
    switch (insn.op) {
    case Arm64Op::MOV_REG:
    case Arm64Op::MOV_IMM:
    case Arm64Op::ADD_REG:
    case Arm64Op::ADD_IMM:
    case Arm64Op::SUB_REG:
    case Arm64Op::SUB_IMM:
    case Arm64Op::MUL:
    case Arm64Op::AND_REG:
    case Arm64Op::ORR_REG:
    case Arm64Op::EOR_REG:
        break;
    default:
        return false;
    }

    // MOVK is represented as MOV_IMM by the phase-1 decoder, but its
    // semantics are read-modify-write and cannot be safely treated as MOV.
    if (insn.op == Arm64Op::MOV_IMM) {
        const uint32_t opc = (insn.raw >> 29) & 0x3;
        if (opc == 0x3) return false;
    }
    return true;
}
} // namespace

JitCompiler::JitCompiler(const LoadedBinary& binary) : binary_(binary) {}

JitCompiler::~JitCompiler() {
    clear();
}

void JitCompiler::free_block(Block& block) {
    if (block.code && block.size)
        ::munmap(block.code, block.size);
    block = {};
}

void JitCompiler::clear() {
    for (auto& [pc, block] : blocks_) {
        (void)pc;
        free_block(block);
    }
    blocks_.clear();
}

bool JitCompiler::compile(uint64_t guest_pc, Block& out) {
    std::vector<uint8_t> code;
    code.reserve(512);

    uint64_t pc = guest_pc;
    constexpr size_t kMaxInstructions = 32;

    for (size_t i = 0; i < kMaxInstructions; ++i, pc += 4) {
        uint8_t* insn_host = nullptr;
        for (const auto& seg : binary_.segments) {
            if (seg.mapped && pc >= seg.vmaddr &&
                pc < seg.vmaddr + seg.vmsize) {
                insn_host = seg.mapped + (pc - seg.vmaddr);
                break;
            }
        }
        if (!insn_host) break;

        Arm64Insn insn = decoder_.decode(insn_host, pc);
        if (!jit_safe(insn)) break;

        switch (insn.op) {
        case Arm64Op::MOV_REG:
            load_rax(code, insn.rm);
            store_rax(code, insn.rd);
            break;

        case Arm64Op::MOV_IMM:
            mov_rax_imm64(code, static_cast<uint64_t>(insn.imm));
            store_rax(code, insn.rd);
            break;

        case Arm64Op::ADD_REG:
            load_rax(code, insn.rn);
            load_rcx(code, insn.rm);
            emit8(code, 0x48); emit8(code, 0x01); emit8(code, 0xC8); // add rax,rcx
            store_rax(code, insn.rd);
            break;

        case Arm64Op::ADD_IMM:
            load_rax(code, insn.rn);
            if (insn.imm >= 0 && static_cast<uint64_t>(insn.imm) <= 0x7fffffffULL) {
                emit8(code, 0x48); emit8(code, 0x05);
                emit32(code, static_cast<uint32_t>(insn.imm));
            } else {
                load_rcx(code, insn.rn);
                mov_rax_imm64(code, static_cast<uint64_t>(insn.imm));
                emit8(code, 0x48); emit8(code, 0x01); emit8(code, 0xC1);
                emit8(code, 0x48); emit8(code, 0x89); emit8(code, 0xC8);
            }
            store_rax(code, insn.rd);
            break;

        case Arm64Op::SUB_REG:
            load_rax(code, insn.rn);
            load_rcx(code, insn.rm);
            emit8(code, 0x48); emit8(code, 0x29); emit8(code, 0xC8); // sub rax,rcx
            store_rax(code, insn.rd);
            break;

        case Arm64Op::SUB_IMM:
            load_rax(code, insn.rn);
            if (insn.imm >= 0 && static_cast<uint64_t>(insn.imm) <= 0x7fffffffULL) {
                emit8(code, 0x48); emit8(code, 0x2D);
                emit32(code, static_cast<uint32_t>(insn.imm));
            } else {
                load_rcx(code, insn.rn);
                mov_rax_imm64(code, static_cast<uint64_t>(insn.imm));
                emit8(code, 0x48); emit8(code, 0x29); emit8(code, 0xC1);
                emit8(code, 0x48); emit8(code, 0x89); emit8(code, 0xC8);
            }
            store_rax(code, insn.rd);
            break;

        case Arm64Op::MUL:
            load_rax(code, insn.rn);
            load_rcx(code, insn.rm);
            emit8(code, 0x48); emit8(code, 0x0F); emit8(code, 0xAF); emit8(code, 0xC1);
            store_rax(code, insn.rd);
            break;

        case Arm64Op::AND_REG:
            load_rax(code, insn.rn);
            load_rcx(code, insn.rm);
            emit8(code, 0x48); emit8(code, 0x21); emit8(code, 0xC8);
            store_rax(code, insn.rd);
            break;

        case Arm64Op::ORR_REG:
            load_rax(code, insn.rn);
            load_rcx(code, insn.rm);
            emit8(code, 0x48); emit8(code, 0x09); emit8(code, 0xC8);
            store_rax(code, insn.rd);
            break;

        case Arm64Op::EOR_REG:
            load_rax(code, insn.rn);
            load_rcx(code, insn.rm);
            emit8(code, 0x48); emit8(code, 0x31); emit8(code, 0xC8);
            store_rax(code, insn.rd);
            break;

        default:
            return false;
        }
    }

    const size_t instruction_count = (pc - guest_pc) / 4;
    if (instruction_count == 0) return false;

    // The interpreter resumes at the first instruction not included in the
    // native block. This deliberately leaves branches, syscalls, memory, and
    // flags under interpreter control for now.
    const uint64_t next_pc = pc;
    mov_rax_imm64(code, next_pc);
    // pc field is immediately after x[31].
    emit8(code, 0x48); emit8(code, 0x89); emit8(code, 0x87);
    emit32(code, static_cast<uint32_t>(offsetof(CpuState, pc)));
    emit8(code, 0xC3); // ret

    const long page_size = ::sysconf(_SC_PAGESIZE);
    const size_t page = page_size > 0 ? static_cast<size_t>(page_size) : kPageSizeFallback;
    const size_t alloc_size = ((code.size() + page - 1) / page) * page;

    void* mem = ::mmap(nullptr, alloc_size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) return false;

    std::memcpy(mem, code.data(), code.size());
    if (::mprotect(mem, alloc_size, PROT_READ | PROT_EXEC) != 0) {
        ::munmap(mem, alloc_size);
        return false;
    }

    out.code = mem;
    out.size = alloc_size;
    return true;
}

bool JitCompiler::run(CpuState& state) {
    auto it = blocks_.find(state.pc);
    if (it == blocks_.end()) {
        Block block;
        if (!compile(state.pc, block)) return false;
        it = blocks_.emplace(state.pc, block).first;
    }

    auto fn = reinterpret_cast<JitFn>(it->second.code);
    fn(&state);
    return true;
}
