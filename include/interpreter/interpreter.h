#pragma once
#include <cstdint>
#include <cstring>
#include <functional>
#include "loader/macho_loader.h"
#include "decoder/arm64_decoder.h"

// ARM64 CPU state
struct CpuState {
    uint64_t x[31];   // X0-X30 (X30 = link register)
    uint64_t sp;      // Stack pointer
    uint64_t pc;      // Program counter

    // PSTATE / NZCV flags
    bool n, z, c, v;

    // SIMD/FP registers (128-bit each) — stored as two u64s for now
    uint64_t q[32][2];

    CpuState() { std::memset(this, 0, sizeof(*this)); }

    // Read Xn (X31 reads as 0 / XZR)
    uint64_t reg(uint8_t n) const { return n == 31 ? 0ULL : x[n]; }
    // Write Xn (X31 writes are discarded)
    void set_reg(uint8_t n, uint64_t v) { if (n != 31) x[n] = v; }
};

// Return codes from the interpreter run loop
enum class RunResult {
    OK,           // ran to completion (exit syscall)
    SYSCALL,      // hit SVC — call syscall handler then continue
    UNSUPPORTED,  // hit an instruction we can't handle yet
    FAULT,        // memory access fault
    ERROR
};

// Syscall handler: receives cpu state, returns false to stop execution
using SyscallHandler = std::function<bool(CpuState&)>;

class Interpreter {
public:
    explicit Interpreter(const LoadedBinary& binary);

    void set_syscall_handler(SyscallHandler h) { syscall_handler_ = std::move(h); }

    // Run from entry point until exit or error
    RunResult run();

    // Single-step one instruction; returns false when execution should stop
    bool step();

    CpuState& state() { return state_; }
    const CpuState& state() const { return state_; }

    // Translate guest virtual address to host pointer (nullptr if unmapped)
    uint8_t* guest_to_host(uint64_t vaddr) const;

private:
    void execute(const Arm64Insn& insn);
    void execute_branch(const Arm64Insn& insn);
    void execute_load_store(const Arm64Insn& insn);
    void execute_data_proc(const Arm64Insn& insn);

    bool eval_cond(Arm64Cond cond) const;
    void update_flags_add(uint64_t a, uint64_t b, uint64_t result);
    void update_flags_sub(uint64_t a, uint64_t b, uint64_t result);

    const LoadedBinary& binary_;
    CpuState state_;
    Arm64Decoder decoder_;
    SyscallHandler syscall_handler_;
    bool running_ = false;
};
