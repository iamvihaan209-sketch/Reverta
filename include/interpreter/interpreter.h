#pragma once
#include <cstdint>
#include <cstring>
#include <functional>
#include <cstddef>
#include <vector>
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

enum class GuestAccess { Read, Write, Execute };

// Syscall handler: receives cpu state, returns false to stop execution
using SyscallHandler = std::function<bool(CpuState&)>;

// PC hook: called when the PC is not executable guest memory (for example an
// imported-symbol trampoline). Return true if the hook handled it and updated
// state.pc; return false to fault.
using PcHook = std::function<bool(CpuState&)>;

class Interpreter {
public:
    explicit Interpreter(const LoadedBinary& binary);
    ~Interpreter();

    void set_syscall_handler(SyscallHandler h) { syscall_handler_ = std::move(h); }
    void set_pc_hook(PcHook h) { pc_hook_ = std::move(h); }

    // Run from entry point until exit or error
    RunResult run();

    // Single-step one instruction; returns false when execution should stop
    bool step();

    CpuState& state() { return state_; }
    const CpuState& state() const { return state_; }

    // Translate guest virtual address to host pointer (nullptr if unmapped)
    uint8_t* guest_to_host(uint64_t vaddr, size_t access_size = 1,
                           GuestAccess access = GuestAccess::Read) const;
    int64_t mmap_guest(uint64_t requested_address, size_t length, int prot,
                       int flags, int fd, int64_t offset);
    int64_t munmap_guest(uint64_t address, size_t length);

private:
    struct DynamicMapping {
        uint64_t guest_base;
        size_t size;
        uint8_t* host;
        int prot;
    };
    bool guest_range_overlaps(uint64_t address, size_t size) const;

    void execute(const Arm64Insn& insn);
    void execute_branch(const Arm64Insn& insn);
    void execute_load_store(const Arm64Insn& insn);
    void execute_vector_structure(const Arm64Insn& insn);
    void execute_data_proc(const Arm64Insn& insn);
    void execute_fp(const Arm64Insn& insn);

    bool eval_cond(Arm64Cond cond) const;
    void update_flags_add(uint64_t a, uint64_t b, uint64_t result);
    void update_flags_sub(uint64_t a, uint64_t b, uint64_t result);

    const LoadedBinary& binary_;
    CpuState state_;
    Arm64Decoder decoder_;
    SyscallHandler syscall_handler_;
    PcHook pc_hook_;
    bool running_ = false;
    bool faulted_ = false;
    // Exclusive monitor for a single core: armed by LDXR/LDXP, consumed by STXR/STXP.
    bool excl_valid_ = false;
    uint64_t excl_addr_ = 0;
    unsigned excl_bytes_ = 0;
    std::vector<DynamicMapping> dynamic_mappings_;
    uint64_t next_guest_mapping_ = 0x4000000000ULL;
};
