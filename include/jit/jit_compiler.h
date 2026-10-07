#pragma once
#include <cstdint>
#include <memory>
#include <unordered_map>
#include "decoder/arm64_decoder.h"
#include "interpreter/interpreter.h"
#include "loader/macho_loader.h"

// Small x86-64 JIT for straight-line AArch64 integer blocks.
// Unsupported instructions are left for the interpreter.
class JitCompiler {
public:
    explicit JitCompiler(const LoadedBinary& binary);
    ~JitCompiler();

    // Execute a compiled block at state.pc. Returns true when a block ran.
    bool run(CpuState& state);

    void clear();

private:
    using JitFn = void (*)(CpuState*);

    struct Block {
        void* code = nullptr;
        size_t size = 0;
    };

    bool compile(uint64_t guest_pc, Block& out);
    void free_block(Block& block);

    const LoadedBinary& binary_;
    Arm64Decoder decoder_;
    std::unordered_map<uint64_t, Block> blocks_;
};
