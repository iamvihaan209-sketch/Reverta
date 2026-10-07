#include "jit/jit_compiler.h"
#include <cassert>
#include <cstdint>
#include <cstring>
#include <iostream>

static void put32(uint8_t* p, uint32_t v) {
    std::memcpy(p, &v, sizeof(v));
}

int main() {
    alignas(4) uint8_t code[16]{};
    put32(code + 0, 0xD28000A0); // mov x0, #5
    put32(code + 4, 0x91000C01); // add x1, x0, #3
    put32(code + 8, 0x8A000022); // and x2, x1, x0
    put32(code + 12, 0xCA010043); // eor x3, x2, x1

    LoadedBinary binary{};
    Segment text{};
    text.name = "__TEXT";
    text.vmaddr = 0x1000;
    text.vmsize = sizeof(code);
    text.mapped = code;
    binary.segments.push_back(text);

    CpuState state{};
    state.pc = 0x1000;

    JitCompiler jit(binary);
    assert(jit.run(state));
    assert(state.x[0] == 5);
    assert(state.x[1] == 8);
    assert(state.x[2] == (8 & 5));
    assert(state.x[3] == ((8 & 5) ^ 8));
    assert(state.pc == 0x1010);

    std::cout << "Reverta JIT smoke test passed\n";
    return 0;
}
