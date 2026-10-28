#include "interpreter/interpreter.h"
#include <cassert>
#include <cstdint>
#include <cstring>

static void put32(uint8_t* p, uint32_t value) {
    std::memcpy(p, &value, sizeof(value));
}
static uint32_t fbits(float value) {
    uint32_t bits = 0;
    std::memcpy(&bits, &value, sizeof(bits));
    return bits;
}
static float as_float(uint64_t bits) {
    const uint32_t low = static_cast<uint32_t>(bits);
    float value = 0.0f;
    std::memcpy(&value, &low, sizeof(value));
    return value;
}

int main() {
    alignas(4) uint8_t code[12]{};
    put32(code + 0, 0x1E222820); // fadd s0, s1, s2
    put32(code + 4, 0x1E212000); // fcmp s0, s1
    put32(code + 8, 0x1E204003); // fmov s3, s0

    LoadedBinary binary{};
    Segment text{};
    text.name = "__TEXT";
    text.vmaddr = 0x1000;
    text.mapped_vmaddr = 0x1000;
    text.vmsize = sizeof(code);
    text.mapped = code;
    binary.segments.push_back(text);
    binary.entry_point = 0x1000;

    Interpreter interpreter(binary);
    CpuState& state = interpreter.state();
    state.q[1][0] = fbits(1.5f);
    state.q[2][0] = fbits(2.25f);

    assert(interpreter.step());
    assert(as_float(state.q[0][0]) == 3.75f);
    assert(interpreter.step());
    assert(!state.n && !state.z && state.c && !state.v);
    assert(interpreter.step());
    assert(as_float(state.q[3][0]) == 3.75f);
    assert(state.pc == 0x100c);
    return 0;
}
