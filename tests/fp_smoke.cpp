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
static uint64_t dbits(double value) {
    uint64_t bits = 0;
    std::memcpy(&bits, &value, sizeof(bits));
    return bits;
}
static double as_double(uint64_t bits) {
    double value = 0.0;
    std::memcpy(&value, &bits, sizeof(value));
    return value;
}
static float as_float(uint64_t bits) {
    const uint32_t low = static_cast<uint32_t>(bits);
    float value = 0.0f;
    std::memcpy(&value, &low, sizeof(value));
    return value;
}

int main() {
    alignas(4) uint8_t code[112]{};
    put32(code + 0,  0x1E222820); // fadd s0, s1, s2
    put32(code + 4,  0x1E212000); // fcmp s0, s1
    put32(code + 8,  0x1E204003); // fmov s3, s0
    put32(code + 12, 0x1E6628A4); // fadd d4, d5, d6
    put32(code + 16, 0x1E652080); // fcmp d4, d5
    put32(code + 20, 0x1E604087); // fmov d7, d4
    put32(code + 24, 0x1E2E1008); // fmov s8, #1.0
    put32(code + 28, 0x1E701009); // fmov d9, #-2.0
    put32(code + 32, 0x1E26000A); // fmov w10, s0
    put32(code + 36, 0x9E66008D); // fmov x13, d4
    put32(code + 40, 0x0B020020); // add w0, w1, w2
    put32(code + 44, 0x1E21400E); // fneg s14, s0
    put32(code + 48, 0x1E60C08F); // fabs d15, d4
    put32(code + 52, 0x1E223830); // fsub s16, s1, s2
    put32(code + 56, 0x1E220831); // fmul s17, s1, s2
    put32(code + 60, 0x1E211852); // fdiv s18, s2, s1
    put32(code + 64, 0x1E62408C); // fcvt s12, d4
    put32(code + 68, 0x1E22C18D); // fcvt d13, s12
    put32(code + 72, 0x1E212010); // fcmpe s0, s1
    put32(code + 76, 0xBD00002E); // str s14, [x1]
    put32(code + 80, 0xBD400030); // ldr s16, [x1]
    put32(code + 84, 0xFD00042F); // str d15, [x1, #8]
    put32(code + 88, 0xFD400431); // ldr d17, [x1, #8]

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
    state.q[5][0] = dbits(1.25);
    state.q[6][0] = dbits(2.5);
    state.x[1] = 0xffffffffULL;
    state.x[2] = 2;

    assert(interpreter.step());
    assert(as_float(state.q[0][0]) == 3.75f);
    assert(interpreter.step());
    assert(!state.n && !state.z && state.c && !state.v);
    assert(interpreter.step());
    assert(as_float(state.q[3][0]) == 3.75f);
    assert(interpreter.step());
    assert(as_double(state.q[4][0]) == 3.75);
    assert(interpreter.step());
    assert(!state.n && !state.z && state.c && !state.v);
    assert(interpreter.step());
    assert(as_double(state.q[7][0]) == 3.75);
    assert(interpreter.step());
    assert(as_float(state.q[8][0]) == 1.0f);
    assert(interpreter.step());
    assert(as_double(state.q[9][0]) == -2.0);
    assert(interpreter.step());
    assert(state.x[10] == fbits(3.75f));
    assert(interpreter.step());
    assert(state.x[13] == dbits(3.75));
    assert(interpreter.step());
    assert(state.x[0] == 1); // W-register arithmetic wraps to 32 bits, then zero-extends
    assert(interpreter.step());
    assert(as_float(state.q[14][0]) == -3.75f);
    assert(interpreter.step());
    assert(as_double(state.q[15][0]) == 3.75);
    assert(interpreter.step());
    assert(as_float(state.q[16][0]) == -0.75f);
    assert(interpreter.step());
    assert(as_float(state.q[17][0]) == 3.375f);
    assert(interpreter.step());
    assert(as_float(state.q[18][0]) == 1.5f);
    assert(interpreter.step());
    assert(as_float(state.q[12][0]) == 3.75f);
    assert(interpreter.step());
    assert(as_double(state.q[13][0]) == 3.75);

    state.q[0][0] = 0x7fc00000U; // quiet NaN
    assert(interpreter.step());
    assert(!state.n && !state.z && state.c && state.v);
    assert(state.pc == 0x104C);

    // S/D loads and stores use the mapped guest image rather than arbitrary host pointers.
    state.x[1] = 0x1000 + 96;
    assert(interpreter.step());
    assert(interpreter.step());
    assert(as_float(state.q[16][0]) == -3.75f);
    assert(interpreter.step());
    assert(interpreter.step());
    assert(as_double(state.q[17][0]) == 3.75);
    assert(state.pc == 0x105C);

    alignas(4) uint8_t unsupported[4]{};
    put32(unsupported, 0x1E80F000);
    Arm64Decoder decoder;
    const Arm64Insn unknown = decoder.decode(unsupported, 0x2000);
    assert(unknown.op == Arm64Op::UNKNOWN);

    // An unmapped/out-of-range guest load must fault, never dereference a host pointer.
    alignas(4) uint8_t load_code[4]{};
    put32(load_code, 0xF9400020); // ldr x0, [x1]
    LoadedBinary fault_binary{};
    Segment fault_text{};
    fault_text.name = "__TEXT";
    fault_text.vmaddr = 0x3000;
    fault_text.mapped_vmaddr = 0x3000;
    fault_text.vmsize = sizeof(load_code);
    fault_text.mapped = load_code;
    fault_binary.segments.push_back(fault_text);
    fault_binary.entry_point = 0x3000;
    Interpreter fault_interpreter(fault_binary);
    fault_interpreter.state().x[1] = 0xDEADBEEF;
    assert(!fault_interpreter.step());
    return 0;
}
