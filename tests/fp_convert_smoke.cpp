// Scalar FP conversions, FSQRT, FMAX/FMIN and compare-with-zero.
// Encodings were produced by `llvm-mc -triple=arm64-apple-macos` and checked
// against the AArch64 encoding tables; expected results follow the Arm ARM.
#include "interpreter/interpreter.h"
#include <cassert>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <limits>
#include <sys/mman.h>

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
static float as_float(uint64_t q0) {
    const uint32_t low = static_cast<uint32_t>(q0);
    float value = 0.0f;
    std::memcpy(&value, &low, sizeof(value));
    return value;
}
static double as_double(uint64_t q0) {
    double value = 0.0;
    std::memcpy(&value, &q0, sizeof(value));
    return value;
}

int main() {
    alignas(4) uint8_t code[15 * 4]{};
    put32(code + 0 * 4,  0x1E220020); // scvtf  s0, w1
    put32(code + 1 * 4,  0x9E620062); // scvtf  d2, x3
    put32(code + 2 * 4,  0x1E2300A4); // ucvtf  s4, w5
    put32(code + 3 * 4,  0x1E3800E6); // fcvtzs w6, s7
    put32(code + 4 * 4,  0x9E780128); // fcvtzs x8, d9
    put32(code + 5 * 4,  0x1E38016A); // fcvtzs w10, s11
    put32(code + 6 * 4,  0x1E3901AC); // fcvtzu w12, s13
    put32(code + 7 * 4,  0x9E7901EE); // fcvtzu x14, d15
    put32(code + 8 * 4,  0x1E21C230); // fsqrt  s16, s17
    put32(code + 9 * 4,  0x1E61C272); // fsqrt  d18, d19
    put32(code + 10 * 4, 0x1E364AB4); // fmax   s20, s21, s22
    put32(code + 11 * 4, 0x1E365AB7); // fmin   s23, s21, s22
    put32(code + 12 * 4, 0x1E7A4B38); // fmax   d24, d25, d26
    put32(code + 13 * 4, 0x1E202008); // fcmp   s0, #0.0
    put32(code + 14 * 4, 0x1E602378); // fcmpe  d27, #0.0

    LoadedBinary binary{};
    Segment text{};
    text.name = "__TEXT";
    text.vmaddr = 0x1000;
    text.mapped_vmaddr = 0x1000;
    text.vmsize = sizeof(code);
    text.initprot = PROT_READ | PROT_WRITE | PROT_EXEC;
    text.mapped = code;
    binary.segments.push_back(text);
    binary.entry_point = 0x1000;

    const double quiet_nan = std::numeric_limits<double>::quiet_NaN();
    Interpreter interpreter(binary);
    CpuState& state = interpreter.state();
    state.x[1] = 0xFFFFFFFEULL;                // W1 = -2 (signed 32-bit)
    state.x[3] = static_cast<uint64_t>(-5LL);  // X3 = -5
    state.x[5] = 0xFFFFFFFEULL;                // W5 = 4294967294 (unsigned)
    state.x[6] = 0xDEADULL;
    state.x[8] = 0xDEADULL;
    state.x[10] = 0xDEADULL;
    state.x[12] = 0xDEADULL;
    state.x[14] = 0xDEADULL;
    state.q[7][0] = fbits(-2.75f);
    state.q[9][0] = dbits(1e30);
    state.q[11][0] = 0x7FC00000ULL;            // single-precision quiet NaN
    state.q[13][0] = fbits(-0.5f);
    state.q[15][0] = dbits(2.5);
    state.q[17][0] = fbits(9.0f);
    state.q[19][0] = dbits(-1.0);
    state.q[21][0] = fbits(-0.0f);
    state.q[22][0] = fbits(0.0f);
    state.q[25][0] = dbits(quiet_nan);
    state.q[26][0] = dbits(1.0);
    state.q[27][0] = dbits(quiet_nan);

    // scvtf: signed, W source, single-precision result.
    assert(interpreter.step());
    assert(as_float(state.q[0][0]) == -2.0f);
    assert((state.q[0][1]) == 0);

    // scvtf: signed, X source, double-precision result.
    assert(interpreter.step());
    assert(as_double(state.q[2][0]) == -5.0);

    // ucvtf: unsigned W source; 4294967294 rounds to 4294967296 as a float.
    assert(interpreter.step());
    assert(as_float(state.q[4][0]) == 4294967296.0f);

    // fcvtzs (W, S): -2.75 truncates toward zero to -2; zero-extended into X6.
    assert(interpreter.step());
    assert(state.x[6] == 0xFFFFFFFEULL);

    // fcvtzs (X, D): 1e30 saturates to INT64_MAX.
    assert(interpreter.step());
    assert(state.x[8] == static_cast<uint64_t>(INT64_MAX));

    // fcvtzs (W, S): NaN converts to 0.
    assert(interpreter.step());
    assert(state.x[10] == 0);

    // fcvtzu (W, S): -0.5 truncates to 0 (negative values saturate to 0 when unsigned).
    assert(interpreter.step());
    assert(state.x[12] == 0);

    // fcvtzu (X, D): 2.5 truncates to 2.
    assert(interpreter.step());
    assert(state.x[14] == 2);

    // fsqrt single: 9 -> 3.
    assert(interpreter.step());
    assert(as_float(state.q[16][0]) == 3.0f);

    // fsqrt double of a negative number: default NaN, positive sign (0x7FF8...).
    assert(interpreter.step());
    assert(state.q[18][0] == 0x7FF8000000000000ULL);

    // fmax of -0 and +0 returns +0 (bits 0).
    assert(interpreter.step());
    assert(static_cast<uint32_t>(state.q[20][0]) == 0x00000000u);

    // fmin of -0 and +0 returns -0 (sign bit set).
    assert(interpreter.step());
    assert(static_cast<uint32_t>(state.q[23][0]) == 0x80000000u);

    // fmax with a NaN operand propagates the NaN.
    assert(interpreter.step());
    assert(std::isnan(as_double(state.q[24][0])));

    // fcmp s0, #0.0 with s0 = -2.0: N=1 Z=0 C=0 V=0.
    assert(interpreter.step());
    assert(state.n && !state.z && !state.c && !state.v);

    // fcmpe d27, #0.0 with a NaN: unordered gives N=0 Z=0 C=1 V=1.
    assert(interpreter.step());
    assert(!state.n && !state.z && state.c && state.v);

    return 0;
}
