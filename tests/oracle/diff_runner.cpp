// Differential-test runner. Reads one case per line on stdin, executes exactly
// one instruction in the Reverta interpreter and prints the resulting state.
//
// Input line:  <word_hex> <sp_hex> <nzcv_0_to_15> <x0..x30 hex> <lo0..lo31> <hi0..hi31>
//              lo/hi are the low and high 64-bit halves of V0..V31.
// Output line: "U"                       the decoder does not model the word
//              "R"                       decoded, but the interpreter refused it
//              "<mnemonic> <sp> <nzcv> <x0..x30> <lo0..lo31> <hi0..hi31> <512 hex bytes>"
//
// Driven by tests/oracle/diff_oracle.py, which compares against Unicorn.
#include "interpreter/interpreter.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/mman.h>

// Data page shared with the Python driver: same address, size and fill pattern.
static const uint64_t kDataAddr = 0x20000;
static const uint64_t kDataSize = 0x10000;
static const uint64_t kWindowStart = 0x20700;   // 512 bytes around the base 0x20800
static const uint64_t kWindowSize = 512;

static uint8_t pattern_byte(uint32_t i) {
    return static_cast<uint8_t>(static_cast<uint32_t>(i * 2654435761u) >> 13);
}

int main() {
    // One 4 KB code page, as the Python side maps: literal loads read from it.
    alignas(16) static uint8_t code[0x1000];
    alignas(16) static uint8_t data[kDataSize];

    Segment text{};
    text.name = "__TEXT";
    text.vmaddr = 0x1000;
    text.mapped_vmaddr = 0x1000;
    text.vmsize = sizeof(code);
    text.initprot = PROT_READ | PROT_WRITE | PROT_EXEC;
    text.mapped = code;
    Segment data_seg{};
    data_seg.name = "__DATA";
    data_seg.vmaddr = kDataAddr;
    data_seg.mapped_vmaddr = kDataAddr;
    data_seg.vmsize = kDataSize;
    data_seg.initprot = PROT_READ | PROT_WRITE;
    data_seg.mapped = data;
    LoadedBinary binary{};
    binary.segments.push_back(text);
    binary.segments.push_back(data_seg);
    binary.entry_point = 0x1000;

    Arm64Decoder decoder;

    char line[8192];
    while (std::fgets(line, sizeof line, stdin)) {
        unsigned int word = 0;
        unsigned long long sp = 0;
        unsigned int nzcv = 0;
        uint64_t x[31] = {};
        uint64_t d[32] = {};
        uint64_t hi[32] = {};
        char* p = line;
        word = static_cast<unsigned int>(std::strtoul(p, &p, 16));
        sp = std::strtoull(p, &p, 16);
        nzcv = static_cast<unsigned int>(std::strtoul(p, &p, 16));
        for (int i = 0; i < 31; ++i) x[i] = std::strtoull(p, &p, 16);
        for (int i = 0; i < 32; ++i) d[i] = std::strtoull(p, &p, 16);
        for (int i = 0; i < 32; ++i) hi[i] = std::strtoull(p, &p, 16);

        std::memcpy(code, &word, sizeof(word));
        Arm64Insn insn = decoder.decode(code, 0x1000);
        if (insn.op == Arm64Op::UNKNOWN) {
            std::puts("U");
            continue;
        }

        // A fresh interpreter per case: a fault is sticky, and one refused
        // instruction must not poison the results for the rest of the run.
        for (uint32_t i = 0; i < kDataSize; ++i) data[i] = pattern_byte(i);
        Interpreter interp(binary);
        CpuState& s = interp.state();
        for (int i = 0; i < 31; ++i) s.x[i] = x[i];
        for (int i = 0; i < 32; ++i) { s.q[i][0] = d[i]; s.q[i][1] = hi[i]; }
        s.sp = sp;
        s.pc = 0x1000;
        s.n = (nzcv >> 3) & 1;
        s.z = (nzcv >> 2) & 1;
        s.c = (nzcv >> 1) & 1;
        s.v = nzcv & 1;

        if (!interp.step()) {
            std::puts("R");
            continue;
        }

        // mnemonic() appends a "\t[raw=...]" debug suffix; keep only the name.
        std::string name = insn.mnemonic();
        name = name.substr(0, name.find_first_of(" \t"));
        const CpuState& r = interp.state();
        unsigned int out_nzcv = (r.n << 3) | (r.z << 2) | (r.c << 1) | (r.v ? 1u : 0u);
        std::printf("%s %llx %x", name.c_str(), static_cast<unsigned long long>(r.sp), out_nzcv);
        for (int i = 0; i < 31; ++i)
            std::printf(" %llx", static_cast<unsigned long long>(r.x[i]));
        for (int i = 0; i < 32; ++i)
            std::printf(" %llx", static_cast<unsigned long long>(r.q[i][0]));
        for (int i = 0; i < 32; ++i)
            std::printf(" %llx", static_cast<unsigned long long>(r.q[i][1]));
        // The window around the base register, as the guest now sees it.
        std::printf(" ");
        for (uint64_t i = 0; i < kWindowSize; ++i)
            std::printf("%02x", data[kWindowStart - kDataAddr + i]);
        std::printf("\n");
    }
    return 0;
}
