#pragma once
#include <cstdint>
#include <string>

// AArch64 instruction types we handle
enum class Arm64Op {
    // Data processing
    MOV_REG, MOV_IMM,
    ADD_REG, ADD_IMM,
    SUB_REG, SUB_IMM,
    MUL,
    AND_REG, AND_IMM,
    ORR_REG, ORR_IMM,
    EOR_REG, EOR_IMM,
    LSL_IMM, LSR_IMM, ASR_IMM,
    CMP_REG, CMP_IMM,
    // Load/Store
    LDR_REG, LDR_IMM,
    STR_REG, STR_IMM,
    LDP, STP,
    LDRB, STRB,
    LDRH, STRH,
    // Branches
    B, BL, BLR, BR, RET,
    B_COND,   // Bcc
    CBZ, CBNZ,
    TBZ, TBNZ,
    // System
    SVC,
    NOP,
    // Unsupported / decode error
    UNKNOWN
};

// Condition codes for Bcc
enum class Arm64Cond {
    EQ=0, NE, CS, CC, MI, PL, VS, VC,
    HI, LS, GE, LT, GT, LE, AL, NV
};

// Decoded instruction
struct Arm64Insn {
    Arm64Op  op;
    uint32_t raw;        // raw 32-bit encoding
    uint64_t pc;         // address this was decoded from

    // Register fields (0-30 = Xn, 31 = XZR/SP depending on context)
    uint8_t  rd, rn, rm; // destination, source1, source2

    // Immediate / offset
    int64_t  imm;
    bool     is64;       // 64-bit variant (vs 32-bit Wn)
    bool     set_flags;  // S suffix (ADDS, SUBS, etc.)

    Arm64Cond cond;      // for B.cond, CSEL, etc.
    uint8_t  bit_pos;    // for TBZ/TBNZ

    // Human-readable (debug)
    std::string mnemonic() const;
};

class Arm64Decoder {
public:
    // Decode one 4-byte instruction at the given address
    Arm64Insn decode(const uint8_t* pc, uint64_t vaddr) const;

private:
    Arm64Insn decode_data_proc_imm(uint32_t insn, uint64_t pc) const;
    Arm64Insn decode_data_proc_reg(uint32_t insn, uint64_t pc) const;
    Arm64Insn decode_loads_stores(uint32_t insn, uint64_t pc) const;
    Arm64Insn decode_branches(uint32_t insn, uint64_t pc) const;
};
