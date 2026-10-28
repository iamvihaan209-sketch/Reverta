#pragma once
#include <cstdint>
#include <string>

// AArch64 instruction types we handle
enum class Arm64Op {
    // Data processing - MOV/immediate
    MOV_REG, MOV_IMM,
    // Data processing - arithmetic
    ADD_REG, ADD_IMM,
    SUB_REG, SUB_IMM,
    MUL, SMULL, UMULL,
    // Data processing - logical
    AND_REG, AND_IMM,
    ORR_REG, ORR_IMM,
    EOR_REG, EOR_IMM,
    // Data processing - shifts
    LSL_IMM, LSL_REG,
    LSR_IMM, LSR_REG,
    ASR_IMM, ASR_REG,
    ROR_IMM, ROR_REG,
    // Data processing - compare & test
    CMP_REG, CMP_IMM,
    CMN_REG, CMN_IMM,
    TST_REG, TST_IMM,
    // Data processing - bitfield
    UBFX, SBFX, BFI,
    // Data processing - conditional
    CSEL, CSNEG, CSINC,
    // Floating point
    FADD, FSUB, FMUL, FDIV, FABS, FNEG, FCVT_SD, FCVT_DS,
    FCMP, FCMPE, FCSEL,
    FMOV, FMOV_IMM, FMOV_TO_GPR, FMOV_FROM_GPR,
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
    bool     is_fp;      // scalar floating-point register operand
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
    Arm64Insn decode_fp(uint32_t insn, uint64_t pc) const;
    Arm64Insn decode_loads_stores(uint32_t insn, uint64_t pc) const;
    Arm64Insn decode_branches(uint32_t insn, uint64_t pc) const;
};
