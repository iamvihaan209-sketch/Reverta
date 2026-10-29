#pragma once
#include <cstdint>
#include <string>

// AArch64 instruction types we handle
enum class Arm64Op {
    // Data processing - MOV/immediate
    MOV_REG, MOV_IMM,
    MOVK,     // read-modify-write: replaces one 16-bit field, keeps the rest of Rd
    // PC-relative addressing
    ADR, ADRP,
    // Data processing - arithmetic
    ADD_REG, ADD_IMM, ADD_EXT,          // ADD_EXT: extended-register form
    SUB_REG, SUB_IMM, SUB_EXT,
    ADC, SBC,                           // add/subtract with carry
    MUL,                                // MADD with Ra = XZR
    MADD, MSUB,
    SMULL, UMULL,                       // SMADDL/UMADDL with Ra = XZR
    SMADDL, SMSUBL, UMADDL, UMSUBL,
    SMULH, UMULH,
    UDIV, SDIV,
    // Data processing - logical
    AND_REG, AND_IMM,
    ORR_REG, ORR_IMM,
    EOR_REG, EOR_IMM,
    BIC_REG, ORN_REG, EON_REG,          // inverted-operand forms (N bit set)
    // Data processing - shifts (variable forms use LSLV/LSRV/ASRV/RORV)
    LSL_IMM, LSL_REG,
    LSR_IMM, LSR_REG,
    ASR_IMM, ASR_REG,
    ROR_IMM, ROR_REG,
    // Data processing - compare & test
    CMP_REG, CMP_IMM,
    CMN_REG, CMN_IMM,
    TST_REG, TST_IMM,
    // Data processing - bitfield (UBFX, LSL, ... are aliases of these)
    UBFM, SBFM, BFM,
    EXTR,
    // Data processing - conditional
    CSEL, CSNEG, CSINC, CSINV,
    // Data processing - conditional compare
    CCMP_REG, CCMP_IMM, CCMN_REG, CCMN_IMM,
    // Data processing - CRC32 (B/H/W/X, and the Castagnoli CRC32C variants)
    CRC32B, CRC32H, CRC32W, CRC32X,
    CRC32CB, CRC32CH, CRC32CW, CRC32CX,
    // Data processing - bit and byte manipulation
    RBIT, REV16, REV, REV32, CLZ, CLS,
    // Floating point
    FADD, FSUB, FMUL, FDIV, FABS, FNEG, FCVT_SD, FCVT_DS,
    FCMP, FCMPE, FCSEL,
    FMOV, FMOV_IMM, FMOV_TO_GPR, FMOV_FROM_GPR,
    FSQRT, FMAX, FMIN,
    FCMP_ZERO, FCMPE_ZERO,              // FCMP Fn, #0.0 / FCMPE Fn, #0.0
    SCVTF, UCVTF,                       // integer -> FP (signed / unsigned)
    FCVTZS, FCVTZU,                     // FP -> integer, round toward zero
    FMADD, FMSUB, FNMADD, FNMSUB,       // fused three-source: Rd = +/-Ra +/- Rn*Rm
    // Load/Store
    // A single load or store is LDR_IMM/STR_IMM with access_bytes (register-offset
    // and literal forms set reg_offset / pc_literal).
    LDR_IMM, STR_IMM,
    LDRSB, LDRSH, LDRSW,                // sign-extending loads
    LDP, STP, LDPSW,                    // pairs (integer or SIMD&FP)
    LDEX, STEX, LDEXP, STEXP,           // exclusive monitor: LDXR/STXR and pairs
    CAS,                                // compare and swap
    SWP, LDADD, LDCLR, LDEOR, LDSET,    // LSE atomics (result = old value in Rt)
    LDSMAX, LDSMIN, LDUMAX, LDUMIN,
    VLD_MULT, VST_MULT,                 // Advanced SIMD LD1-LD4 / ST1-ST4, multiple structures
    VLD_LANE, VST_LANE,                 // Advanced SIMD single-lane LDn / STn
    VLD_REPL,                           // Advanced SIMD LD1R-LD4R (replicate)
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

// DecodeBitMasks from the Arm ARM. Returns false for reserved encodings. With
// immediate = true this is the logical-immediate form, which additionally
// rejects an all-ones element. wmask/tmask are replicated to the datasize.
bool arm64_decode_bit_masks(bool is64, uint32_t n, uint32_t imms, uint32_t immr,
                            bool immediate, uint64_t& wmask, uint64_t& tmask);

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
    uint8_t  move_shift = 0; // MOVZ/MOVN/MOVK: 16 * hw (0, 16, 32, 48)
    // Register operand modifiers. Shifted register: kind 0..3 = LSL/LSR/ASR/ROR,
    // amount = imm6. Extended register: kind = option (UXTB..SXTX), amount = imm3.
    uint8_t  shift_kind = 0;
    uint8_t  shift_amount = 0;
    uint8_t  ra = 31;        // third source register for 3-source multiplies
    uint8_t  access_bytes = 0; // memory operations: bytes per element (1..16)
    uint8_t  selem = 1;      // Advanced SIMD structures: registers per structure
    uint8_t  rpt = 1;        // Advanced SIMD multiple structures: repeat count
    uint8_t  lane = 0;       // Advanced SIMD single-lane: element index
    bool     vec_q = false;  // Advanced SIMD: 128-bit (Q=1) vector, else 64-bit
    bool     reg_offset = false;   // memory: address uses Rm (extended by shift_kind, << shift_amount)
    bool     pc_literal = false;   // memory: base is the instruction address (literal load)
    uint8_t  nzcv = 0;       // conditional compare: flags used when the condition fails
    uint8_t  immr = 0;       // bitfield: immr (UBFM/SBFM/BFM)
    uint8_t  imms = 0;       // bitfield: imms
    // Loads/stores: 0 = base + imm, 1 = pre-index (base += imm after access),
    // 2 = post-index (access at base, then base += imm).
    uint8_t  index_mode = 0;
    bool     gpr64 = false;  // integer-side width for int<->FP conversions (sf bit);
                             // is64 then names the FP precision (type bits)
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
