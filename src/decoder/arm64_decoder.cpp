#include "decoder/arm64_decoder.h"
#include <sstream>

// ── Bit extraction helpers ────────────────────────────────────────────────────
static inline uint32_t bits(uint32_t v, int hi, int lo) {
    return (v >> lo) & ((1u << (hi - lo + 1)) - 1);
}
static inline int32_t sign_extend(uint32_t v, int bits_count) {
    int shift = 32 - bits_count;
    return static_cast<int32_t>(v << shift) >> shift;
}

// ── Public decode entry ───────────────────────────────────────────────────────
Arm64Insn Arm64Decoder::decode(const uint8_t* pc, uint64_t vaddr) const {
    uint32_t insn = *reinterpret_cast<const uint32_t*>(pc);

    Arm64Insn out{};
    out.op = Arm64Op::UNKNOWN;  // any path that does not set op stays unknown
    out.raw  = insn;
    out.pc   = vaddr;
    out.op   = Arm64Op::UNKNOWN;
    out.is64 = true;

    // Top-level decode by op0 [28:25]
    uint32_t op0 = bits(insn, 28, 25);

    switch (op0) {
    case 0b1000: case 0b1001: // Data processing — immediate
        return decode_data_proc_imm(insn, vaddr);
    case 0b0101: case 0b1101: // Data processing — register
        return decode_data_proc_reg(insn, vaddr);
    case 0b0100: case 0b0110:
    case 0b1100: case 0b1110: // Loads and stores
        return decode_loads_stores(insn, vaddr);
    case 0b0010:
    case 0b1010: case 0b1011: // Branches, system, exceptions
        return decode_branches(insn, vaddr);
    case 0b1111: // Scalar FP / SIMD encoding space; decode only known scalar FP forms
        return decode_fp(insn, vaddr);
    default:
        break;
    }
    return out; // UNKNOWN
}

// ── Bit masks (DecodeBitMasks, Arm ARM) ──────────────────────────────────────
static uint64_t element_mask(uint32_t width) {
    return width >= 64 ? ~0ULL : ((1ULL << width) - 1);
}

bool arm64_decode_bit_masks(bool is64, uint32_t n, uint32_t imms, uint32_t immr,
                            bool immediate, uint64_t& wmask, uint64_t& tmask) {
    const uint32_t datasize = is64 ? 64 : 32;
    // len = HighestSetBit(N : NOT(imms)), a 7-bit value.
    const uint32_t len_src = (n << 6) | (~imms & 0x3F);
    int len = -1;
    for (int b = 6; b >= 0; --b) {
        if ((len_src >> b) & 1) { len = b; break; }
    }
    if (len < 1) return false;                   // element size must be >= 2
    const uint32_t esize = 1u << len;
    if (esize > datasize) return false;
    const uint32_t levels = esize - 1;
    const uint32_t S = imms & levels;
    const uint32_t R = immr & levels;
    if (immediate && S == levels) return false;  // all-ones element is not a logical immediate

    const uint32_t d = (S - R) & levels;         // low len bits of S - R
    const uint64_t emask = element_mask(esize);
    const uint64_t welem = element_mask(S + 1) & emask;
    const uint64_t telem = element_mask(d + 1) & emask;
    // Rotate the welem run right by R within the element.
    const uint64_t rotated = R == 0
        ? welem
        : (((welem >> R) | (welem << (esize - R))) & emask);

    auto replicate = [&](uint64_t elem) {
        uint64_t out = 0;
        for (uint32_t pos = 0; pos < datasize; pos += esize) out |= elem << pos;
        return out;
    };
    wmask = replicate(rotated);
    tmask = replicate(telem);
    return true;
}

static int64_t sign_extend64(uint64_t v, int width) {
    const int shift = 64 - width;
    return static_cast<int64_t>(v << shift) >> shift;
}

// ── Data processing — immediate ───────────────────────────────────────────────
Arm64Insn Arm64Decoder::decode_data_proc_imm(uint32_t insn, uint64_t pc) const {
    Arm64Insn out{};
    out.op = Arm64Op::UNKNOWN;  // any path that does not set op stays unknown
    out.raw = insn; out.pc = pc;
    out.is64 = bits(insn, 31, 31);
    out.rd = bits(insn, 4, 0);
    out.rn = bits(insn, 9, 5);

    const uint32_t op23 = bits(insn, 25, 23);
    switch (op23) {
    case 0b000:  // PC-relative: bits 25:23 = 00x, since immhi occupies those bits
    case 0b001: { // ADR (op=0) or ADRP (op=1, page-aligned)
        const uint32_t imm21 = (bits(insn, 23, 5) << 2) | bits(insn, 30, 29);
        out.is64 = true;
        if (bits(insn, 31, 31)) {
            out.op  = Arm64Op::ADRP;
            out.imm = sign_extend64(imm21, 21) << 12;
        } else {
            out.op  = Arm64Op::ADR;
            out.imm = sign_extend64(imm21, 21);
        }
        break;
    }
    case 0b010: { // Add/sub immediate
        const bool sub = bits(insn, 30, 30);
        const bool S   = bits(insn, 29, 29);
        const uint32_t imm12 = bits(insn, 21, 10);
        const bool sh = bits(insn, 22, 22);
        out.imm = static_cast<int64_t>(sh ? (static_cast<uint64_t>(imm12) << 12) : imm12);
        out.set_flags = S;
        if (S && out.rd == 31) {
            out.op = sub ? Arm64Op::CMP_IMM : Arm64Op::CMN_IMM;
        } else {
            out.op = sub ? Arm64Op::SUB_IMM : Arm64Op::ADD_IMM;
        }
        break;
    }
    case 0b100: { // Logical immediate
        const uint32_t opc = bits(insn, 30, 29);
        const uint32_t N = bits(insn, 22, 22);
        const uint32_t immr = bits(insn, 21, 16);
        const uint32_t imms = bits(insn, 15, 10);
        if (!out.is64 && N) break;               // reserved for 32-bit
        uint64_t wmask = 0, tmask = 0;
        if (!arm64_decode_bit_masks(out.is64, N, imms, immr, true, wmask, tmask)) break;
        out.imm = static_cast<int64_t>(wmask);
        out.set_flags = (opc == 0b11);
        switch (opc) {
        case 0b00: out.op = Arm64Op::AND_IMM; break;
        case 0b01: out.op = Arm64Op::ORR_IMM; break;
        case 0b10: out.op = Arm64Op::EOR_IMM; break;
        default:   // ANDS; with Rd = XZR it is TST
            out.op = (out.rd == 31) ? Arm64Op::TST_IMM : Arm64Op::AND_IMM;
            break;
        }
        break;
    }
    case 0b101: { // Move wide: MOVN (00), MOVZ (10), MOVK (11); 01 is reserved
        const uint32_t opc = bits(insn, 30, 29);
        const uint32_t imm16 = bits(insn, 20, 5);
        const uint32_t hw    = bits(insn, 22, 21);
        if (opc == 0b01 || (!out.is64 && hw > 1)) break;   // reserved
        out.move_shift = static_cast<uint8_t>(hw * 16);
        if (opc == 0b11) {
            out.imm = imm16;
            out.op  = Arm64Op::MOVK;
            break;
        }
        int64_t val = static_cast<int64_t>(static_cast<uint64_t>(imm16) << (hw * 16));
        if (opc == 0b00) val = ~val; // MOVN
        out.imm = val;
        out.op  = Arm64Op::MOV_IMM;
        break;
    }
    case 0b110: { // Bitfield: SBFM (00), BFM (01), UBFM (10); 11 is reserved
        const uint32_t opc = bits(insn, 30, 29);
        const uint32_t N = bits(insn, 22, 22);
        const uint32_t immr = bits(insn, 21, 16);
        const uint32_t imms = bits(insn, 15, 10);
        if (opc == 0b11 || N != out.is64) break;
        if (!out.is64 && (immr > 31 || imms > 31)) break;
        uint64_t wmask = 0, tmask = 0;
        if (!arm64_decode_bit_masks(out.is64, N, imms, immr, false, wmask, tmask)) break;
        out.immr = static_cast<uint8_t>(immr);
        out.imms = static_cast<uint8_t>(imms);
        out.op = opc == 0b00 ? Arm64Op::SBFM : opc == 0b01 ? Arm64Op::BFM : Arm64Op::UBFM;
        break;
    }
    case 0b111: { // Extract: EXTR (rm:rn >> lsb); the ROR alias is EXTR with Rn == Rm
        const uint32_t N = bits(insn, 22, 22);
        const uint32_t imms = bits(insn, 15, 10);
        if (bits(insn, 30, 29) != 0 || bits(insn, 21, 21) != 0) break;
        if (N != out.is64) break;
        if (!out.is64 && imms > 31) break;
        out.rm = bits(insn, 20, 16);
        out.imm = imms;
        out.op = Arm64Op::EXTR;
        break;
    }
    default:
        // 011 is unallocated.
        break;
    }
    return out;
}

// ── Data processing — register ────────────────────────────────────────────────
Arm64Insn Arm64Decoder::decode_data_proc_reg(uint32_t insn, uint64_t pc) const {
    Arm64Insn out{};
    out.op = Arm64Op::UNKNOWN;  // any path that does not set op stays unknown
    out.raw = insn; out.pc = pc;
    out.is64 = bits(insn, 31, 31);
    out.rd = bits(insn, 4, 0);
    out.rn = bits(insn, 9, 5);
    out.rm = bits(insn, 20, 16);

    const uint32_t op24 = bits(insn, 28, 24);
    const uint32_t S    = bits(insn, 29, 29);

    // Logical (shifted register): AND/ORR/EOR/ANDS, and BIC/ORN/EON/BICS when N=1.
    if (op24 == 0b01010) {
        const uint32_t opc    = bits(insn, 30, 29);
        const uint32_t N      = bits(insn, 21, 21);
        const uint32_t shift  = bits(insn, 23, 22);
        const uint32_t amount = bits(insn, 15, 10);
        if (!out.is64 && amount > 31) return out;
        out.shift_kind = static_cast<uint8_t>(shift);
        out.shift_amount = static_cast<uint8_t>(amount);
        out.set_flags = (opc == 0b11);
        static const Arm64Op plain[4]    = {Arm64Op::AND_REG, Arm64Op::ORR_REG, Arm64Op::EOR_REG, Arm64Op::AND_REG};
        static const Arm64Op inverted[4] = {Arm64Op::BIC_REG, Arm64Op::ORN_REG, Arm64Op::EON_REG, Arm64Op::BIC_REG};
        out.op = N ? inverted[opc] : plain[opc];
        if (opc == 0b11 && !N && out.rd == 31) out.op = Arm64Op::TST_REG;  // ANDS to XZR
        // MOV (register) is ORR Rd, XZR, Rm with no shift.
        if (opc == 0b01 && !N && out.rn == 31 && shift == 0 && amount == 0)
            out.op = Arm64Op::MOV_REG;
        return out;
    }

    // Add/subtract, shifted register (bit 21 = 0) or extended register (bit 21 = 1).
    if (op24 == 0b01011) {
        const bool sub = bits(insn, 30, 30);
        out.set_flags = S;
        if (bits(insn, 21, 21) == 0) {
            const uint32_t shift  = bits(insn, 23, 22);
            const uint32_t amount = bits(insn, 15, 10);
            if (shift == 0b11 || (!out.is64 && amount > 31)) return out;
            out.shift_kind = static_cast<uint8_t>(shift);
            out.shift_amount = static_cast<uint8_t>(amount);
            if (!sub) out.op = (S && out.rd == 31) ? Arm64Op::CMN_REG : Arm64Op::ADD_REG;
            else      out.op = (S && out.rd == 31) ? Arm64Op::CMP_REG : Arm64Op::SUB_REG;
        } else {
            const uint32_t option = bits(insn, 15, 13);
            const uint32_t imm3   = bits(insn, 12, 10);
            if (bits(insn, 23, 22) != 0 || imm3 > 4) return out;
            out.shift_kind = static_cast<uint8_t>(option);
            out.shift_amount = static_cast<uint8_t>(imm3);
            out.op = sub ? Arm64Op::SUB_EXT : Arm64Op::ADD_EXT;
        }
        return out;
    }

    // Add/subtract with carry (op24 = 11010, bits 23-21 = 000, bits 15-10 = 0).
    if (op24 == 0b11010 && bits(insn, 23, 21) == 0 && bits(insn, 15, 10) == 0) {
        out.set_flags = S;
        out.op = bits(insn, 30, 30) ? Arm64Op::SBC : Arm64Op::ADC;
        return out;
    }

    // Conditional select: CSEL, CSINC, CSINV, CSNEG.
    if (op24 == 0b11010 && bits(insn, 23, 21) == 0b100) {
        const uint32_t op2 = bits(insn, 11, 10);
        if (S || op2 > 1) return out;
        const uint32_t op = bits(insn, 30, 30);
        out.cond = static_cast<Arm64Cond>(bits(insn, 15, 12));
        if (op == 0) out.op = op2 ? Arm64Op::CSINC : Arm64Op::CSEL;
        else         out.op = op2 ? Arm64Op::CSNEG : Arm64Op::CSINV;
        return out;
    }

    // Two-source: UDIV/SDIV and variable shifts.
    if (op24 == 0b11010 && bits(insn, 23, 21) == 0b110 && bits(insn, 30, 29) == 0) {
        const uint32_t opc = bits(insn, 15, 10);
        if (opc >= 0b010000 && opc <= 0b010111) {
            // CRC32{B,H,W,X} (opc bit 2 = 0) and CRC32C{B,H,W,X} (bit 2 = 1).
            // X takes a 64-bit Rm and needs sf = 1; the others need sf = 0.
            const uint32_t kind = opc & 3;
            if ((kind == 3) != out.is64) return out;
            static const Arm64Op crc[2][4] = {
                {Arm64Op::CRC32B, Arm64Op::CRC32H, Arm64Op::CRC32W, Arm64Op::CRC32X},
                {Arm64Op::CRC32CB, Arm64Op::CRC32CH, Arm64Op::CRC32CW, Arm64Op::CRC32CX},
            };
            out.op = crc[(opc >> 2) & 1][kind];
            return out;
        }
        switch (opc) {
        case 0b000010: out.op = Arm64Op::UDIV; break;
        case 0b000011: out.op = Arm64Op::SDIV; break;
        case 0b001000: out.op = Arm64Op::LSL_REG; break;
        case 0b001001: out.op = Arm64Op::LSR_REG; break;
        case 0b001010: out.op = Arm64Op::ASR_REG; break;
        case 0b001011: out.op = Arm64Op::ROR_REG; break;
        default: break;
        }
        return out;
    }

    // One-source: RBIT, REV16, REV/REV32, CLZ.
    if (op24 == 0b11010 && bits(insn, 23, 21) == 0b110 && bits(insn, 30, 29) == 0b10
        && out.rm == 0) {
        const uint32_t opcode = bits(insn, 15, 10);
        switch (opcode) {
        case 0b000000: out.op = Arm64Op::RBIT; break;
        case 0b000001: out.op = Arm64Op::REV16; break;
        case 0b000010: out.op = out.is64 ? Arm64Op::REV32 : Arm64Op::REV; break;
        case 0b000011: if (out.is64) out.op = Arm64Op::REV; break;
        case 0b000100: out.op = Arm64Op::CLZ; break;
        case 0b000101: out.op = Arm64Op::CLS; break;
        default: break;
        }
        return out;
    }

    // Three-source: multiply-add family.
    if (op24 == 0b11011) {
        if (bits(insn, 30, 29) != 0) return out;
        const uint32_t op31 = bits(insn, 23, 21);
        const bool o0 = bits(insn, 15, 15);
        out.ra = static_cast<uint8_t>(bits(insn, 14, 10));
        switch (op31) {
        case 0b000:  // MADD / MSUB (32- or 64-bit)
            if (!o0 && out.ra == 31) out.op = Arm64Op::MUL;
            else out.op = o0 ? Arm64Op::MSUB : Arm64Op::MADD;
            break;
        case 0b001:  // SMADDL / SMSUBL (64-bit result from 32-bit sources)
            if (!out.is64) break;
            if (!o0 && out.ra == 31) out.op = Arm64Op::SMULL;
            else out.op = o0 ? Arm64Op::SMSUBL : Arm64Op::SMADDL;
            break;
        case 0b010:  // SMULH
            if (out.is64 && !o0 && out.ra == 31) out.op = Arm64Op::SMULH;
            break;
        case 0b101:  // UMADDL / UMSUBL
            if (!out.is64) break;
            if (!o0 && out.ra == 31) out.op = Arm64Op::UMULL;
            else out.op = o0 ? Arm64Op::UMSUBL : Arm64Op::UMADDL;
            break;
        case 0b110:  // UMULH
            if (out.is64 && !o0 && out.ra == 31) out.op = Arm64Op::UMULH;
            break;
        default: break;
        }
        return out;
    }

    // Conditional compare: sf op 1 11010010 Rm|imm5 cond 1 x 0 Rn 0 nzcv
    if (op24 == 0b11010 && bits(insn, 23, 21) == 0b010 && S
        && bits(insn, 10, 10) == 0 && bits(insn, 4, 4) == 0) {
        out.cond = static_cast<Arm64Cond>(bits(insn, 15, 12));
        out.nzcv = static_cast<uint8_t>(bits(insn, 3, 0));
        const bool ccmp = bits(insn, 30, 30);
        if (bits(insn, 11, 11)) {
            out.imm = bits(insn, 20, 16);
            out.op = ccmp ? Arm64Op::CCMP_IMM : Arm64Op::CCMN_IMM;
        } else {
            out.op = ccmp ? Arm64Op::CCMP_REG : Arm64Op::CCMN_REG;
        }
        return out;
    }

    return out;
}

// ── Scalar floating-point instructions ────────────────────────────────────────
Arm64Insn Arm64Decoder::decode_fp(uint32_t insn, uint64_t pc) const {
    Arm64Insn out{};
    out.op = Arm64Op::UNKNOWN;  // any path that does not set op stays unknown
    out.raw = insn;
    out.pc = pc;
    out.op = Arm64Op::UNKNOWN;
    out.rd = bits(insn, 4, 0);
    out.rn = bits(insn, 9, 5);
    out.rm = bits(insn, 20, 16);
    // Scalar type: 00 = S (32-bit), 01 = D (64-bit). Other types are unsupported.
    const uint32_t type = bits(insn, 23, 22);
    if (type > 1) return out;
    out.is64 = type == 1;

    // Three-source fused multiply-add: 0 00 11111 type o1 Rm o0 Ra Rn Rd (M must be 0).
    if ((insn & 0xFF000000) == 0x1F000000) {
        const uint32_t o1 = bits(insn, 21, 21);
        const uint32_t o0 = bits(insn, 15, 15);
        out.ra = static_cast<uint8_t>(bits(insn, 14, 10));
        if (o1 == 0) out.op = o0 ? Arm64Op::FMSUB : Arm64Op::FMADD;
        else         out.op = o0 ? Arm64Op::FNMSUB : Arm64Op::FNMADD;
        return out;
    }

    const uint32_t fadd_mask = insn & 0xFF20FC00;
    switch (fadd_mask) {
    case 0x1E202800: out.op = Arm64Op::FADD; return out;
    case 0x1E203800: out.op = Arm64Op::FSUB; return out;
    case 0x1E200800: out.op = Arm64Op::FMUL; return out;
    case 0x1E201800: out.op = Arm64Op::FDIV; return out;
    default: break;
    }

    if ((insn & 0xFF200C00) == 0x1E200C00) {
        out.op = Arm64Op::FCSEL;
        out.cond = static_cast<Arm64Cond>(bits(insn, 15, 12));
        return out;
    }
    if ((insn & 0xFFBFFC00) == 0x1E224000) {
        out.op = Arm64Op::FCVT_SD;
        out.is64 = false;
        return out;
    }
    if ((insn & 0xFFBFFC00) == 0x1E22C000) {
        out.op = Arm64Op::FCVT_DS;
        out.is64 = true;
        return out;
    }
    if ((insn & 0xFFBFFC00) == 0x1E20C000) {
        out.op = Arm64Op::FABS;
        return out;
    }
    if ((insn & 0xFFBFFC00) == 0x1E214000) {
        out.op = Arm64Op::FNEG;
        return out;
    }
    if ((insn & 0xFF20FC1F) == 0x1E202010) {
        out.op = Arm64Op::FCMPE;
        return out;
    }
    if ((insn & 0xFF20FC1F) == 0x1E202000) {
        out.op = Arm64Op::FCMP;
        return out;
    }
    // FMOV register: Rm and opcode fields are fixed; Rn/Rd select FP registers.
    if ((insn & 0xFFFFFC00) == 0x1E260000 ||
        (insn & 0xFFFFFC00) == 0x9E660000) {
        out.op = Arm64Op::FMOV_TO_GPR;
        out.is64 = ((insn >> 31) & 1) != 0;
        return out;
    }
    if ((insn & 0xFFFFFC00) == 0x1E270000 ||
        (insn & 0xFFFFFC00) == 0x9E670000) {
        out.op = Arm64Op::FMOV_FROM_GPR;
        out.is64 = ((insn >> 31) & 1) != 0;
        return out;
    }
    if ((insn & 0xFF201FE0) == 0x1E201000) {
        out.op = Arm64Op::FMOV_IMM;
        out.imm = bits(insn, 20, 13);
        return out;
    }
    if ((insn & 0xFFBFFC00) == 0x1E204000) {
        out.op = Arm64Op::FMOV;
        return out;
    }
    if ((insn & 0xFF3FFC00) == 0x1E21C000) {        // FSQRT Fd, Fn
        out.op = Arm64Op::FSQRT;
        return out;
    }
    if ((insn & 0xFF20FC00) == 0x1E204800) {        // FMAX Fd, Fn, Fm
        out.op = Arm64Op::FMAX;
        return out;
    }
    if ((insn & 0xFF20FC00) == 0x1E205800) {        // FMIN Fd, Fn, Fm
        out.op = Arm64Op::FMIN;
        return out;
    }
    if ((insn & 0xFF20FC1F) == 0x1E202008) {        // FCMP Fn, #0.0
        out.op = Arm64Op::FCMP_ZERO;
        return out;
    }
    if ((insn & 0xFF20FC1F) == 0x1E202018) {        // FCMPE Fn, #0.0
        out.op = Arm64Op::FCMPE_ZERO;
        return out;
    }
    // Integer <-> FP conversions: sf 0 0 11110 type 1 rmode opcode 000000 Rn Rd.
    // The rmode/opcode selector sits in bits 20-16 and sf (bit 31) is the integer width.
    if ((insn & 0x7F20FC00) == 0x1E200000) {
        out.gpr64 = ((insn >> 31) & 1) != 0;
        switch (bits(insn, 20, 16)) {
        case 0x02: out.op = Arm64Op::SCVTF;  return out;   // 00 010
        case 0x03: out.op = Arm64Op::UCVTF;  return out;   // 00 011
        case 0x18: out.op = Arm64Op::FCVTZS; return out;   // 11 000
        case 0x19: out.op = Arm64Op::FCVTZU; return out;   // 11 001
        default: break;
        }
    }
    return out;
}

// ── Loads and stores ──────────────────────────────────────────────────────────
// Top-level groups by bits 29:27: 001 exclusive/ordered/CAS, 011 literal,
// 101 pairs, 111 single register. Bit 26 is V (SIMD&FP register).
Arm64Insn Arm64Decoder::decode_loads_stores(uint32_t insn, uint64_t pc) const {
    Arm64Insn out{};
    out.op = Arm64Op::UNKNOWN;  // any path that does not set op stays unknown
    out.raw = insn; out.pc = pc;
    out.rd = bits(insn, 4, 0);
    out.rn = bits(insn, 9, 5);
    out.rm = bits(insn, 20, 16);

    const uint32_t size  = bits(insn, 31, 30);
    const bool     V     = bits(insn, 26, 26);
    const uint32_t group = bits(insn, 29, 27);
    const uint32_t opc   = bits(insn, 23, 22);
    const bool     load  = bits(insn, 22, 22);

    // ── Literal (PC-relative): opc 0 V 011 00 imm19 Rt ───────────────────────
    if (group == 0b011 && bits(insn, 25, 24) == 0) {
        out.pc_literal = true;
        out.imm = sign_extend64(bits(insn, 23, 5), 19) << 2;
        if (V) {
            if (size == 3) return out;                   // unallocated
            out.is_fp = true;
            out.access_bytes = static_cast<uint8_t>(4u << size);   // S, D, Q
            out.op = Arm64Op::LDR_IMM;
            return out;
        }
        if (size == 3) { out.op = Arm64Op::NOP; return out; }      // PRFM literal (hint)
        out.is64 = (size != 0);
        out.access_bytes = (size == 2) ? 4 : static_cast<uint8_t>(4u << size);
        out.op = (size == 2) ? Arm64Op::LDRSW : Arm64Op::LDR_IMM;
        return out;
    }

    // ── Exclusive, ordered and compare-and-swap: size 001 o2 L o1 Rs o0 Rt2 Rn Rt
    if (group == 0b001 && bits(insn, 24, 24) == 0 && !V) {
        const uint32_t o2 = bits(insn, 23, 23);
        const uint32_t o1 = bits(insn, 21, 21);
        const uint32_t rs = bits(insn, 20, 16);
        const uint32_t rt2 = bits(insn, 14, 10);
        out.ra = static_cast<uint8_t>(rt2);
        if (o2 == 0 && o1 == 0) {                        // exclusive single: LDXR/STXR (+A/L)
            if (load && rs != 31) return out;            // LDXR requires Rs = 11111
            out.is64 = (size == 3);
            out.access_bytes = static_cast<uint8_t>(1u << size);
            out.op = load ? Arm64Op::LDEX : Arm64Op::STEX;
            return out;
        }
        if (o2 == 0 && o1 == 1) {                        // exclusive pair: LDXP/STXP (size = 1x)
            if (size < 2) return out;
            out.is64 = (size == 3);
            out.access_bytes = out.is64 ? 8 : 4;
            out.op = load ? Arm64Op::LDEXP : Arm64Op::STEXP;
            return out;
        }
        if (o2 == 1 && o1 == 0) {                        // ordered: LDAR/STLR family
            if (rs != 31 || rt2 != 31) return out;
            out.is64 = (size == 3);
            out.access_bytes = static_cast<uint8_t>(1u << size);
            out.op = load ? Arm64Op::LDR_IMM : Arm64Op::STR_IMM;   // acquire/release ordering is a no-op here
            return out;
        }
        if (rt2 != 31) return out;                       // compare-and-swap: CAS{,A,L,AL}
        out.is64 = (size == 3);
        out.access_bytes = static_cast<uint8_t>(1u << size);
        out.op = Arm64Op::CAS;
        return out;
    }

    // ── Load/store pair: opc 0 V 101 mode L imm7 Rt2 Rn Rt ───────────────────
    // mode 000 = non-temporal, 001 = post-index, 010 = signed offset, 011 = pre-index.
    if (group == 0b101) {
        const uint32_t mode = bits(insn, 25, 23);
        if (mode != 0b000 && mode != 0b001 && mode != 0b010 && mode != 0b011) return out;
        if (size == 3) return out;
        uint32_t elem = 0;
        if (V) {
            out.is_fp = true;
            elem = 4u << size;                           // S, D, Q
        } else if (size == 1) {                          // LDPSW (load only)
            if (!load) return out;
            elem = 4;
            out.is64 = true;
        } else {
            elem = size == 2 ? 8 : 4;
            out.is64 = (size == 2);
        }
        out.access_bytes = static_cast<uint8_t>(elem);
        out.ra = static_cast<uint8_t>(bits(insn, 14, 10));       // Rt2
        out.imm = sign_extend64(bits(insn, 21, 15), 7) * static_cast<int64_t>(elem);
        out.index_mode = mode == 0b001 ? 2 : (mode == 0b011 ? 1 : 0);
        if (!V && size == 1) out.op = Arm64Op::LDPSW;
        else out.op = load ? Arm64Op::LDP : Arm64Op::STP;
        return out;
    }

    // ── Single register: size 111 V 00 ... ───────────────────────────────────
    if (group != 0b111) return out;

    // Atomic memory operations (LSE): size 111 V 00 A R 1 Rs o3 opc 00 Rn Rt.
    if (!V && bits(insn, 25, 24) == 0 && bits(insn, 21, 21) && bits(insn, 11, 10) == 0b00) {
        const uint32_t o3 = bits(insn, 15, 15);
        const uint32_t aop = bits(insn, 14, 12);
        out.is64 = (size == 3);
        out.access_bytes = static_cast<uint8_t>(1u << size);
        if (o3) {
            if (aop != 0) return out;
            out.op = Arm64Op::SWP;
        } else {
            static const Arm64Op ops[8] = {
                Arm64Op::LDADD, Arm64Op::LDCLR, Arm64Op::LDEOR, Arm64Op::LDSET,
                Arm64Op::LDSMAX, Arm64Op::LDSMIN, Arm64Op::LDUMAX, Arm64Op::LDUMIN,
            };
            out.op = ops[aop];
        }
        return out;
    }

    // PRFM / PRFUM are hints with no architectural effect.
    if (!V && size == 3 && opc == 0b10) {
        out.op = Arm64Op::NOP;
        return out;
    }

    // Sign-extending loads: opc 10 loads a 64-bit Rt, opc 11 a 32-bit Rt.
    const bool sign_extend_load = !V && opc >= 2;
    if (sign_extend_load && (size == 3 || (opc == 3 && size == 2))) return out;

    if (V) {
        // Scalar FP/SIMD register size: (opc<1>:size) selects B, H, S, D or Q.
        const uint32_t vcode = (bits(insn, 23, 23) << 2) | size;
        if (vcode > 4) return out;
        static const uint8_t bytes_for[5] = {1, 2, 4, 8, 16};
        out.is_fp = true;
        out.access_bytes = bytes_for[vcode];
    } else {
        out.access_bytes = static_cast<uint8_t>(1u << size);
        out.is64 = sign_extend_load ? (opc == 2) : (size == 3);
    }
    const bool is_load = V ? load : (sign_extend_load || opc == 1);

    if (bits(insn, 25, 24) == 0b01) {
        // Unsigned scaled 12-bit offset.
        out.imm = static_cast<int64_t>(bits(insn, 21, 10)) * out.access_bytes;
    } else if (bits(insn, 21, 21)) {
        // Register offset: LDR Rt, [Rn, Rm{, extend {#S}}]. option<1> must be 1.
        const uint32_t option = bits(insn, 15, 13);
        if (bits(insn, 11, 10) != 0b10 || (option & 2) == 0) return out;
        out.reg_offset = true;
        out.shift_kind = static_cast<uint8_t>(option);
        const bool scaled = bits(insn, 12, 12);
        uint32_t shift = 0;
        for (unsigned s = out.access_bytes; s > 1; s >>= 1) ++shift;
        out.shift_amount = scaled ? static_cast<uint8_t>(shift) : 0;
    } else {
        // Unscaled (LDUR/STUR), pre-index, post-index and unprivileged share bits 25:24 = 00.
        const uint32_t idx = bits(insn, 11, 10);
        out.imm = sign_extend64(bits(insn, 20, 12), 9);
        out.index_mode = idx == 0b01 ? 2 : (idx == 0b11 ? 1 : 0);   // 10 (LDTR) is a plain access at EL0
    }

    if (sign_extend_load) {
        out.op = size == 0 ? Arm64Op::LDRSB : size == 1 ? Arm64Op::LDRSH : Arm64Op::LDRSW;
    } else {
        out.op = is_load ? Arm64Op::LDR_IMM : Arm64Op::STR_IMM;
    }
    return out;
}

// ── Branches / system / exceptions ───────────────────────────────────────────
Arm64Insn Arm64Decoder::decode_branches(uint32_t insn, uint64_t pc) const {
    Arm64Insn out{};
    out.op = Arm64Op::UNKNOWN;  // any path that does not set op stays unknown
    out.raw = insn; out.pc = pc;
    out.is64 = true;

    if (insn == 0xD503201F) { out.op = Arm64Op::NOP; return out; }

    // Unconditional branch (immediate) — B / BL
    if ((insn >> 26) == 0b000101 || (insn >> 26) == 0b100101) {
        bool link = bits(insn, 31, 31);
        int32_t imm26 = sign_extend(bits(insn, 25, 0), 26);
        out.imm = (int64_t)imm26 * 4;
        out.op  = link ? Arm64Op::BL : Arm64Op::B;
        return out;
    }

    // Conditional branch B.cond
    if ((insn >> 24) == 0b01010100) {
        int32_t imm19 = sign_extend(bits(insn, 23, 5), 19);
        out.imm = (int64_t)imm19 * 4;
        out.cond = static_cast<Arm64Cond>(bits(insn, 3, 0));
        out.op   = Arm64Op::B_COND;
        return out;
    }

    // CBZ / CBNZ
    if ((insn >> 25) == 0b0110100 || (insn >> 25) == 0b0110101) {
        bool nz = bits(insn, 24, 24);
        out.rd  = bits(insn, 4, 0);
        int32_t imm19 = sign_extend(bits(insn, 23, 5), 19);
        out.imm = (int64_t)imm19 * 4;
        out.op  = nz ? Arm64Op::CBNZ : Arm64Op::CBZ;
        out.is64 = bits(insn, 31, 31);
        return out;
    }

    // TBZ / TBNZ
    if ((insn >> 25) == 0b0110110 || (insn >> 25) == 0b0110111) {
        bool nz = bits(insn, 24, 24);
        out.rd  = bits(insn, 4, 0);
        out.bit_pos = bits(insn, 23, 19) | (bits(insn, 31, 31) << 5);
        int32_t imm14 = sign_extend(bits(insn, 18, 5), 14);
        out.imm = (int64_t)imm14 * 4;
        out.op  = nz ? Arm64Op::TBNZ : Arm64Op::TBZ;
        return out;
    }

    // Unconditional branch (register) — BLR, BR, RET
    if ((insn >> 25) == 0b1101011) {
        uint32_t opc = bits(insn, 22, 21);
        out.rn = bits(insn, 9, 5);
        switch (opc) {
        case 0b00: out.op = Arm64Op::BR;  break;
        case 0b01: out.op = Arm64Op::BLR; break;
        case 0b10: out.op = Arm64Op::RET; break;
        default:   out.op = Arm64Op::UNKNOWN;
        }
        return out;
    }

    // SVC
    if ((insn >> 21) == 0b11010100000) {
        out.imm = bits(insn, 20, 5);
        out.op  = Arm64Op::SVC;
        return out;
    }

    out.op = Arm64Op::UNKNOWN;
    return out;
}

// ── Mnemonic for debug ────────────────────────────────────────────────────────
std::string Arm64Insn::mnemonic() const {
    // A switch rather than a parallel name array: -Wswitch flags any new Arm64Op
    // that lacks a name, instead of silently shifting every later name.
    const char* name = "???";
    switch (op) {
    case Arm64Op::MOV_REG: case Arm64Op::MOV_IMM: name = "mov"; break;
    case Arm64Op::MOVK: name = "movk"; break;
    case Arm64Op::ADD_REG: case Arm64Op::ADD_IMM: name = "add"; break;
    case Arm64Op::SUB_REG: case Arm64Op::SUB_IMM: name = "sub"; break;
    case Arm64Op::MUL: name = "mul"; break;
    case Arm64Op::SMULL: name = "smull"; break;
    case Arm64Op::UMULL: name = "umull"; break;
    case Arm64Op::AND_REG: case Arm64Op::AND_IMM: name = "and"; break;
    case Arm64Op::ORR_REG: case Arm64Op::ORR_IMM: name = "orr"; break;
    case Arm64Op::EOR_REG: case Arm64Op::EOR_IMM: name = "eor"; break;
    case Arm64Op::LSL_IMM: case Arm64Op::LSL_REG: name = "lsl"; break;
    case Arm64Op::LSR_IMM: case Arm64Op::LSR_REG: name = "lsr"; break;
    case Arm64Op::ASR_IMM: case Arm64Op::ASR_REG: name = "asr"; break;
    case Arm64Op::ROR_IMM: case Arm64Op::ROR_REG: name = "ror"; break;
    case Arm64Op::CMP_REG: case Arm64Op::CMP_IMM: name = "cmp"; break;
    case Arm64Op::CMN_REG: case Arm64Op::CMN_IMM: name = "cmn"; break;
    case Arm64Op::TST_REG: case Arm64Op::TST_IMM: name = "tst"; break;
    case Arm64Op::ADR: name = "adr"; break;
    case Arm64Op::ADRP: name = "adrp"; break;
    case Arm64Op::ADD_EXT: name = "add"; break;
    case Arm64Op::SUB_EXT: name = "sub"; break;
    case Arm64Op::ADC: name = "adc"; break;
    case Arm64Op::SBC: name = "sbc"; break;
    case Arm64Op::MADD: name = "madd"; break;
    case Arm64Op::MSUB: name = "msub"; break;
    case Arm64Op::SMADDL: name = "smaddl"; break;
    case Arm64Op::SMSUBL: name = "smsubl"; break;
    case Arm64Op::UMADDL: name = "umaddl"; break;
    case Arm64Op::UMSUBL: name = "umsubl"; break;
    case Arm64Op::SMULH: name = "smulh"; break;
    case Arm64Op::UMULH: name = "umulh"; break;
    case Arm64Op::UDIV: name = "udiv"; break;
    case Arm64Op::SDIV: name = "sdiv"; break;
    case Arm64Op::BIC_REG: name = "bic"; break;
    case Arm64Op::ORN_REG: name = "orn"; break;
    case Arm64Op::EON_REG: name = "eon"; break;
    case Arm64Op::CSINV: name = "csinv"; break;
    case Arm64Op::UBFM: name = "ubfm"; break;
    case Arm64Op::SBFM: name = "sbfm"; break;
    case Arm64Op::BFM: name = "bfm"; break;
    case Arm64Op::EXTR: name = "extr"; break;
    case Arm64Op::RBIT: name = "rbit"; break;
    case Arm64Op::REV16: name = "rev16"; break;
    case Arm64Op::REV: name = "rev"; break;
    case Arm64Op::REV32: name = "rev32"; break;
    case Arm64Op::CLZ: name = "clz"; break;
    case Arm64Op::CLS: name = "cls"; break;
    case Arm64Op::CCMP_REG: case Arm64Op::CCMP_IMM: name = "ccmp"; break;
    case Arm64Op::CCMN_REG: case Arm64Op::CCMN_IMM: name = "ccmn"; break;
    case Arm64Op::CRC32B: name = "crc32b"; break;
    case Arm64Op::CRC32H: name = "crc32h"; break;
    case Arm64Op::CRC32W: name = "crc32w"; break;
    case Arm64Op::CRC32X: name = "crc32x"; break;
    case Arm64Op::CRC32CB: name = "crc32cb"; break;
    case Arm64Op::CRC32CH: name = "crc32ch"; break;
    case Arm64Op::CRC32CW: name = "crc32cw"; break;
    case Arm64Op::CRC32CX: name = "crc32cx"; break;
    case Arm64Op::LDRSB: name = "ldrsb"; break;
    case Arm64Op::LDRSH: name = "ldrsh"; break;
    case Arm64Op::LDRSW: name = "ldrsw"; break;
    case Arm64Op::FMADD: name = "fmadd"; break;
    case Arm64Op::FMSUB: name = "fmsub"; break;
    case Arm64Op::FNMADD: name = "fnmadd"; break;
    case Arm64Op::FNMSUB: name = "fnmsub"; break;
    case Arm64Op::CSEL: name = "csel"; break;
    case Arm64Op::CSNEG: name = "csneg"; break;
    case Arm64Op::CSINC: name = "csinc"; break;
    case Arm64Op::FADD: name = "fadd"; break;
    case Arm64Op::FSUB: name = "fsub"; break;
    case Arm64Op::FMUL: name = "fmul"; break;
    case Arm64Op::FDIV: name = "fdiv"; break;
    case Arm64Op::FABS: name = "fabs"; break;
    case Arm64Op::FNEG: name = "fneg"; break;
    case Arm64Op::FCVT_SD: case Arm64Op::FCVT_DS: name = "fcvt"; break;
    case Arm64Op::FCMP: name = "fcmp"; break;
    case Arm64Op::FCMPE: name = "fcmpe"; break;
    case Arm64Op::FCSEL: name = "fcsel"; break;
    case Arm64Op::FMOV: case Arm64Op::FMOV_IMM: case Arm64Op::FMOV_TO_GPR:
    case Arm64Op::FMOV_FROM_GPR: name = "fmov"; break;
    case Arm64Op::LDR_IMM: name = "ldr"; break;
    case Arm64Op::STR_IMM: name = "str"; break;
    case Arm64Op::LDP: name = "ldp"; break;
    case Arm64Op::STP: name = "stp"; break;
    case Arm64Op::LDPSW: name = "ldpsw"; break;
    case Arm64Op::LDEX: name = "ldxr"; break;
    case Arm64Op::STEX: name = "stxr"; break;
    case Arm64Op::LDEXP: name = "ldxp"; break;
    case Arm64Op::STEXP: name = "stxp"; break;
    case Arm64Op::CAS: name = "cas"; break;
    case Arm64Op::SWP: name = "swp"; break;
    case Arm64Op::LDADD: name = "ldadd"; break;
    case Arm64Op::LDCLR: name = "ldclr"; break;
    case Arm64Op::LDEOR: name = "ldeor"; break;
    case Arm64Op::LDSET: name = "ldset"; break;
    case Arm64Op::LDSMAX: name = "ldsmax"; break;
    case Arm64Op::LDSMIN: name = "ldsmin"; break;
    case Arm64Op::LDUMAX: name = "ldumax"; break;
    case Arm64Op::LDUMIN: name = "ldumin"; break;
    case Arm64Op::B: name = "b"; break;
    case Arm64Op::BL: name = "bl"; break;
    case Arm64Op::BLR: name = "blr"; break;
    case Arm64Op::BR: name = "br"; break;
    case Arm64Op::RET: name = "ret"; break;
    case Arm64Op::B_COND: name = "b.cond"; break;
    case Arm64Op::CBZ: name = "cbz"; break;
    case Arm64Op::CBNZ: name = "cbnz"; break;
    case Arm64Op::TBZ: name = "tbz"; break;
    case Arm64Op::TBNZ: name = "tbnz"; break;
    case Arm64Op::SVC: name = "svc"; break;
    case Arm64Op::NOP: name = "nop"; break;
    case Arm64Op::FSQRT: name = "fsqrt"; break;
    case Arm64Op::FMAX: name = "fmax"; break;
    case Arm64Op::FMIN: name = "fmin"; break;
    case Arm64Op::FCMP_ZERO: name = "fcmp"; break;
    case Arm64Op::FCMPE_ZERO: name = "fcmpe"; break;
    case Arm64Op::SCVTF: name = "scvtf"; break;
    case Arm64Op::UCVTF: name = "ucvtf"; break;
    case Arm64Op::FCVTZS: name = "fcvtzs"; break;
    case Arm64Op::FCVTZU: name = "fcvtzu"; break;
    case Arm64Op::UNKNOWN: break;
    }
    std::ostringstream oss;
    oss << name << "\t[raw=0x" << std::hex << raw << "]";
    return oss.str();
}
