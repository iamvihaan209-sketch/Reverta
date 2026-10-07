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
    default:
        break;
    }
    return out; // UNKNOWN
}

// ── Data processing — immediate ───────────────────────────────────────────────
Arm64Insn Arm64Decoder::decode_data_proc_imm(uint32_t insn, uint64_t pc) const {
    Arm64Insn out{};
    out.raw = insn; out.pc = pc;

    uint32_t op23 = bits(insn, 25, 23);
    out.is64 = bits(insn, 31, 31);

    switch (op23) {
    case 0b010: case 0b011: { // Add/sub immediate
        bool sub = bits(insn, 30, 30);
        bool S   = bits(insn, 29, 29);
        out.rd = bits(insn, 4, 0);
        out.rn = bits(insn, 9, 5);
        uint32_t imm12 = bits(insn, 21, 10);
        uint32_t shift = bits(insn, 23, 22);
        out.imm = (int64_t)(shift == 1 ? imm12 << 12 : imm12);
        out.set_flags = S;
        if (!sub) {
            out.op = (S && out.rd == 31) ? Arm64Op::CMP_IMM : Arm64Op::ADD_IMM;
        } else {
            out.op = (S && out.rd == 31) ? Arm64Op::CMP_IMM : Arm64Op::SUB_IMM;
            if (S && out.rd == 31) out.rd = 31;
        }
        break;
    }
    case 0b100: case 0b101: { // Move wide (MOVZ, MOVN, MOVK) — treat as MOV_IMM
        uint32_t opc = bits(insn, 30, 29);
        out.rd = bits(insn, 4, 0);
        uint32_t imm16 = bits(insn, 20, 5);
        uint32_t hw    = bits(insn, 22, 21);
        int64_t val = (int64_t)((uint64_t)imm16 << (hw * 16));
        if (opc == 0b00) val = ~val; // MOVN
        out.imm = val;
        out.op  = Arm64Op::MOV_IMM;
        break;
    }
    default:
        out.op = Arm64Op::UNKNOWN;
    }
    return out;
}

// ── Data processing — register ────────────────────────────────────────────────
Arm64Insn Arm64Decoder::decode_data_proc_reg(uint32_t insn, uint64_t pc) const {
    Arm64Insn out{};
    out.raw = insn; out.pc = pc;
    out.is64 = bits(insn, 31, 31);
    out.rd = bits(insn,  4,  0);
    out.rn = bits(insn,  9,  5);
    out.rm = bits(insn, 20, 16);
    out.set_flags = bits(insn, 29, 29);

    uint32_t op24 = bits(insn, 28, 24);

    // Logical shifted register / Add-sub shifted / etc.
    if ((op24 & 0b11000) == 0b01000) {
        // Add/sub shifted register [28:24] = 01011/01010/etc.
        bool sub = bits(insn, 30, 30);
        bool S   = bits(insn, 29, 29);
        uint32_t imm6 = bits(insn, 15, 10);
        uint32_t shift = bits(insn, 23, 22);
        out.imm = imm6;
        (void)shift; // TODO: apply shift
        if (!sub) {
            out.op = (S && out.rd == 31) ? Arm64Op::CMP_REG : Arm64Op::ADD_REG;
        } else {
            out.op = (S && out.rd == 31) ? Arm64Op::CMP_REG : Arm64Op::SUB_REG;
        }
    } else if ((op24 & 0b11111) == 0b11011) {
        // Data-processing 3-source (MUL etc.)
        out.op = Arm64Op::MUL;
    } else {
        // Logical shifted register
        uint32_t opc = bits(insn, 30, 29);
        // MOV (register) is ORR Xd, XZR, Xm
        if (opc == 0b01 && out.rn == 31 && bits(insn, 15, 10) == 0) {
            out.op = Arm64Op::MOV_REG;
        } else {
            switch (opc) {
            case 0b00: out.op = Arm64Op::AND_REG; break;
            case 0b01: out.op = Arm64Op::ORR_REG; break;
            case 0b10: out.op = Arm64Op::EOR_REG; break;
            default:   out.op = Arm64Op::UNKNOWN;
            }
        }
    }
    return out;
}

// ── Loads and stores ──────────────────────────────────────────────────────────
Arm64Insn Arm64Decoder::decode_loads_stores(uint32_t insn, uint64_t pc) const {
    Arm64Insn out{};
    out.raw = insn; out.pc = pc;
    out.rd = bits(insn,  4,  0);
    out.rn = bits(insn,  9,  5);
    out.rm = bits(insn, 20, 16);

    uint32_t op28_27 = bits(insn, 28, 27);
    uint32_t size    = bits(insn, 31, 30);
    bool     V       = bits(insn, 26, 26); // SIMD/FP
    bool     load    = bits(insn, 22, 22);
    (void)V;

    out.is64 = (size == 3);

    // LDP / STP — [29:28]=10, [27:26]=10
    if (op28_27 == 0b10 && bits(insn, 27, 26) == 0b10) {
        out.op = load ? Arm64Op::LDP : Arm64Op::STP;
        int32_t imm7 = sign_extend(bits(insn, 21, 15), 7);
        out.imm = (int64_t)imm7 * (out.is64 ? 8 : 4);
        return out;
    }

    // Load/Store register (unsigned immediate)
    int32_t imm12 = (int32_t)bits(insn, 21, 10);
    int scale = (size == 3) ? 3 : (int)size;
    out.imm = (int64_t)(imm12 << scale);

    switch (size) {
    case 0: out.op = load ? Arm64Op::LDRB : Arm64Op::STRB; break;
    case 1: out.op = load ? Arm64Op::LDRH : Arm64Op::STRH; break;
    case 2: case 3:
        out.op = load ? Arm64Op::LDR_IMM : Arm64Op::STR_IMM;
        break;
    }
    return out;
}

// ── Branches / system / exceptions ───────────────────────────────────────────
Arm64Insn Arm64Decoder::decode_branches(uint32_t insn, uint64_t pc) const {
    Arm64Insn out{};
    out.raw = insn; out.pc = pc;
    out.is64 = true;

    uint32_t op31 = bits(insn, 31, 29);
    uint32_t op26 = bits(insn, 26, 26);

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
    static const char* names[] = {
        "mov","mov","add","add","sub","sub","mul",
        "and","and","orr","orr","eor","eor",
        "lsl","lsr","asr","cmp","cmp",
        "ldr","ldr","str","str","ldp","stp",
        "ldrb","strb","ldrh","strh",
        "b","bl","blr","br","ret","b.cond","cbz","cbnz","tbz","tbnz",
        "svc","nop","???"
    };
    int idx = static_cast<int>(op);
    if (idx < 0 || idx > static_cast<int>(Arm64Op::UNKNOWN)) idx = static_cast<int>(Arm64Op::UNKNOWN);
    std::ostringstream oss;
    oss << names[idx] << "\t[raw=0x" << std::hex << raw << "]";
    return oss.str();
}
