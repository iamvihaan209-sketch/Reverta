#pragma once
#include <cstdint>

// NEON → SSE/AVX mapping helpers
// CpuState stores SIMD regs as q[32][2] (two uint64_t = 128 bits each)
// These functions operate on raw pointers to those pairs.

namespace NeonSimd {

// 128-bit integer add (VADD.I64 / VADDQ)
void vadd_u64(uint64_t* dst, const uint64_t* a, const uint64_t* b);
void vadd_u32(uint64_t* dst, const uint64_t* a, const uint64_t* b);
void vadd_u16(uint64_t* dst, const uint64_t* a, const uint64_t* b);
void vadd_u8 (uint64_t* dst, const uint64_t* a, const uint64_t* b);

// 128-bit integer subtract
void vsub_u64(uint64_t* dst, const uint64_t* a, const uint64_t* b);
void vsub_u32(uint64_t* dst, const uint64_t* a, const uint64_t* b);

// 128-bit float add/sub/mul (single precision)
void vfadd_f32(uint64_t* dst, const uint64_t* a, const uint64_t* b);
void vfsub_f32(uint64_t* dst, const uint64_t* a, const uint64_t* b);
void vfmul_f32(uint64_t* dst, const uint64_t* a, const uint64_t* b);

// 128-bit double add/sub/mul
void vfadd_f64(uint64_t* dst, const uint64_t* a, const uint64_t* b);
void vfsub_f64(uint64_t* dst, const uint64_t* a, const uint64_t* b);
void vfmul_f64(uint64_t* dst, const uint64_t* a, const uint64_t* b);

// Bitwise
void vand(uint64_t* dst, const uint64_t* a, const uint64_t* b);
void vorr(uint64_t* dst, const uint64_t* a, const uint64_t* b);
void veor(uint64_t* dst, const uint64_t* a, const uint64_t* b);

// Shift (immediate, per lane)
void vshl_u32(uint64_t* dst, const uint64_t* a, int shift);
void vshr_u32(uint64_t* dst, const uint64_t* a, int shift);
void vshl_u64(uint64_t* dst, const uint64_t* a, int shift);
void vshr_u64(uint64_t* dst, const uint64_t* a, int shift);

// Splat scalar into all lanes (DUP / VDUP)
void vdup_u32(uint64_t* dst, uint32_t scalar);
void vdup_u64(uint64_t* dst, uint64_t scalar);
void vdup_f32(uint64_t* dst, float scalar);
void vdup_f64(uint64_t* dst, double scalar);

// Load / store 128-bit
void vld1q(uint64_t* dst, const void* src);
void vst1q(void* dst, const uint64_t* src);

// Convert
void vcvt_f32_u32(uint64_t* dst, const uint64_t* src); // uint→float
void vcvt_u32_f32(uint64_t* dst, const uint64_t* src); // float→uint (truncate)
void vcvt_f64_f32(uint64_t* dst, const uint64_t* src); // f32→f64 (low 2 lanes)
void vcvt_f32_f64(uint64_t* dst, const uint64_t* src); // f64→f32

// Zip / Unzip (interleave)
void vzip1_u32(uint64_t* dst, const uint64_t* a, const uint64_t* b);
void vzip2_u32(uint64_t* dst, const uint64_t* a, const uint64_t* b);
void vuzp1_u32(uint64_t* dst, const uint64_t* a, const uint64_t* b);
void vuzp2_u32(uint64_t* dst, const uint64_t* a, const uint64_t* b);

// Min / Max
void vmin_u32(uint64_t* dst, const uint64_t* a, const uint64_t* b);
void vmax_u32(uint64_t* dst, const uint64_t* a, const uint64_t* b);
void vfmin_f32(uint64_t* dst, const uint64_t* a, const uint64_t* b);
void vfmax_f32(uint64_t* dst, const uint64_t* a, const uint64_t* b);

} // namespace NeonSimd
