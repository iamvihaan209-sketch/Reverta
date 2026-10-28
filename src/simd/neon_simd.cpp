#include "simd/neon_simd.h"
#include <cstring>
#include <cstdint>
#include <algorithm>

// We use SSE2 intrinsics (guaranteed on x86-64) for correctness.
// On macOS with Clang, <immintrin.h> is always available.
#if defined(__x86_64__) || defined(_M_X64)
#  include <immintrin.h>
#  define USE_SSE2 1
#endif

namespace NeonSimd {

// ── helpers ──────────────────────────────────────────────────────────────────

#ifdef USE_SSE2
static inline __m128i load128(const uint64_t* p) {
    return _mm_loadu_si128(reinterpret_cast<const __m128i*>(p));
}
static inline void store128(uint64_t* p, __m128i v) {
    _mm_storeu_si128(reinterpret_cast<__m128i*>(p), v);
}
static inline __m128 loadf(const uint64_t* p) {
    return _mm_loadu_ps(reinterpret_cast<const float*>(p));
}
static inline void storef(uint64_t* p, __m128 v) {
    _mm_storeu_ps(reinterpret_cast<float*>(p), v);
}
static inline __m128d loadd(const uint64_t* p) {
    return _mm_loadu_pd(reinterpret_cast<const double*>(p));
}
static inline void stored(uint64_t* p, __m128d v) {
    _mm_storeu_pd(reinterpret_cast<double*>(p), v);
}
#endif

// ── integer add ──────────────────────────────────────────────────────────────

void vadd_u64(uint64_t* dst, const uint64_t* a, const uint64_t* b) {
#ifdef USE_SSE2
    store128(dst, _mm_add_epi64(load128(a), load128(b)));
#else
    dst[0] = a[0] + b[0]; dst[1] = a[1] + b[1];
#endif
}
void vadd_u32(uint64_t* dst, const uint64_t* a, const uint64_t* b) {
#ifdef USE_SSE2
    store128(dst, _mm_add_epi32(load128(a), load128(b)));
#else
    uint32_t *d=(uint32_t*)dst, *x=(uint32_t*)a, *y=(uint32_t*)b;
    for(int i=0;i<4;i++) d[i]=x[i]+y[i];
#endif
}
void vadd_u16(uint64_t* dst, const uint64_t* a, const uint64_t* b) {
#ifdef USE_SSE2
    store128(dst, _mm_add_epi16(load128(a), load128(b)));
#else
    uint16_t *d=(uint16_t*)dst, *x=(uint16_t*)a, *y=(uint16_t*)b;
    for(int i=0;i<8;i++) d[i]=x[i]+y[i];
#endif
}
void vadd_u8(uint64_t* dst, const uint64_t* a, const uint64_t* b) {
#ifdef USE_SSE2
    store128(dst, _mm_add_epi8(load128(a), load128(b)));
#else
    uint8_t *d=(uint8_t*)dst, *x=(uint8_t*)a, *y=(uint8_t*)b;
    for(int i=0;i<16;i++) d[i]=x[i]+y[i];
#endif
}

// ── integer subtract ─────────────────────────────────────────────────────────

void vsub_u64(uint64_t* dst, const uint64_t* a, const uint64_t* b) {
#ifdef USE_SSE2
    store128(dst, _mm_sub_epi64(load128(a), load128(b)));
#else
    dst[0]=a[0]-b[0]; dst[1]=a[1]-b[1];
#endif
}
void vsub_u32(uint64_t* dst, const uint64_t* a, const uint64_t* b) {
#ifdef USE_SSE2
    store128(dst, _mm_sub_epi32(load128(a), load128(b)));
#else
    uint32_t *d=(uint32_t*)dst,*x=(uint32_t*)a,*y=(uint32_t*)b;
    for(int i=0;i<4;i++) d[i]=x[i]-y[i];
#endif
}

// ── float add/sub/mul (f32) ───────────────────────────────────────────────────

void vfadd_f32(uint64_t* dst, const uint64_t* a, const uint64_t* b) {
#ifdef USE_SSE2
    storef(dst, _mm_add_ps(loadf(a), loadf(b)));
#else
    float *d=(float*)dst,*x=(float*)a,*y=(float*)b;
    for(int i=0;i<4;i++) d[i]=x[i]+y[i];
#endif
}
void vfsub_f32(uint64_t* dst, const uint64_t* a, const uint64_t* b) {
#ifdef USE_SSE2
    storef(dst, _mm_sub_ps(loadf(a), loadf(b)));
#else
    float *d=(float*)dst,*x=(float*)a,*y=(float*)b;
    for(int i=0;i<4;i++) d[i]=x[i]-y[i];
#endif
}
void vfmul_f32(uint64_t* dst, const uint64_t* a, const uint64_t* b) {
#ifdef USE_SSE2
    storef(dst, _mm_mul_ps(loadf(a), loadf(b)));
#else
    float *d=(float*)dst,*x=(float*)a,*y=(float*)b;
    for(int i=0;i<4;i++) d[i]=x[i]*y[i];
#endif
}

// ── float add/sub/mul (f64) ───────────────────────────────────────────────────

void vfadd_f64(uint64_t* dst, const uint64_t* a, const uint64_t* b) {
#ifdef USE_SSE2
    stored(dst, _mm_add_pd(loadd(a), loadd(b)));
#else
    double *d=(double*)dst,*x=(double*)a,*y=(double*)b;
    d[0]=x[0]+y[0]; d[1]=x[1]+y[1];
#endif
}
void vfsub_f64(uint64_t* dst, const uint64_t* a, const uint64_t* b) {
#ifdef USE_SSE2
    stored(dst, _mm_sub_pd(loadd(a), loadd(b)));
#else
    double *d=(double*)dst,*x=(double*)a,*y=(double*)b;
    d[0]=x[0]-y[0]; d[1]=x[1]-y[1];
#endif
}
void vfmul_f64(uint64_t* dst, const uint64_t* a, const uint64_t* b) {
#ifdef USE_SSE2
    stored(dst, _mm_mul_pd(loadd(a), loadd(b)));
#else
    double *d=(double*)dst,*x=(double*)a,*y=(double*)b;
    d[0]=x[0]*y[0]; d[1]=x[1]*y[1];
#endif
}

// ── bitwise ───────────────────────────────────────────────────────────────────

void vand(uint64_t* dst, const uint64_t* a, const uint64_t* b) {
#ifdef USE_SSE2
    store128(dst, _mm_and_si128(load128(a), load128(b)));
#else
    dst[0]=a[0]&b[0]; dst[1]=a[1]&b[1];
#endif
}
void vorr(uint64_t* dst, const uint64_t* a, const uint64_t* b) {
#ifdef USE_SSE2
    store128(dst, _mm_or_si128(load128(a), load128(b)));
#else
    dst[0]=a[0]|b[0]; dst[1]=a[1]|b[1];
#endif
}
void veor(uint64_t* dst, const uint64_t* a, const uint64_t* b) {
#ifdef USE_SSE2
    store128(dst, _mm_xor_si128(load128(a), load128(b)));
#else
    dst[0]=a[0]^b[0]; dst[1]=a[1]^b[1];
#endif
}

// ── shifts ────────────────────────────────────────────────────────────────────

void vshl_u32(uint64_t* dst, const uint64_t* a, int shift) {
#ifdef USE_SSE2
    store128(dst, _mm_slli_epi32(load128(a), shift));
#else
    uint32_t *d=(uint32_t*)dst,*x=(uint32_t*)a;
    for(int i=0;i<4;i++) d[i]=x[i]<<shift;
#endif
}
void vshr_u32(uint64_t* dst, const uint64_t* a, int shift) {
#ifdef USE_SSE2
    store128(dst, _mm_srli_epi32(load128(a), shift));
#else
    uint32_t *d=(uint32_t*)dst,*x=(uint32_t*)a;
    for(int i=0;i<4;i++) d[i]=x[i]>>shift;
#endif
}
void vshl_u64(uint64_t* dst, const uint64_t* a, int shift) {
#ifdef USE_SSE2
    store128(dst, _mm_slli_epi64(load128(a), shift));
#else
    dst[0]=a[0]<<shift; dst[1]=a[1]<<shift;
#endif
}
void vshr_u64(uint64_t* dst, const uint64_t* a, int shift) {
#ifdef USE_SSE2
    store128(dst, _mm_srli_epi64(load128(a), shift));
#else
    dst[0]=a[0]>>shift; dst[1]=a[1]>>shift;
#endif
}

// ── splat (DUP) ───────────────────────────────────────────────────────────────

void vdup_u32(uint64_t* dst, uint32_t scalar) {
#ifdef USE_SSE2
    store128(dst, _mm_set1_epi32((int)scalar));
#else
    uint32_t *d=(uint32_t*)dst;
    d[0]=d[1]=d[2]=d[3]=scalar;
#endif
}
void vdup_u64(uint64_t* dst, uint64_t scalar) {
#ifdef USE_SSE2
    store128(dst, _mm_set1_epi64x((long long)scalar));
#else
    dst[0]=dst[1]=scalar;
#endif
}
void vdup_f32(uint64_t* dst, float scalar) {
#ifdef USE_SSE2
    storef(dst, _mm_set1_ps(scalar));
#else
    float *d=(float*)dst; d[0]=d[1]=d[2]=d[3]=scalar;
#endif
}
void vdup_f64(uint64_t* dst, double scalar) {
#ifdef USE_SSE2
    stored(dst, _mm_set1_pd(scalar));
#else
    double *d=(double*)dst; d[0]=d[1]=scalar;
#endif
}

// ── load / store ──────────────────────────────────────────────────────────────

void vld1q(uint64_t* dst, const void* src) {
    std::memcpy(dst, src, 16);
}
void vst1q(void* dst, const uint64_t* src) {
    std::memcpy(dst, src, 16);
}

// ── convert ───────────────────────────────────────────────────────────────────

void vcvt_f32_u32(uint64_t* dst, const uint64_t* src) {
#ifdef USE_SSE2
    storef(dst, _mm_cvtepi32_ps(load128(src)));
#else
    float *d=(float*)dst; uint32_t *s=(uint32_t*)src;
    for(int i=0;i<4;i++) d[i]=(float)s[i];
#endif
}
void vcvt_u32_f32(uint64_t* dst, const uint64_t* src) {
#ifdef USE_SSE2
    store128(dst, _mm_cvttps_epi32(loadf(src)));
#else
    uint32_t *d=(uint32_t*)dst; float *s=(float*)src;
    for(int i=0;i<4;i++) d[i]=(uint32_t)s[i];
#endif
}
void vcvt_f64_f32(uint64_t* dst, const uint64_t* src) {
#ifdef USE_SSE2
    stored(dst, _mm_cvtps_pd(loadf(src)));
#else
    double *d=(double*)dst; float *s=(float*)src;
    d[0]=(double)s[0]; d[1]=(double)s[1];
#endif
}
void vcvt_f32_f64(uint64_t* dst, const uint64_t* src) {
#ifdef USE_SSE2
    storef(dst, _mm_cvtpd_ps(loadd(src)));
#else
    float *d=(float*)dst; double *s=(double*)src;
    d[0]=(float)s[0]; d[1]=(float)s[1]; d[2]=d[3]=0.f;
#endif
}

// ── zip / unzip ───────────────────────────────────────────────────────────────

void vzip1_u32(uint64_t* dst, const uint64_t* a, const uint64_t* b) {
#ifdef USE_SSE2
    store128(dst, _mm_unpacklo_epi32(load128(a), load128(b)));
#else
    uint32_t *d=(uint32_t*)dst,*x=(uint32_t*)a,*y=(uint32_t*)b;
    d[0]=x[0]; d[1]=y[0]; d[2]=x[1]; d[3]=y[1];
#endif
}
void vzip2_u32(uint64_t* dst, const uint64_t* a, const uint64_t* b) {
#ifdef USE_SSE2
    store128(dst, _mm_unpackhi_epi32(load128(a), load128(b)));
#else
    uint32_t *d=(uint32_t*)dst,*x=(uint32_t*)a,*y=(uint32_t*)b;
    d[0]=x[2]; d[1]=y[2]; d[2]=x[3]; d[3]=y[3];
#endif
}
void vuzp1_u32(uint64_t* dst, const uint64_t* a, const uint64_t* b) {
    uint32_t *d=(uint32_t*)dst,*x=(uint32_t*)a,*y=(uint32_t*)b;
    d[0]=x[0]; d[1]=x[2]; d[2]=y[0]; d[3]=y[2];
}
void vuzp2_u32(uint64_t* dst, const uint64_t* a, const uint64_t* b) {
    uint32_t *d=(uint32_t*)dst,*x=(uint32_t*)a,*y=(uint32_t*)b;
    d[0]=x[1]; d[1]=x[3]; d[2]=y[1]; d[3]=y[3];
}

// ── min / max ─────────────────────────────────────────────────────────────────

void vmin_u32(uint64_t* dst, const uint64_t* a, const uint64_t* b) {
#if defined(USE_SSE2) && defined(__SSE4_1__)
    store128(dst, _mm_min_epu32(load128(a), load128(b)));
#else
    uint32_t *d=(uint32_t*)dst,*x=(uint32_t*)a,*y=(uint32_t*)b;
    for(int i=0;i<4;i++) d[i]=std::min(x[i],y[i]);
#endif
}
void vmax_u32(uint64_t* dst, const uint64_t* a, const uint64_t* b) {
#if defined(USE_SSE2) && defined(__SSE4_1__)
    store128(dst, _mm_max_epu32(load128(a), load128(b)));
#else
    uint32_t *d=(uint32_t*)dst,*x=(uint32_t*)a,*y=(uint32_t*)b;
    for(int i=0;i<4;i++) d[i]=std::max(x[i],y[i]);
#endif
}
void vfmin_f32(uint64_t* dst, const uint64_t* a, const uint64_t* b) {
#ifdef USE_SSE2
    storef(dst, _mm_min_ps(loadf(a), loadf(b)));
#else
    float *d=(float*)dst,*x=(float*)a,*y=(float*)b;
    for(int i=0;i<4;i++) d[i]=std::min(x[i],y[i]);
#endif
}
void vfmax_f32(uint64_t* dst, const uint64_t* a, const uint64_t* b) {
#ifdef USE_SSE2
    storef(dst, _mm_max_ps(loadf(a), loadf(b)));
#else
    float *d=(float*)dst,*x=(float*)a,*y=(float*)b;
    for(int i=0;i<4;i++) d[i]=std::max(x[i],y[i]);
#endif
}
void vmin_s32(uint64_t* dst, const uint64_t* a, const uint64_t* b) {
#if defined(USE_SSE2) && defined(__SSE4_1__)
    store128(dst, _mm_min_epi32(load128(a), load128(b)));
#else
    int32_t *d=(int32_t*)dst,*x=(int32_t*)a,*y=(int32_t*)b;
    for(int i=0;i<4;i++) d[i]=std::min(x[i],y[i]);
#endif
}
void vmax_s32(uint64_t* dst, const uint64_t* a, const uint64_t* b) {
#if defined(USE_SSE2) && defined(__SSE4_1__)
    store128(dst, _mm_max_epi32(load128(a), load128(b)));
#else
    int32_t *d=(int32_t*)dst,*x=(int32_t*)a,*y=(int32_t*)b;
    for(int i=0;i<4;i++) d[i]=std::max(x[i],y[i]);
#endif
}

// ── compare ────────────────────────────────────────────────────────────────────

void vcmp_eq_u32(uint64_t* dst, const uint64_t* a, const uint64_t* b) {
#ifdef USE_SSE2
    store128(dst, _mm_cmpeq_epi32(load128(a), load128(b)));
#else
    uint32_t *d=(uint32_t*)dst,*x=(uint32_t*)a,*y=(uint32_t*)b;
    for(int i=0;i<4;i++) d[i]=(x[i]==y[i])?0xFFFFFFFF:0;
#endif
}
void vcmp_gt_s32(uint64_t* dst, const uint64_t* a, const uint64_t* b) {
#ifdef USE_SSE2
    store128(dst, _mm_cmpgt_epi32(load128(a), load128(b)));
#else
    int32_t *d=(int32_t*)dst,*x=(int32_t*)a,*y=(int32_t*)b;
    for(int i=0;i<4;i++) d[i]=(x[i]>y[i])?-1:0;
#endif
}
void vcmp_lt_s32(uint64_t* dst, const uint64_t* a, const uint64_t* b) {
#ifdef USE_SSE2
    store128(dst, _mm_cmplt_epi32(load128(a), load128(b)));
#else
    int32_t *d=(int32_t*)dst,*x=(int32_t*)a,*y=(int32_t*)b;
    for(int i=0;i<4;i++) d[i]=(x[i]<y[i])?-1:0;
#endif
}
void vcmp_eq_f32(uint64_t* dst, const uint64_t* a, const uint64_t* b) {
#ifdef USE_SSE2
    storef(dst, _mm_cmpeq_ps(loadf(a), loadf(b)));
#else
    float *d=(float*)dst,*x=(float*)a,*y=(float*)b;
    uint32_t *di=(uint32_t*)d;
    for(int i=0;i<4;i++) di[i]=(x[i]==y[i])?0xFFFFFFFFU:0;
#endif
}
void vcmp_gt_f32(uint64_t* dst, const uint64_t* a, const uint64_t* b) {
#ifdef USE_SSE2
    storef(dst, _mm_cmpgt_ps(loadf(a), loadf(b)));
#else
    float *d=(float*)dst,*x=(float*)a,*y=(float*)b;
    uint32_t *di=(uint32_t*)d;
    for(int i=0;i<4;i++) di[i]=(x[i]>y[i])?0xFFFFFFFFU:0;
#endif
}

// ── arithmetic saturation (addition/subtraction clamping) ─────────────────────

void vqadd_u32(uint64_t* dst, const uint64_t* a, const uint64_t* b) {
    // SSE2 has no unsigned saturating 32-bit add instruction. Keep the
    // lane-wise fallback for both SSE2 and scalar builds.
    uint32_t *d=(uint32_t*)dst,*x=(uint32_t*)a,*y=(uint32_t*)b;
    for(int i=0;i<4;i++) {
        uint64_t sum = (uint64_t)x[i] + y[i];
        d[i] = (sum > 0xFFFFFFFFU) ? 0xFFFFFFFFU : (uint32_t)sum;
    }
}
void vqsub_u32(uint64_t* dst, const uint64_t* a, const uint64_t* b) {
    // Unsigned saturating subtraction clamps underflow to zero.
    uint32_t *d=(uint32_t*)dst,*x=(uint32_t*)a,*y=(uint32_t*)b;
    for(int i=0;i<4;i++) {
        d[i] = (x[i] < y[i]) ? 0 : (x[i] - y[i]);
    }
}

} // namespace NeonSimd
