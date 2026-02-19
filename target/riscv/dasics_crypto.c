/*
 * RISC-V DASICS S-register crypto helpers (draft framework v1).
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "dasics_crypto.h"

static inline target_ulong dasics_rotl_tl(target_ulong v, unsigned s)
{
    const unsigned w = (unsigned)(sizeof(target_ulong) * 8);

    s %= w;
    if (s == 0) {
        return v;
    }
    return (v << s) | (v >> (w - s));
}

static inline target_ulong dasics_sreg_prf_mask_a(target_ulong addr, uint32_t regno,
                                                   target_ulong sp_off)
{
    target_ulong x = (target_ulong)0x9e3779b97f4a7c15ULL;

    x ^= addr;
    x ^= (target_ulong)regno << 8;
    x ^= sp_off;

    x = dasics_rotl_tl(x, 17) ^ (x >> 7);
    x *= (target_ulong)0xbf58476d1ce4e5b9ULL;
    x ^= x >> 29;
    x *= (target_ulong)0x94d049bb133111ebULL;
    x ^= x >> 31;

    return x;
}

static inline void dasics_sreg_mac_tag_a(target_ulong cipher, target_ulong addr,
                                         uint32_t regno, target_ulong sp_off,
                                         target_ulong *tag_lo, target_ulong *tag_hi)
{
    target_ulong lo = (target_ulong)0x243f6a8885a308d3ULL;
    target_ulong hi = (target_ulong)0x13198a2e03707344ULL;

    lo ^= cipher;
    lo ^= dasics_rotl_tl(addr, 13);
    lo ^= (target_ulong)regno << 16;
    lo ^= sp_off;

    hi ^= dasics_rotl_tl(cipher, 11);
    hi ^= addr;
    hi ^= dasics_rotl_tl(sp_off, 7);

    lo = (lo ^ (lo >> 33)) * (target_ulong)0xff51afd7ed558ccdULL;
    lo ^= lo >> 33;
    hi = (hi ^ (hi >> 33)) * (target_ulong)0xc4ceb9fe1a85ec53ULL;
    hi ^= hi >> 33;

    *tag_lo = lo;
    *tag_hi = hi;
}

void dasics_sreg_crypto_seal_a(target_ulong plain, target_ulong addr, uint32_t regno,
                               target_ulong sp_off, uint8_t tag_bits,
                               target_ulong *cipher_out, target_ulong *tag_lo_out,
                               target_ulong *tag_hi_out)
{
    target_ulong mask;
    target_ulong lo, hi;

    mask = dasics_sreg_prf_mask_a(addr, regno, sp_off);
    *cipher_out = plain ^ mask;

    dasics_sreg_mac_tag_a(*cipher_out, addr, regno, sp_off, &lo, &hi);
    *tag_lo_out = lo;
    *tag_hi_out = (tag_bits == 128) ? hi : 0;
}

int dasics_sreg_crypto_open_a(target_ulong cipher_in, target_ulong addr, uint32_t regno,
                              target_ulong sp_off, uint8_t tag_bits,
                              target_ulong tag_lo_in, target_ulong tag_hi_in,
                              target_ulong *plain_out)
{
    target_ulong expect_lo, expect_hi;
    target_ulong diff = 0;
    target_ulong mask;

    if (tag_bits != 64 && tag_bits != 128) {
        return DASICS_SREG_CRYPTO_ERR_PARAM;
    }

    dasics_sreg_mac_tag_a(cipher_in, addr, regno, sp_off, &expect_lo, &expect_hi);

    diff |= (expect_lo ^ tag_lo_in);
    if (tag_bits == 128) {
        diff |= (expect_hi ^ tag_hi_in);
    }
    if (diff != 0) {
        return DASICS_SREG_CRYPTO_ERR_AUTH;
    }

    mask = dasics_sreg_prf_mask_a(addr, regno, sp_off);
    *plain_out = cipher_in ^ mask;
    return DASICS_SREG_CRYPTO_OK;
}
