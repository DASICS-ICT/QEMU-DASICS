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

static inline target_ulong dasics_mix_slot_master(target_ulong master,
                                                  uint32_t regno)
{
    target_ulong x = master ^ ((target_ulong)regno << 9);

    x = dasics_rotl_tl(x, 17) ^ (x >> 7);
    x *= (target_ulong)0xbf58476d1ce4e5b9ULL;
    x ^= x >> 29;
    x *= (target_ulong)0x94d049bb133111ebULL;
    x ^= x >> 31;

    return x;
}

static inline target_ulong dasics_sreg_prf_mask_a(uint32_t regno)
{
    return dasics_mix_slot_master((target_ulong)0x9e3779b97f4a7c15ULL, regno);
}

static inline target_ulong dasics_sreg_mac_tag_a(target_ulong cipher,
                                                 uint32_t regno)
{
    target_ulong tag = dasics_mix_slot_master((target_ulong)0x243f6a8885a308d3ULL,
                                              regno);

    tag ^= cipher;
    tag = dasics_rotl_tl(tag, 11) ^ (tag >> 5);
    tag *= (target_ulong)0xc4ceb9fe1a85ec53ULL;
    tag ^= tag >> 29;

    return tag;
}

void dasics_sreg_crypto_seal_a(target_ulong plain, uint32_t regno,
                               target_ulong *cipher_out, target_ulong *tag_out)
{
    target_ulong mask = dasics_sreg_prf_mask_a(regno);
    *cipher_out = plain ^ mask;
    *tag_out = dasics_sreg_mac_tag_a(*cipher_out, regno);
}

int dasics_sreg_crypto_open_a(target_ulong cipher_in, uint32_t regno,
                              target_ulong tag_in,
                              target_ulong *plain_out)
{
    target_ulong expect_tag = dasics_sreg_mac_tag_a(cipher_in, regno);
    target_ulong mask;

    if (expect_tag != tag_in) {
        return DASICS_SREG_CRYPTO_ERR_AUTH;
    }

    mask = dasics_sreg_prf_mask_a(regno);
    *plain_out = cipher_in ^ mask;
    return DASICS_SREG_CRYPTO_OK;
}
