#ifndef RISCV_DASICS_CRYPTO_H
#define RISCV_DASICS_CRYPTO_H

#include "qemu/osdep.h"
#include "cpu.h"

#define DASICS_SREG_CRYPTO_OK         0
#define DASICS_SREG_CRYPTO_ERR_PARAM -1
#define DASICS_SREG_CRYPTO_ERR_AUTH  -2

void dasics_sreg_crypto_seal_a(target_ulong plain, uint32_t regno,
                               target_ulong *cipher_out, target_ulong *tag_out);

int dasics_sreg_crypto_open_a(target_ulong cipher_in, uint32_t regno,
                              target_ulong tag_in,
                              target_ulong *plain_out);

#endif
