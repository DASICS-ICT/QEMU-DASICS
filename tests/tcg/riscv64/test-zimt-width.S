/*
 * Zimt width test:
 * - MT_MODE=2 (4-bit) and MT_MODE=3 (8-bit/7-bit pointer tag) paths.
 * - verifies address bits outside tag field are preserved by gentag.
 */

    .option norvc

    .equ CSR_MSECCFG, 0x747
    .equ MSECCFG_MT_MODE_MASK, 0x0000000c00000000
    .equ MSECCFG_MT_MODE_2,    0x0000000800000000
    .equ MSECCFG_MT_MODE_3,    0x0000000c00000000

    .text
    .globl _start
_start:
    /* MT_MODE=2 */
    csrr t0, CSR_MSECCFG
    li t1, 0xfffffff3ffffffff
    and t0, t0, t1
    li t1, MSECCFG_MT_MODE_2
    or t0, t0, t1
    csrw CSR_MSECCFG, t0

    lla t2, ptr_base
    mv t3, t2
    /* gentag t3 (rd=t3, rs1=x0, imm4=0) */
    .word 0x86004e73

    /* low 60 bits must remain unchanged in 4-bit mode */
    li t4, 0x0fffffffffffffff
    and t5, t2, t4
    and t6, t3, t4
    bne t5, t6, fail

    /* MT_MODE=3 */
    csrr t0, CSR_MSECCFG
    li t1, 0xfffffff3ffffffff
    and t0, t0, t1
    li t1, MSECCFG_MT_MODE_3
    or t0, t0, t1
    csrw CSR_MSECCFG, t0

    mv t3, t2
    /* gentag t3 again */
    .word 0x86004e73

    /* low 57 bits must remain unchanged in 7-bit pointer-tag mode */
    li t4, 0x01ffffffffffffff
    and t5, t2, t4
    and t6, t3, t4
    bne t5, t6, fail

    li a0, 0
    j _exit

fail:
    li a0, 1

_exit:
    lla a1, semiargs
    li t0, 0x20026
    sd t0, 0(a1)
    sd a0, 8(a1)
    li a0, 0x20
    .balign 16
    slli zero, zero, 0x1f
    ebreak
    srai zero, zero, 0x7
    j .

    .balign 16
ptr_base:
    .dword 0

    .data
    .balign 8
semiargs:
    .space 16
