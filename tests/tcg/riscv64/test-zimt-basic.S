/*
 * Basic Zimt system test:
 * - gentag/settag/checktag execution path
 * - count=0 means 16 chunks for settag/checktag
 * - mismatch raises SW_CHECK with tval=4
 */

    .option norvc

    .equ CSR_MTVEC,   0x305
    .equ CSR_MCAUSE,  0x342
    .equ CSR_MTVAL,   0x343
    .equ CSR_MVITT,   0x381

    .equ EXPECT_CAUSE_SW_CHECK, 0x12
    .equ EXPECT_TVAL_MTE,       4

    .text
    .globl _start
_start:
    lla t0, trap_handler
    csrw CSR_MTVEC, t0

    /* Point MVITT at aligned tag storage. */
    lla t0, tag_region
    csrw CSR_MVITT, t0

    /* t1 = untagged data pointer */
    lla t1, data_region

    /*
     * gentag t1
     * Encoding: zimt_tagop rd=t1, rs1=x0, imm4=0
     */
    .word 0x86004373

    /*
     * settag rs1=t1, count=0 -> 16 chunks
     * Encoding: zimt_settag rs1=t1, imm4=0
     */
    .word 0x82034073

    /* Corrupt the tag of chunk #15 so checktag(count=0) must fault. */
    lla t2, data_region
    li t3, (15 * 16)
    add t2, t2, t3
    srli t2, t2, 4
    lla t4, tag_region
    add t4, t4, t2
    lbu t5, 0(t4)
    xori t5, t5, 1
    sb t5, 0(t4)

    /*
     * checktag rd=x0, rs1=t1, count=0 -> 16 chunks.
     * Should trap before we reach fail_path.
     */
    .word 0x86034073

fail_path:
    li a0, 1
    j _exit

trap_handler:
    csrr t0, CSR_MCAUSE
    li t1, EXPECT_CAUSE_SW_CHECK
    bne t0, t1, fail_path

    csrr t0, CSR_MTVAL
    li t1, EXPECT_TVAL_MTE
    bne t0, t1, fail_path

    li a0, 0
    j _exit

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

    .balign 4096
tag_region:
    .space 4096

    .balign 4096
data_region:
    .space 4096

    .data
    .balign 8
semiargs:
    .space 16
