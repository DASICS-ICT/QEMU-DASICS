/*
 * DASICS S-mode CSR write protection, run bare-metal on the virt machine.
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Requires -cpu rv64,v=true. M-mode owns the test and checks exception cause,
 * fault PC, instruction bits, destination GPR, and unchanged CSR values.
 */
    .option norvc
    .option norelax
    .text
    .global _start

    .equ DSMCFG, 0xbc0
    .equ DSMLO, 0xbc2
    .equ DSMHI, 0xbc3
    .equ DLCFG, 0x880
    .equ DLLO, 0x890
    .equ DLHI, 0x891

/* Enter a test in S/U mode, returning to M-mode on ECALL. */
    .macro enter label, privilege=0x800
    la s10, 991f
    la t0, \label
    csrw mepc, t0
    li t0, 0x1800
    csrc mstatus, t0
    li t0, \privilege
    csrs mstatus, t0
    li s0, 0
    mret
991:
    .endm

/* All six opcodes and the zero-source/write-mask corner cases. */
    .macro denied csr, op, source, dest=a5
    csrr s3, \csr
    li a5, 0x123
    la s0, 991f
991:
    \op \dest, \csr, \source
    bnez s0, s_fail
    li t0, 0x123
    bne a5, t0, s_fail
    csrr a4, \csr
    bne a4, s3, s_fail
    .endm

    .macro deny_matrix csr
    li a3, 1
    denied \csr, csrrw, a3
    denied \csr, csrrs, a3
    denied \csr, csrrc, a3
    denied \csr, csrrwi, 1
    denied \csr, csrrsi, 1
    denied \csr, csrrci, 1
    denied \csr, csrrw, zero
    denied \csr, csrrwi, 0
    li a3, 0
    denied \csr, csrrs, a3
    denied \csr, csrrc, a3
    denied \csr, csrrw, zero, zero
    denied \csr, csrrwi, 0, zero
    denied \csr, csrrs, a3, zero
    denied \csr, csrrc, a3, zero
    /* Genuine read-only forms must still work, including rd=x0. */
    csrrs a4, \csr, zero
    bne a4, s3, s_fail
    csrrc a4, \csr, zero
    bne a4, s3, s_fail
    csrrsi a4, \csr, 0
    bne a4, s3, s_fail
    csrrci a4, \csr, 0
    bne a4, s3, s_fail
    csrrs zero, \csr, zero
    csrrc zero, \csr, zero
    csrrsi zero, \csr, 0
    csrrci zero, \csr, 0
    .endm

_start:
    la t0, m_trap
    csrw mtvec, t0
    csrw medeleg, zero
    csrw mideleg, zero
    csrw mie, zero
    /* Allow S/U access to RAM and enable FP/vector and counters. */
    li t0, -1
    csrw pmpaddr0, t0
    li t0, 0x1f
    csrw pmpcfg0, t0
    li t0, 0x6600
    csrs mstatus, t0
    li t0, 7
    csrw mcounteren, t0
    csrw scounteren, t0
    csrw DLLO, zero
    li t0, -1
    csrw DLHI, t0
    li t0, 0xb
    csrw DLCFG, t0
    /* Put test branches in a single active zone. */
    csrw 0x8c0, zero
    li t0, -1
    csrw 0x8c1, t0
    li t0, 1
    csrw 0x8c8, t0
    li s2, 0

    /* SENA on: trusted S-mode can still write. */
    la t0, allowed
    csrw DSMLO, t0
    la t0, allowed_end
    csrw DSMHI, t0
    /* Allow untrusted S-mode ECALLs to return to the M-mode harness. */
    li t0, 0x41
    csrw DSMCFG, t0
    enter allowed

    /* SENA off: the same code outside the trusted interval can write. */
    csrw DSMLO, zero
    csrw DSMHI, zero
    csrw DSMCFG, zero
    enter allowed

    /* SENA on does not restrict U-mode (UENA is off). */
    li t0, 0x41
    csrw DSMCFG, t0
    enter user_allowed, 0

    /* Untrusted S-mode: writes denied, reads allowed. H may be on or off. */
    enter untrusted
    li s11, 14 * 19
    bne s2, s11, m_fail
    /* HS is still S privilege, despite its higher CSR effective privilege. */
    csrr t0, misa
    andi t0, t0, 0x80
    beqz t0, 1f
    enter hs_untrusted
    addi s11, s11, 14 * 4
    bne s2, s11, m_fail
1:

    /* Sequential execution across both ends of a trusted interval.
     * A stale env->pc/TB-start check would get these cases wrong. */
    la t0, boundary_out
    csrw DSMLO, t0
    la t0, boundary_out_last
    csrw DSMHI, t0
    enter boundary_out
    la t0, boundary_in_csr
    csrw DSMLO, t0
    la t0, boundary_in_end
    csrw DSMHI, t0
    enter boundary_in

    /* Every 12-bit CSR number must reject a write request. */
    csrw DSMLO, zero
    csrw DSMHI, zero
    li s0, 0
    enter sweep
    li t0, 1 + 4096
    add s11, s11, t0
    bne s2, s11, m_fail
    li a0, 0
    j exit

    .balign 4
m_trap:
    csrr t0, mcause
    li t1, 8
    beq t0, t1, m_return
    li t1, 9
    beq t0, t1, m_return
    li t1, 2
    bne t0, t1, m_fail
    csrr t0, mepc
    la t1, sweep_start
    bltu t0, t1, 1f
    la t1, sweep_end
    bltu t0, t1, 2f
1:
    bne t0, s0, m_fail
2:
    csrr t1, mtval
    lwu t2, 0(t0)
    bne t1, t2, m_fail
    li t1, 0x123
    bne a5, t1, m_fail
    addi s2, s2, 1
    li s0, 0
    addi t0, t0, 4
    csrw mepc, t0
    mret
m_return:
    bnez a0, m_fail
    bnez s0, m_fail
    csrw mepc, s10
    li t0, 0x1800
    csrs mstatus, t0
    mret
m_fail:
    li a0, 1
exit:
    la a1, semiargs
    li t0, 0x20026
    sd t0, 0(a1)
    sd a0, 8(a1)
    li a0, 0x20
    .balign 16
    slli zero, zero, 0x1f
    ebreak
    srai zero, zero, 0x7
    j .

allowed:
    li a3, 1
    csrrw a4, sscratch, a3
    csrrs a4, sscratch, a3
    csrrc a4, sscratch, a3
    csrrwi a4, sscratch, 1
    csrrsi a4, sscratch, 1
    csrrci a4, sscratch, 1
    li a3, 0
    csrrs a4, sscratch, a3
    csrrc a4, sscratch, a3
    csrw sscratch, zero
    csrwi sscratch, 1
    csrr a4, sscratch
    li t0, 1
    bne a4, t0, s_fail
    li a0, 0
    ecall
allowed_end:

user_allowed:
    csrwi fcsr, 1
    csrr a4, fcsr
    li t0, 1
    bne a4, t0, s_fail
    li a0, 0
    ecall

untrusted:
    deny_matrix sstatus
    deny_matrix sie
    deny_matrix stvec
    deny_matrix sscratch
    deny_matrix sepc
    deny_matrix scause
    deny_matrix stval
    deny_matrix sip
    deny_matrix satp
    deny_matrix fflags
    deny_matrix frm
    deny_matrix fcsr
    deny_matrix vstart
    deny_matrix vcsr
    deny_matrix DLCFG
    deny_matrix DLLO
    deny_matrix 0x8c8 /* djmpcfg */
    deny_matrix 0x8b0 /* dmaincall */
    deny_matrix 0x9e0 /* dumcfg */
    csrr a4, time
    csrr a4, cycle
    csrr a4, instret
    li a0, 0
    ecall

hs_untrusted:
    deny_matrix hstatus
    deny_matrix hcounteren
    deny_matrix hgatp
    deny_matrix htimedelta
    li a0, 0
    ecall

boundary_out:
    csrr s3, sscratch
    li a5, 0x123
    la s0, boundary_out_csr
boundary_out_last:
    nop
    nop
boundary_out_csr:
    csrrw a5, sscratch, zero
    bnez s0, s_fail
    csrr a4, sscratch
    bne a4, s3, s_fail
    li a0, 0
    ecall

boundary_in:
    li a3, 2
    nop
boundary_in_csr:
    csrw sscratch, a3
    csrr a4, sscratch
    bne a4, a3, s_fail
    li a0, 0
    ecall
boundary_in_end:

sweep:
    li a5, 0x123
sweep_start:
    .set csrno, 0
    .rept 4096
    /* csrrw x0, csrno, x0 */
    .word (csrno << 20) | 0x1073
    .set csrno, csrno + 1
    .endr
sweep_end:
    li a0, 0
    ecall

s_fail:
    li a0, 1
    ecall
    j .

    .data
    .balign 16
semiargs:
    .space 16
