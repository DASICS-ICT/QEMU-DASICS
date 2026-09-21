/*
 * KDASICS instruction permissions. SPDX-License-Identifier: GPL-2.0-or-later
 * M-mode checks the fault PC, instruction bits, return state and trap count.
 * Build with NO_DASICS and run with dasics=false for the compatibility test.
 */
    .option norvc
    .option norelax
    .text
    .global _start

    .equ DSMCFG, 0xbc0
    .equ DSMLO, 0xbc2
    .equ DSMHI, 0xbc3
    .equ DUMLO, 0x9e2
    .equ DUMHI, 0x9e3

    .macro enter label, privilege=0x800
    la s10, 991f
    la t0, \label
    csrw mepc, t0
    li s5, \privilege
    /* SPP=S, SPIE=SIE=MIE=0, TSR=TW=TVM=0. Snapshot legacy U bits too. */
    ori t0, s5, 0x100
    csrw mstatus, t0
    csrr s4, mstatus
    andi s4, s4, 0x133
    li s0, 0
    mret
991:
    .endm

    .macro expect insn, cause=2
    li s1, \cause
    la s0, 991f
991:
    \insn
    bnez s0, fail_call
    .endm

_start:
    la t0, trap
    csrw mtvec, t0
    csrw medeleg, zero
    csrw mideleg, zero
    csrw mie, zero
    li t0, -1
    csrw pmpaddr0, t0
    li t0, 0x1f
    csrw pmpcfg0, t0
    li s2, 0
    la t0, s_returned
    csrw sepc, t0
    la t0, u_returned
    csrw 0x041, t0 /* uepc */

#ifndef NO_DASICS
    /* Permit test data and branches; only instruction policy is under test. */
    csrw 0x890, zero
    csrw 0x8c0, zero
    li t0, -1
    csrw 0x891, t0
    csrw 0x8c1, t0
    li t0, 0xb
    csrw 0x880, t0
    li t0, 1
    csrw 0x8c8, t0
    csrw DSMLO, zero
    csrw DSMHI, zero
    csrw DUMLO, zero
    csrw DUMHI, zero

    /* Legacy ECALL bypass flags must not defeat either domain's policy. */
    li t0, 3
    csrw DSMCFG, t0
    enter s_denied
    enter u_denied, 0
    li t0, 0x47 /* SENA | UENA | CSET | CUET */
    csrw DSMCFG, t0
    enter s_denied
    enter u_denied, 0
    li t0, 16
    bne s2, t0, fail

    /* Trusted S and U handlers retain their own return instructions. */
    la t0, s_allowed
    csrw DSMLO, t0
    la t0, s_allowed_end
    csrw DSMHI, t0
    la t0, u_allowed
    csrw DUMLO, t0
    la t0, u_allowed_end
    csrw DUMHI, t0
    enter s_allowed
    enter u_allowed, 0

    /* A trusted handler must still be able to return to untrusted code. */
    la t0, s_allowed
    csrw DSMLO, t0
    csrw DSMHI, t0
    enter s_allowed
    la t0, u_allowed
    csrw DUMLO, t0
    csrw DUMHI, t0
    enter u_allowed, 0

    /* URET is rejected in trusted S and M before state changes. */
    la t0, s_uret_denied
    csrw DSMLO, t0
    la t0, s_allowed_end
    csrw DSMHI, t0
    enter s_uret_denied
    enter s_uret_denied, 0x1800
    li t0, 18
    bne s2, t0, fail

    /* Actual PC, not TB-start PC, must decide SRET and WFI permissions. */
    la t0, edge_sret
    csrw DSMLO, t0
    la t0, edge_sret_last
    csrw DSMHI, t0
    enter edge_sret
    la t0, edge_wfi
    csrw DSMLO, t0
    la t0, edge_wfi_last
    csrw DSMHI, t0
    enter edge_wfi
    la t0, edge_uret
    csrw DUMLO, t0
    la t0, edge_uret_last
    csrw DUMHI, t0
    enter edge_uret, 0
    li t0, 21
    bne s2, t0, fail

    /* Disabled domain protection restores S/U execution outside the bounds. */
    csrw DSMCFG, zero
    enter s_allowed
    enter u_allowed, 0
    /* ECALL uses the usual exception causes when protection is disabled. */
    enter s_ecall_allowed
    enter u_ecall_allowed, 0

    /* Trusted ECALLs use the usual causes even while both domains are on. */
    la t0, s_ecall_allowed
    csrw DSMLO, t0
    la t0, s_ecall_end
    csrw DSMHI, t0
    la t0, u_ecall_allowed
    csrw DUMLO, t0
    la t0, u_ecall_end
    csrw DUMHI, t0
    li t0, 3
    csrw DSMCFG, t0
    enter s_ecall_allowed
    enter u_ecall_allowed, 0
    li t0, 25
    bne s2, t0, fail

    /* Fences stay available to untrusted S-mode, including Svinval. */
    enter fences
#else
    enter s_allowed
    enter u_allowed, 0
    /* With the CPU feature off, preserve legacy URET from S and M. */
    enter u_allowed
    enter u_allowed, 0x1800
    enter s_ecall_allowed
    enter u_ecall_allowed, 0
    enter fences
    li t0, 2
    bne s2, t0, fail
#endif

    /* Pending SSIP wakes WFI despite SIE=0; no interrupt is taken. */
    li t0, 2
    csrw mideleg, t0
    csrw mie, t0
    csrs mip, t0
#ifndef NO_DASICS
    la t0, wfi_allowed
    csrw DSMLO, t0
    /* Only WFI itself is trusted: checking its next PC would reject it. */
    csrw DSMHI, t0
#endif
    enter wfi_allowed
#ifndef NO_DASICS
    csrw DSMCFG, zero
    enter wfi_allowed
#endif
    li a0, 0
    j exit

    .balign 4
trap:
    csrr t0, mcause
    li t1, 3
    beq t0, t1, done
    bne t0, s1, fail
    csrr t1, mepc
    bne t1, s0, fail
    /* A rejected return must not consume the S/U interrupt-enable stack. */
    csrr t2, mstatus
    andi t3, t2, 0x133
    bne t3, s4, fail
    li t4, 0x1800
    and t2, t2, t4
    bne t2, s5, fail
    csrr t2, sepc
    la t3, s_returned
    bne t2, t3, fail
    csrr t2, 0x041
    la t3, u_returned
    bne t2, t3, fail
    li t2, 2
    bne t0, t2, check_ecall
    csrr t2, mtval
    lwu t3, 0(t1)
    bne t2, t3, fail
    j resume
check_ecall:
    csrr t2, mtval
    bnez t2, fail
#ifndef NO_DASICS
    li t2, 24
    bltu t0, t2, resume
    csrr t2, 0x8b3 /* dfreason */
    li t3, 1 /* DFR_EF */
    bne t2, t3, fail
#endif
resume:
    li s0, 0
    addi s2, s2, 1
    addi t1, t1, 4
    csrw mepc, t1
    mret
done:
    bnez s0, fail
    bnez a0, fail
    csrw mepc, s10
    li t0, 0x1800
    csrs mstatus, t0
    mret
fail:
    li a0, 1
exit:
    la a1, args
    li t0, 0x20026
    sd t0, 0(a1)
    sd a0, 8(a1)
    li a0, 0x20
    .balign 16
    slli zero, zero, 0x1f
    ebreak
    srai zero, zero, 0x7
    j .

s_denied:
    expect sret
    expect uret
    expect wfi
    expect ecall, 25
    li a0, 0
    ebreak
u_denied:
    expect sret
    expect uret
    expect wfi
    expect ecall, 24
    li a0, 0
    ebreak

s_allowed:
    sret
s_returned:
    csrr t0, sstatus
    andi t0, t0, 0x122
    li t1, 0x20
    bne t0, t1, fail_call
    li a0, 0
    ebreak
s_uret_denied:
    expect uret
    li a0, 0
    ebreak
s_allowed_end:

u_allowed:
    uret
u_returned:
    csrr t0, 0 /* ustatus */
    andi t0, t0, 0x11
    srli t1, s4, 4
    andi t1, t1, 1
    ori t1, t1, 0x10
    bne t0, t1, fail_call
    li a0, 0
    ebreak
u_allowed_end:

edge_sret:
    li s1, 2
    la s0, 1f
edge_sret_last:
    nop
    nop
1:
    sret
    bnez s0, fail_call
    li a0, 0
    ebreak
edge_wfi:
    li s1, 2
    la s0, 1f
edge_wfi_last:
    nop
    nop
1:
    wfi
    bnez s0, fail_call
    li a0, 0
    ebreak
edge_uret:
    li s1, 2
    la s0, 1f
edge_uret_last:
    nop
    nop
1:
    uret
    bnez s0, fail_call
    li a0, 0
    ebreak

s_ecall_allowed:
    expect ecall, 9
    li a0, 0
    ebreak
s_ecall_end:
u_ecall_allowed:
    expect ecall, 8
    li a0, 0
    ebreak
u_ecall_end:
fences:
    fence
    fence.i
    sfence.vma
    .word 0x16000073 /* sinval.vma x0,x0 */
    .word 0x18000073 /* sfence.w.inval */
    .word 0x18100073 /* sfence.inval.ir */
    li a0, 0
    ebreak
wfi_allowed:
    wfi
    li a0, 0
    ebreak
fail_call:
    li a0, 1
    ebreak
    j .

    .data
    .balign 16
args:
    .space 16
