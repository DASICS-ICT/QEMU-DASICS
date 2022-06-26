/*
 * RISC-V Emulation Helpers for QEMU.
 *
 * Copyright (c) 2016-2017 Sagar Karandikar, sagark@eecs.berkeley.edu
 * Copyright (c) 2017-2018 SiFive, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 or later, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "cpu.h"
#include "qemu/main-loop.h"
#include "exec/exec-all.h"
#include "exec/helper-proto.h"
#include "dasics.h"

/* Exceptions processing helpers */
void QEMU_NORETURN riscv_raise_exception(CPURISCVState *env,
                                          uint32_t exception, uintptr_t pc)
{
    CPUState *cs = env_cpu(env);
    qemu_log_mask(CPU_LOG_INT, "%s: %d\n", __func__, exception);
    cs->exception_index = exception;
    cpu_loop_exit_restore(cs, pc);
}

void helper_raise_exception(CPURISCVState *env, uint32_t exception)
{
    riscv_raise_exception(env, exception, 0);
}

target_ulong helper_csrrw(CPURISCVState *env, target_ulong src,
        target_ulong csr)
{
    target_ulong val = 0;
    if (riscv_csrrw(env, csr, &val, src, -1) < 0) {
        riscv_raise_exception(env, RISCV_EXCP_ILLEGAL_INST, GETPC());
    }
    return val;
}

target_ulong helper_csrrs(CPURISCVState *env, target_ulong src,
        target_ulong csr, target_ulong rs1_pass)
{
    target_ulong val = 0;
    if (riscv_csrrw(env, csr, &val, -1, rs1_pass ? src : 0) < 0) {
        riscv_raise_exception(env, RISCV_EXCP_ILLEGAL_INST, GETPC());
    }
    return val;
}

target_ulong helper_csrrc(CPURISCVState *env, target_ulong src,
        target_ulong csr, target_ulong rs1_pass)
{
    target_ulong val = 0;
    if (riscv_csrrw(env, csr, &val, 0, rs1_pass ? src : 0) < 0) {
        riscv_raise_exception(env, RISCV_EXCP_ILLEGAL_INST, GETPC());
    }
    return val;
}

#ifndef CONFIG_USER_ONLY

target_ulong helper_uret(CPURISCVState *env, target_ulong cpu_pc_deb)
{
    target_ulong retpc = env->uepc;
    if (!riscv_has_ext(env, RVC) && (retpc & 0x3)) {
        riscv_raise_exception(env, RISCV_EXCP_INST_ADDR_MIS, GETPC());
    }

    target_ulong mstatus = env->mstatus;
    mstatus = set_field(mstatus, MSTATUS_UIE, get_field(mstatus, MSTATUS_UPIE));
    mstatus = set_field(mstatus, MSTATUS_UPIE, 1);
    riscv_cpu_set_mode(env, PRV_U);
    env->mstatus = mstatus;

    return retpc;
}

target_ulong helper_sret(CPURISCVState *env, target_ulong cpu_pc_deb)
{
    if (!(env->priv >= PRV_S)) {
        riscv_raise_exception(env, RISCV_EXCP_ILLEGAL_INST, GETPC());
    }

    target_ulong retpc = env->sepc;
    if (!riscv_has_ext(env, RVC) && (retpc & 0x3)) {
        riscv_raise_exception(env, RISCV_EXCP_INST_ADDR_MIS, GETPC());
    }

    if (env->priv_ver >= PRIV_VERSION_1_10_0 &&
        get_field(env->mstatus, MSTATUS_TSR)) {
        riscv_raise_exception(env, RISCV_EXCP_ILLEGAL_INST, GETPC());
    }

    // Special function provided for UCAS-OS Lab: sepc must within d*mbounds!
    if (riscv_feature(env, RISCV_FEATURE_DASICS) &&
            (env->dasics_state.maincfg & MCFG_OSLAB) &&) {
        bool in_dsmbounds = env->dasics_state.smbound.lo <= retpc &&
                            env->dasics_state.smbound.hi >= retpc;
        bool in_dumbounds = env->dasics_state.umbound.lo <= retpc &&
                            env->dasics_state.umbound.hi >= retpc;
        target_ulong spp = get_field(mstatus, MSTATUS_SPP);

        if (!((spp == PRV_S && in_dsmbounds) || (spp == PRV_U && in_dumbounds))) {
            raise_exception(env, RISCV_EXCP_DASICS_S_INST_ACCESS_FAULT, GETPC());
        }
    }

    target_ulong mstatus = env->mstatus;
    target_ulong prev_priv = get_field(mstatus, MSTATUS_SPP);
    mstatus = set_field(mstatus,
        env->priv_ver >= PRIV_VERSION_1_10_0 ?
        MSTATUS_SIE : MSTATUS_UIE << prev_priv,
        get_field(mstatus, MSTATUS_SPIE));
    mstatus = set_field(mstatus, MSTATUS_SPIE, 1);
    mstatus = set_field(mstatus, MSTATUS_SPP, PRV_U);
    riscv_cpu_set_mode(env, prev_priv);
    env->mstatus = mstatus;

    return retpc;
}

target_ulong helper_mret(CPURISCVState *env, target_ulong cpu_pc_deb)
{
    if (!(env->priv >= PRV_M)) {
        riscv_raise_exception(env, RISCV_EXCP_ILLEGAL_INST, GETPC());
    }

    target_ulong retpc = env->mepc;
    if (!riscv_has_ext(env, RVC) && (retpc & 0x3)) {
        riscv_raise_exception(env, RISCV_EXCP_INST_ADDR_MIS, GETPC());
    }

    target_ulong mstatus = env->mstatus;
    target_ulong prev_priv = get_field(mstatus, MSTATUS_MPP);
    mstatus = set_field(mstatus,
        env->priv_ver >= PRIV_VERSION_1_10_0 ?
        MSTATUS_MIE : MSTATUS_UIE << prev_priv,
        get_field(mstatus, MSTATUS_MPIE));
    mstatus = set_field(mstatus, MSTATUS_MPIE, 1);
    mstatus = set_field(mstatus, MSTATUS_MPP, PRV_U);
    riscv_cpu_set_mode(env, prev_priv);
    env->mstatus = mstatus;

    return retpc;
}

void helper_wfi(CPURISCVState *env)
{
    CPUState *cs = env_cpu(env);

    if (env->priv == PRV_S &&
        env->priv_ver >= PRIV_VERSION_1_10_0 &&
        get_field(env->mstatus, MSTATUS_TW)) {
        riscv_raise_exception(env, RISCV_EXCP_ILLEGAL_INST, GETPC());
    } else {
        cs->halted = 1;
        cs->exception_index = EXCP_HLT;
        cpu_loop_exit(cs);
    }
}

void helper_tlb_flush(CPURISCVState *env)
{
    CPUState *cs = env_cpu(env);
    if (!(env->priv >= PRV_S) ||
        (env->priv == PRV_S &&
         env->priv_ver >= PRIV_VERSION_1_10_0 &&
         get_field(env->mstatus, MSTATUS_TVM))) {
        riscv_raise_exception(env, RISCV_EXCP_ILLEGAL_INST, GETPC());
    } else {
        tlb_flush(cs);
    }
}

/* DASICS helpers */
void helper_dasics_ld_check(CPURISCVState *env, target_ulong addr, uint64_t pc)
{
    // FIXME: Is GETPC() different from env->pc ???
    assert(env->pc == GETPC());

    // Load from trusted code zone is permitted
    if (dasics_in_trusted_zone(env)) {
        return;
    }

    // Check whether target address is within dlibbounds
    bool withinRange = false;
    for (int i = 0; i < MAX_DASICS_LIBBOUNDS; ++i) {
        uint8_t cfgval = env->dasics_state.libcfg[i];
        target_ulong boundhi = env->dasics_state.libbound[i].hi;
        target_ulong boundlo = env->dasics_state.libbound[i].lo;
        if ((cfgval & LIBCFG_V) && (cfgval & LIBCFG_R) && \
                boundlo <= addr && addr <= boundhi) {
            withinRange = true;
            break;
        }
    }

    if (!withinRange) {
        uint32_t exception = (env->priv == PRV_U) ?
                                RISCV_EXCP_DASICS_U_LOAD_ACCESS_FAULT:
                                RISCV_EXCP_DASICS_S_LOAD_ACCESS_FAULT;
        riscv_raise_exception(env, exception, GETPC());
    }
}

void helper_dasics_st_check(CPURISCVState *env, target_ulong addr, uint64_t pc)
{
    // FIXME: Is GETPC() different from env->pc ???
    assert(env->pc == GETPC());

    // Store from trusted code zone is permitted
    if (dasics_in_trusted_zone(env)) {
        return;
    }

    // Check whether target address is within dlibbounds
    bool withinRange = false;
    for (int i = 0; i < MAX_DASICS_LIBBOUNDS; ++i) {
        uint8_t cfgval = env->dasics_state.libcfg[i];
        target_ulong boundhi = env->dasics_state.libbound[i].hi;
        target_ulong boundlo = env->dasics_state.libbound[i].lo;
        if ((cfgval & LIBCFG_V) && (cfgval & LIBCFG_W) && \
                boundlo <= addr && addr <= boundhi) {
            withinRange = true;
            break;
        }
    }

    if (!withinRange) {
        uint32_t exception = (env->priv == PRV_U) ?
                                RISCV_EXCP_DASICS_U_STORE_ACCESS_FAULT:
                                RISCV_EXCP_DASICS_S_STORE_ACCESS_FAULT;
        riscv_raise_exception(env, exception, GETPC());
}

#endif /* !CONFIG_USER_ONLY */
