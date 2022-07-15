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
void helper_dasics_ld_check(CPURISCVState *env, target_ulong addr)
{
    // Load from trusted code zone is permitted
    if (!riscv_feature(env, RISCV_FEATURE_DASICS) ||
            dasics_in_trusted_zone(env, env->pc)) {
        return;
    }

    // Check whether target address is within dlibbounds
    if (!dasics_match_dlib(env, addr, LIBCFG_V | LIBCFG_R)) {
        uint32_t exception = (env->priv == PRV_U) ?
                                RISCV_EXCP_DASICS_U_LOAD_ACCESS_FAULT:
                                RISCV_EXCP_DASICS_S_LOAD_ACCESS_FAULT;
        env->badaddr = addr;
        riscv_raise_exception(env, exception, GETPC());
    }
}

void helper_dasics_st_check(CPURISCVState *env, target_ulong addr)
{
    // Store from trusted code zone is permitted
    if (!riscv_feature(env, RISCV_FEATURE_DASICS) ||
            dasics_in_trusted_zone(env, env->pc)) {
        return;
    }

    // Check whether target address is within dlibbounds
    if (!dasics_match_dlib(env, addr, LIBCFG_V | LIBCFG_W)) {
        uint32_t exception = (env->priv == PRV_U) ?
                                RISCV_EXCP_DASICS_U_STORE_ACCESS_FAULT:
                                RISCV_EXCP_DASICS_S_STORE_ACCESS_FAULT;
        env->badaddr = addr;
        riscv_raise_exception(env, exception, GETPC());
    }
}

void helper_dasics_redirect(CPURISCVState *env, target_ulong newpc,
    target_ulong nextpc, uint64_t is_dasicsret)
{
    if (!riscv_feature(env, RISCV_FEATURE_DASICS)) {
        return;
    }

    // Check whether this redirect instr is permitted
    int src_trusted = dasics_in_trusted_zone(env, env->pc);
    int dst_trusted = dasics_in_trusted_zone(env, newpc);
    int src_freezone = dasics_match_dlib(env, env->pc, LIBCFG_V | LIBCFG_X);
    int dst_freezone = dasics_match_dlib(env, newpc, LIBCFG_V | LIBCFG_X);

    int allow_lib_to_main = !src_trusted && dst_trusted &&
        (newpc == env->dasics_state.dretpc || newpc == env->dasics_state.dmaincall);
    int allow_freezone_to_lib = src_freezone && !dst_trusted &&
        !dst_freezone && (newpc == env->dasics_state.dretpcfz);

    int allow_brjp = src_trusted  || allow_lib_to_main ||
                     dst_freezone || allow_freezone_to_lib;

    if (!allow_brjp) {
        uint32_t exception = (env->priv == PRV_U) ?
                                RISCV_EXCP_DASICS_U_INST_ACCESS_FAULT:
                                RISCV_EXCP_DASICS_S_INST_ACCESS_FAULT;
        env->badaddr = newpc;
        riscv_raise_exception(env, exception, GETPC());
    }

    // Set dretpc when redirect from trusted zone to untrusted, if not dasicsret
    if (src_trusted && !dst_trusted && !is_dasicsret) {
        env->dasics_state.dretpc = nextpc;
    }
}

#endif /* !CONFIG_USER_ONLY */
