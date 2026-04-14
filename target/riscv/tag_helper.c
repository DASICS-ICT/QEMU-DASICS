/*
 * RISC-V Zimt/Svatag/Smvatag helpers.
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "internals.h"
#include "pmp.h"
#include "accel/tcg/cpu-ldst.h"
#include "exec/tb-flush.h"

#ifdef CONFIG_USER_ONLY

target_ulong riscv_zimt_get_vitt_base(CPURISCVState *env, int mmu_idx)
{
    return 0;
}

target_ulong riscv_zimt_compute_tag_va(CPURISCVState *env, target_ulong va,
                                       int mmu_idx)
{
    return va;
}

uint8_t riscv_zimt_get_mc_tag_width(CPURISCVState *env, int mmu_idx)
{
    return 0;
}

bool riscv_zimt_mt_enabled(CPURISCVState *env, int mmu_idx)
{
    return false;
}

target_ulong riscv_zimt_tag_load(CPURISCVState *env, target_ulong va, int mmu_idx,
                                 uintptr_t retaddr)
{
    (void)retaddr;
    return 0;
}

void riscv_zimt_tag_store(CPURISCVState *env, target_ulong va, target_ulong tag,
                          int mmu_idx, uintptr_t retaddr)
{
    (void)retaddr;
}

bool riscv_zimt_addr_in_vitt(CPURISCVState *env, target_ulong va, int mmu_idx)
{
    return false;
}

#else

static uint64_t riscv_zimt_get_mt_mode(CPURISCVState *env, int mmu_idx)
{
    int priv = mmuidx_priv(mmu_idx);
    bool virt = mmuidx_2stage(mmu_idx);

    if (virt) {
        if (priv == PRV_U) {
            return get_field(env->hstatus, HSTATUS_VUMT_MODE);
        }
        return get_field(env->henvcfg, HENVCFG_MT_MODE);
    }

    switch (priv) {
    case PRV_M:
        return get_field(env->mseccfg, MSECCFG_MT_MODE);
    case PRV_S:
        return get_field(env->menvcfg, MENVCFG_MT_MODE);
    case PRV_U:
        return get_field(env->senvcfg, SENVCFG_MT_MODE);
    default:
        return 0;
    }
}

uint8_t riscv_zimt_get_mc_tag_width(CPURISCVState *env, int mmu_idx)
{
    uint64_t mt_mode = riscv_zimt_get_mt_mode(env, mmu_idx);

    if (mt_mode == 2) {
        return 4;
    }
    if (mt_mode == 3) {
        return 8;
    }
    return 0;
}

bool riscv_zimt_mt_enabled(CPURISCVState *env, int mmu_idx)
{
    return riscv_zimt_get_mt_mode(env, mmu_idx) >= 2;
}

target_ulong riscv_zimt_get_vitt_base(CPURISCVState *env, int mmu_idx)
{
    int priv = mmuidx_priv(mmu_idx);
    bool virt = mmuidx_2stage(mmu_idx);

    if (virt) {
        if (priv == PRV_U) {
            return env->vsvittu;
        }
        return env->vsvitts;
    }

    switch (priv) {
    case PRV_M:
        return env->mvitt;
    case PRV_S:
        return env->svitts;
    case PRV_U:
        return env->svittu;
    default:
        return 0;
    }
}

target_ulong riscv_zimt_compute_tag_va(CPURISCVState *env, target_ulong va,
                                       int mmu_idx)
{
    uint8_t width = riscv_zimt_get_mc_tag_width(env, mmu_idx);
    target_ulong base = riscv_zimt_get_vitt_base(env, mmu_idx);

    if (width == 8) {
        return base + (va >> 4);
    }
    if (width == 4) {
        return base + (va >> 5);
    }
    return base;
}

target_ulong riscv_zimt_tag_load(CPURISCVState *env, target_ulong va, int mmu_idx,
                                 uintptr_t retaddr)
{
    uint8_t width = riscv_zimt_get_mc_tag_width(env, mmu_idx);
    target_ulong tag_va = riscv_zimt_compute_tag_va(env, va, mmu_idx);
    uint8_t byte;

    env->in_tag_access = true;
    byte = cpu_ldub_mmuidx_ra(env, tag_va, mmu_idx, retaddr);
    env->in_tag_access = false;

    if (width == 8) {
        return byte;
    }
    if (width == 4) {
        return ((va >> 4) & 1) ? (byte >> 4) : (byte & 0xf);
    }
    return 0;
}

void riscv_zimt_tag_store(CPURISCVState *env, target_ulong va, target_ulong tag,
                          int mmu_idx, uintptr_t retaddr)
{
    uint8_t width = riscv_zimt_get_mc_tag_width(env, mmu_idx);
    target_ulong tag_va = riscv_zimt_compute_tag_va(env, va, mmu_idx);

    env->in_tag_access = true;
    if (width == 8) {
        cpu_stb_mmuidx_ra(env, tag_va, tag & 0xff, mmu_idx, retaddr);
    } else if (width == 4) {
        uint8_t byte = cpu_ldub_mmuidx_ra(env, tag_va, mmu_idx, retaddr);
        uint8_t nib = tag & 0xf;
        if ((va >> 4) & 1) {
            byte = (byte & 0x0f) | (nib << 4);
        } else {
            byte = (byte & 0xf0) | nib;
        }
        cpu_stb_mmuidx_ra(env, tag_va, byte, mmu_idx, retaddr);
    }
    env->in_tag_access = false;
}

bool riscv_zimt_addr_in_vitt(CPURISCVState *env, target_ulong va, int mmu_idx)
{
    target_ulong base = riscv_zimt_get_vitt_base(env, mmu_idx);
    if (base == 0) {
        return false;
    }

    /*
     * Derive the VITT protection range from the current page table mode.
     * The VITT covers tag VAs for the user-accessible virtual address space
     * [0, 2^(va_bits-1)), so the protected interval is
     *   [vitt_base, vitt_base + (max_user_va >> shift)].
     */
    int vm, va_bits, shift;
    uint8_t width = riscv_zimt_get_mc_tag_width(env, mmu_idx);

    shift = (width == 8) ? 4 : 5;

    if (riscv_cpu_mxl(env) == MXL_RV32) {
        vm = get_field(env->satp, SATP32_MODE);
        switch (vm) {
        case VM_1_10_SV32:  va_bits = 32; break;
        default:            va_bits = 32; break;
        }
    } else {
        vm = get_field(env->satp, SATP64_MODE);
        switch (vm) {
        case VM_1_10_SV39:  va_bits = 39; break;
        case VM_1_10_SV48:  va_bits = 48; break;
        case VM_1_10_SV57:  va_bits = 57; break;
        default:            return false;
        }
    }

    target_ulong max_user_va = (1ULL << (va_bits - 1)) - 1;
    target_ulong start = base;
    target_ulong end = base + (max_user_va >> shift);

    return va >= start && va <= end;
}

#endif

void riscv_zimt_update_tag_check_active(CPURISCVState *env)
{
#ifndef CONFIG_USER_ONLY
    bool old = env->zimt_tag_check_active;
    bool new_active = false;

    uint64_t menvcfg_mt = get_field(env->menvcfg, MENVCFG_MT_MODE);
    uint64_t senvcfg_mt = get_field(env->senvcfg, SENVCFG_MT_MODE);
    uint64_t mseccfg_mt = get_field(env->mseccfg, MSECCFG_MT_MODE);

    if (menvcfg_mt >= 2 || senvcfg_mt >= 2 || mseccfg_mt >= 2) {
        new_active = true;
    }

    env->zimt_tag_check_active = new_active;

    if (old != new_active) {
        queue_tb_flush(env_cpu(env));
    }
#else
    env->zimt_tag_check_active = false;
#endif
}
