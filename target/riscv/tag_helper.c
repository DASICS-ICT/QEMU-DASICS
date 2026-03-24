/*
 * RISC-V Zimt/Svatag/Smvatag helpers.
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "internals.h"
#include "accel/tcg/cpu-ldst.h"

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

target_ulong riscv_zimt_tag_load(CPURISCVState *env, target_ulong va, int mmu_idx)
{
    return 0;
}

void riscv_zimt_tag_store(CPURISCVState *env, target_ulong va, target_ulong tag,
                          int mmu_idx)
{
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

target_ulong riscv_zimt_tag_load(CPURISCVState *env, target_ulong va, int mmu_idx)
{
    uint8_t width = riscv_zimt_get_mc_tag_width(env, mmu_idx);
    target_ulong tag_va = riscv_zimt_compute_tag_va(env, va, mmu_idx);
    uint8_t byte;

    env->in_tag_access = true;
    byte = cpu_ldub_mmuidx_ra(env, tag_va, mmu_idx, 0);
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
                          int mmu_idx)
{
    uint8_t width = riscv_zimt_get_mc_tag_width(env, mmu_idx);
    target_ulong tag_va = riscv_zimt_compute_tag_va(env, va, mmu_idx);

    env->in_tag_access = true;
    if (width == 8) {
        cpu_stb_mmuidx_ra(env, tag_va, tag & 0xff, mmu_idx, 0);
    } else if (width == 4) {
        uint8_t byte = cpu_ldub_mmuidx_ra(env, tag_va, mmu_idx, 0);
        uint8_t nib = tag & 0xf;
        if ((va >> 4) & 1) {
            byte = (byte & 0x0f) | (nib << 4);
        } else {
            byte = (byte & 0xf0) | nib;
        }
        cpu_stb_mmuidx_ra(env, tag_va, byte, mmu_idx, 0);
    }
    env->in_tag_access = false;
}

bool riscv_zimt_addr_in_vitt(CPURISCVState *env, target_ulong va, int mmu_idx)
{
    /*
     * Conservative approximation: derive a full-space tag mapping interval.
     * This protects against direct accesses to the virtual tag table while
     * avoiding a page-table-mode-dependent helper dependency.
     */
    target_ulong start = riscv_zimt_compute_tag_va(env, 0, mmu_idx);
    target_ulong end = riscv_zimt_compute_tag_va(env, (target_ulong)-1, mmu_idx);

    if (start <= end) {
        return va >= start && va <= end;
    }
    return va >= end && va <= start;
}

#endif
