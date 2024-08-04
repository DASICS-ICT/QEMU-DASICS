#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/main-loop.h"
#include "cpu.h"
#include "internals.h"
#include "pmu.h"
#include "exec/exec-all.h"
#include "instmap.h"
#include "tcg/tcg-op.h"
#include "trace.h"
#include "semihosting/common-semi.h"
#include "sysemu/cpu-timers.h"
#include "cpu_bits.h"
#include "debug.h"
#include "tcg/oversized-guest.h"
#include "dasics.h"

int dasics_in_trusted_zone(CPURISCVState *env, target_ulong pc) 
{
#ifndef CONFIG_USER_ONLY
    int is_smain_enable = env->dasics_state.smbound.lo <= env->dasics_state.smbound.hi && \
                          (env->dasics_state.maincfg & MCFG_SENA);
    int is_umain_enable = env->dasics_state.umbound.lo <= env->dasics_state.umbound.hi && \
                          (env->dasics_state.maincfg & MCFG_UENA);

    int in_smain_zone = pc <= env->dasics_state.smbound.hi && \
                        pc >= env->dasics_state.smbound.lo && \
                        env->priv == PRV_S && is_smain_enable;
    int in_umain_zone = pc <= env->dasics_state.umbound.hi && \
                        pc >= env->dasics_state.umbound.lo && \
                        env->priv == PRV_U && is_umain_enable;

    int in_s_trusted_zone = in_smain_zone || (env->priv == PRV_S && !is_smain_enable);
    int in_u_trusted_zone = in_umain_zone || (env->priv == PRV_U && !is_umain_enable);
    return env->priv == PRV_M || in_s_trusted_zone || in_u_trusted_zone;
#endif
    return 0;
}

int dasics_in_active_zone(CPURISCVState *env, target_ulong pc, int lvl)
{
#ifndef CONFIG_USER_ONLY

    int withinRange = 0;
    for (int i = 0; i < MAX_DASICS_LIBJMPBOUNDS; ++i) {
        uint8_t cfgval = env->dasics_state.libjmpcfg[i];
        target_ulong boundhi = env->dasics_state.libjmpbound[i].hi;
        target_ulong boundlo = env->dasics_state.libjmpbound[i].lo;
        uint8_t level = env->dasics_state.djlevel[i];
        if ((cfgval & LIBJMPCFG_V) && boundlo <= pc && pc <= boundhi && level == lvl) {
            withinRange = 1;
            break;
        }
    }

    return withinRange;    

#endif
    return 0;
}

int dasics_match_dlib(CPURISCVState *env, target_ulong addr, target_ulong cfg, int lvl) {
    // Check whether the addr is within dlbounds which is marked as cfg
#ifndef CONFIG_USER_ONLY

    int withinRange = 0;
    for (int i = 0; i < MAX_DASICS_LIBBOUNDS; ++i) {
        uint8_t cfgval = env->dasics_state.libcfg[i];
        target_ulong boundhi = env->dasics_state.libbound[i].hi;
        target_ulong boundlo = env->dasics_state.libbound[i].lo;
        int level = dasics_get_mem_level_from_idx(env, i);
        if (!((cfgval & cfg) ^ cfg) && boundlo <= addr && addr <= boundhi && level == lvl) {
            withinRange = 1;
            break;
        }
    }

    return withinRange;
#endif
    return 0;
}

int dasics_get_mem_level_from_idx(CPURISCVState *env, int idx)
{
#ifndef CONFIG_USER_ONLY
    assert(0 <= idx && idx < MAX_DASICS_LIBBOUNDS);
    return (int)(env->dasics_state.dmlevel[idx] & LEVEL_MASK);
#else
    return 0;
#endif
}

int dasics_get_jmp_level_from_idx(CPURISCVState *env, int idx)
{
#ifndef CONFIG_USER_ONLY
    assert(0 <= idx && idx < MAX_DASICS_LIBJMPBOUNDS);
    return (int)(env->dasics_state.djlevel[idx] & LEVEL_MASK);
#else
    return 0;
#endif
}

int dasics_get_jmp_level(CPURISCVState *env, target_ulong pc)
{
#ifndef CONFIG_USER_ONLY
    int maxLevel = 0;

    for (int i = 0; i < MAX_DASICS_LIBJMPBOUNDS; ++i) {
        uint8_t cfgval = env->dasics_state.libjmpcfg[i];
        target_ulong boundhi = env->dasics_state.libjmpbound[i].hi;
        target_ulong boundlo = env->dasics_state.libjmpbound[i].lo;
        if ((cfgval & LIBJMPCFG_V) && boundlo <= pc && pc <= boundhi) {
            int level = dasics_get_jmp_level_from_idx(env, i);
            if (level > maxLevel) {
                maxLevel = level;
            }
        }
    }

    return maxLevel;
#else
    return 0;
#endif
}

int dasics_get_scratch_level(CPURISCVState *env)
{
#ifndef CONFIG_USER_ONLY
    return (int)(env->dasics_state.dscratchlevel & LEVEL_MASK);
#else
    return 0;
#endif
}

int dasics_access_lib_csrs(int csrno)
{
#ifndef CONFIG_USER_ONLY
    return csrno == CSR_DLCFG ||
           (CSR_DLBOUND0 <= csrno && csrno <= CSR_DLBOUND31) ||
           csrno == CSR_DJMPCFG ||
           (CSR_DLIBJMPBOUND0 <= csrno && csrno <= CSR_DLIBJMPBOUND7) ||
           csrno == CSR_DSCRATCHCFG ||
           csrno == CSR_DSCRATCHLO  ||
           csrno == CSR_DSCRATCHHI;
#else
    return 0;
#endif
}