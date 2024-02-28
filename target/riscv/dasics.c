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
    if (env->priv != PRV_U) return 1;

    int is_umain_enable = env->dasics_state.umbound.lo <= env->dasics_state.umbound.hi && \
                          (env->dasics_state.maincfg & MCFG_UENA);

    int in_umain_zone = pc <= env->dasics_state.umbound.hi && \
                        pc >= env->dasics_state.umbound.lo && \
                        env->priv == PRV_U && is_umain_enable;

    int in_u_trusted_zone = in_umain_zone || (env->priv == PRV_U && !is_umain_enable);
    return in_u_trusted_zone;
#endif
    return 0;
}

int dasics_in_active_zone(CPURISCVState *env, target_ulong pc)
{
#ifndef CONFIG_USER_ONLY

    int withinRange = 0;
    for (int i = 0; i < MAX_DASICS_LIBJMPBOUNDS; ++i) {
        uint8_t cfgval = env->dasics_state.libjmpcfg[i];
        target_ulong boundhi = env->dasics_state.libjmpbound[i].hi;
        target_ulong boundlo = env->dasics_state.libjmpbound[i].lo;
        if ((cfgval & LIBJMPCFG_V) && boundlo <= pc && pc <= boundhi) {
            withinRange = 1;
            break;
        }
    }

    return withinRange;    

#endif
    return 0;
}

int dasics_match_dlib(CPURISCVState *env, target_ulong addr, target_ulong cfg) {
    // Check whether the addr is within dlbounds which is marked as cfg
#ifndef CONFIG_USER_ONLY

    int withinRange = 0;
    for (int i = 0; i < MAX_DASICS_LIBBOUNDS; ++i) {
        uint8_t cfgval = env->dasics_state.libcfg[i];
        target_ulong boundhi = env->dasics_state.libbound[i].hi;
        target_ulong boundlo = env->dasics_state.libbound[i].lo;
        if (!((cfgval & cfg) ^ cfg) && boundlo <= addr && addr <= boundhi) {
            withinRange = 1;
            break;
        }
    }

    return withinRange;
#endif
    return 0;
}
