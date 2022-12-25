#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qapi/error.h"

#include "cpu.h"

int dasics_in_trusted_zone(CPURISCVState *env, target_ulong pc) {
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
}

int dasics_match_dlib(CPURISCVState *env, target_ulong addr, target_ulong cfg) {
    // Check whether the addr is within dlbounds which is marked as cfg
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
}
