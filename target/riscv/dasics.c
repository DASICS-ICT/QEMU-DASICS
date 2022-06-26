#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qapi/error.h"

#include "cpu.h"

int dasics_in_trusted_zone(CPURISCVState *env) {
    int is_smain_enable = env->dasics_state.smbound.lo <= env->dasics_state.smbound.hi && \
                          (env->dasics_state.maincfg & MCFG_SENA);
    int is_umain_enable = env->dasics_state.umbound.lo <= env->dasics_state.umbound.hi && \
                          (env->dasics_state.maincfg & MCFG_UENA);

    int in_smain_zone = env->pc <= env->dasics_state.smbound.hi && \
                        env->pc >= env->dasics_state.smbound.lo && \
                        env->priv == PRV_S && is_smain_enable;
    int in_umain_zone = env->pc <= env->dasics_state.umbound.hi && \
                        env->pc >= env->dasics_state.umbound.lo && \
                        env->priv == PRV_U && is_umain_enable;

    int in_s_trusted_zone = in_smain_zone || (env->priv == PRV_S && !is_smain_enable);
    int in_u_trusted_zone = in_umain_zone || (env->priv == PRV_U && !is_umain_enable);

    return env->priv == PRV_M || in_s_trusted_zone || in_u_trusted_zone;
}