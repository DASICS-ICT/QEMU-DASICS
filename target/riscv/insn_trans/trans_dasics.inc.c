
static bool trans_dasicsret(DisasContext *ctx, arg_jalr *a)
{
#ifndef CONFIG_USER_ONLY
    /* no chaining with JALR */
    TCGLabel *misaligned = NULL;
    TCGv t0 = tcg_temp_new();

    gen_get_gpr(t0, a->rs1);
    tcg_gen_addi_tl(t0, t0, a->imm);
    tcg_gen_andi_tl(t0, t0, (target_ulong)-2);

    gen_helper_dasics_redirect(cpu_env, t0, tcg_const_i64(ctx->pc_succ_insn),
                               tcg_const_i64(1));

    tcg_gen_mov_tl(cpu_pc, t0);

    if (!has_ext(ctx, RVC)) {
        misaligned = gen_new_label();
        tcg_gen_andi_tl(t0, cpu_pc, 0x2);
        tcg_gen_brcondi_tl(TCG_COND_NE, t0, 0x0, misaligned);
    }

    if (a->rd != 0) {
        tcg_gen_movi_tl(cpu_gpr[a->rd], ctx->pc_succ_insn);
    }
    lookup_and_goto_ptr(ctx);

    if (misaligned) {
        gen_set_label(misaligned);
        gen_exception_inst_addr_mis(ctx);
    }
    ctx->base.is_jmp = DISAS_NORETURN;

    tcg_temp_free(t0);
    return true;
#endif
    return false;
}
