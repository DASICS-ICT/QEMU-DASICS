// dasicscall.j 
static bool trans_dasicscallj(DisasContext *ctx, arg_dasicscallj *a)
{
    TCGLabel *misaligned = NULL;
    TCGv target_pc = tcg_temp_new();
    TCGv succ_pc = dest_gpr(ctx, (int)1);  

    tcg_gen_addi_tl(target_pc, get_gpr(ctx, (int)0, EXT_NONE), a->imm);
    tcg_gen_andi_tl(target_pc, target_pc, (target_ulong)-2);

    if (get_xl(ctx) == MXL_RV32) {
        tcg_gen_ext32s_tl(target_pc, target_pc);
    }

    if (!has_ext(ctx, RVC) && !ctx->cfg_ptr->ext_zca) {
        TCGv t0 = tcg_temp_new();

        misaligned = gen_new_label();
        tcg_gen_andi_tl(t0, target_pc, 0x2);
        tcg_gen_brcondi_tl(TCG_COND_NE, t0, 0x0, misaligned);
    }    

    gen_pc_plus_diff(succ_pc, ctx, ctx->cur_insn_len);

    // DASICS check before update rd and pc
#ifndef CONFIG_USER_ONLY
    TCGv pc_now = tcg_temp_new();
    gen_pc_plus_diff(pc_now, ctx, 0);

    gen_helper_dasics_call(cpu_env, pc_now, target_pc, succ_pc);    

#endif

    gen_set_gpr(ctx, (int)1, succ_pc);


    tcg_gen_mov_tl(cpu_pc, target_pc);
    lookup_and_goto_ptr(ctx);

    if (misaligned) {
        gen_set_label(misaligned);
        gen_exception_inst_addr_mis(ctx, target_pc);
    }
    ctx->base.is_jmp = DISAS_NORETURN;

    return true;
}

// dasicscall.jr
static bool trans_dasicscalljr(DisasContext *ctx, arg_dasicscalljr *a)
{
    TCGLabel *misaligned = NULL;
    TCGv target_pc = tcg_temp_new();
    TCGv succ_pc = dest_gpr(ctx, (int)1);

    tcg_gen_addi_tl(target_pc, get_gpr(ctx, a->rs1, EXT_NONE), a->imm);
    tcg_gen_andi_tl(target_pc, target_pc, (target_ulong)-2);

    if (get_xl(ctx) == MXL_RV32) {
        tcg_gen_ext32s_tl(target_pc, target_pc);
    }

    if (!has_ext(ctx, RVC) && !ctx->cfg_ptr->ext_zca) {
        TCGv t0 = tcg_temp_new();

        misaligned = gen_new_label();
        tcg_gen_andi_tl(t0, target_pc, 0x2);
        tcg_gen_brcondi_tl(TCG_COND_NE, t0, 0x0, misaligned);
    }

    gen_pc_plus_diff(succ_pc, ctx, ctx->cur_insn_len);

    // DASICS check before update rd and pc
#ifndef CONFIG_USER_ONLY
    TCGv pc_now = tcg_temp_new();
    gen_pc_plus_diff(pc_now, ctx, 0);
    
    gen_helper_dasics_call(cpu_env, pc_now, target_pc, succ_pc);

#endif

    gen_set_gpr(ctx, (int)1, succ_pc);

    tcg_gen_mov_tl(cpu_pc, target_pc);
    lookup_and_goto_ptr(ctx);

    if (misaligned) {
        gen_set_label(misaligned);
        gen_exception_inst_addr_mis(ctx, target_pc);
    }
    ctx->base.is_jmp = DISAS_NORETURN;

    return true;
}

// dibndmv
static bool trans_dibndmv(DisasContext *ctx, arg_dibndmv *a)
{
    TCGv rs1 = get_gpr(ctx, a->rs1, EXT_NONE);
    TCGv rs2 = get_gpr(ctx, a->rs2, EXT_NONE);
    TCGv_i32 imm = tcg_constant_i32(a->imm);

    /* The helper may raise ILLEGAL_INSN -- record binv for unwind. */
    decode_save_opc(ctx);

    gen_helper_dasics_dibndmv(cpu_env, rs1, rs2, imm);

    /* We may have changed important cpu state -- exit to main loop. */
    gen_update_pc(ctx, ctx->cur_insn_len);
    exit_tb(ctx);
    ctx->base.is_jmp = DISAS_NORETURN;

    return true;
}

// dibndquery
static bool trans_dibndquery(DisasContext *ctx, arg_dibndquery *a)
{
    TCGv dest = dest_gpr(ctx, a->rd);
    TCGv_i32 imm = tcg_constant_i32(a->imm);

    /* The helper may raise ILLEGAL_INSN -- record binv for unwind. */
    decode_save_opc(ctx);

    gen_helper_dasics_dibndquery(dest, cpu_env, imm);
    gen_set_gpr(ctx, a->rd, dest);

    /* We may have changed important cpu state -- exit to main loop. */
    gen_update_pc(ctx, ctx->cur_insn_len);
    exit_tb(ctx);
    ctx->base.is_jmp = DISAS_NORETURN;
    return true;
}