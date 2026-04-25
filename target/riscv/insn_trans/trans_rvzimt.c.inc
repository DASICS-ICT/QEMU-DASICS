/*
 * RISC-V translation routines for Zimt memory tagging extension.
 */

#define REQUIRE_ZIMT(ctx) do {           \
    if (!(ctx)->cfg_ptr->ext_zimt) {     \
        return false;                    \
    }                                    \
} while (0)

static bool trans_zimt_tagop(DisasContext *ctx, arg_zimt_tag *a)
{
    REQUIRE_ZIMT(ctx);

    if (a->rd == 0) {
        TCGv src = get_gpr(ctx, a->rs1, EXT_NONE);
        gen_helper_zimt_checktag(tcg_env, src, tcg_constant_tl(a->tag_imm4));
        return true;
    }

    if (a->rs1 == 0 && a->tag_imm4 == 0) {
        TCGv src = get_gpr(ctx, a->rd, EXT_NONE);
        TCGv dest = dest_gpr(ctx, a->rd);
        gen_helper_zimt_gentag(dest, tcg_env, src);
        gen_set_gpr(ctx, a->rd, dest);
        return true;
    }

    {
        TCGv src = get_gpr(ctx, a->rs1, EXT_NONE);
        TCGv dest = dest_gpr(ctx, a->rd);
        gen_helper_zimt_addtag(dest, tcg_env, src, tcg_constant_tl(a->tag_imm4));
        gen_set_gpr(ctx, a->rd, dest);
        return true;
    }
}

static bool trans_zimt_settag(DisasContext *ctx, arg_zimt_settag *a)
{
    REQUIRE_ZIMT(ctx);
    gen_helper_zimt_settag(tcg_env, get_gpr(ctx, a->rs1, EXT_NONE),
                           tcg_constant_tl(a->tag_imm4));
    return true;
}
