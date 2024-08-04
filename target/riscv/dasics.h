#ifndef RISCV_DASICS_H
#define RISCV_DASICS_H

#define MCFG_UCLS           0x8ul
#define MCFG_SCLS           0x4ul
#define MCFG_UENA           0X2ul
#define MCFG_SENA           0x1ul

#define SMCFG_MASK          0xf
#define UMCFG_MASK          0xa

#define LIBCFG_MASK         0xbul
#define LIBCFG_V            0x8ul
#define LIBCFG_U            0x4ul
#define LIBCFG_R            0x2ul
#define LIBCFG_W            0x1ul

#define LIBJMPCFG_MASK      0x0001ul
#define LIBJMPCFG_V         0x0001ul

#define LEVEL_MASK          0x3ul

#define DIBNDMV_SCRATCH_IDX  31

#define MAX_DASICS_LEVELS    4
#define MAX_DASICS_LIBBOUNDS 16
#define MAX_DASICS_LIBJMPBOUNDS 4

typedef struct {
    target_ulong hi;
    target_ulong lo;
} dasics_bound_t;

typedef struct {
    uint8_t         maincfg;
    dasics_bound_t  smbound;
    dasics_bound_t  umbound;

    uint8_t         libcfg[MAX_DASICS_LIBBOUNDS];
    dasics_bound_t  libbound[MAX_DASICS_LIBBOUNDS];

    uint16_t        libjmpcfg[MAX_DASICS_LIBJMPBOUNDS];
    dasics_bound_t  libjmpbound[MAX_DASICS_LIBJMPBOUNDS];

    target_ulong    dmaincall;
    target_ulong    dretpc[MAX_DASICS_LEVELS];
    target_ulong    dretpcactz;

    uint8_t         dmlevel[MAX_DASICS_LIBBOUNDS];
    uint8_t         djlevel[MAX_DASICS_LIBJMPBOUNDS];

    uint8_t         dscratchcfg;
    uint8_t         dscratchlevel;
    dasics_bound_t  dscratchbound;
} dasics_table_t;

int dasics_in_trusted_zone(CPURISCVState *env, target_ulong pc);
int dasics_in_active_zone(CPURISCVState *env, target_ulong pc, int lvl);
int dasics_match_dlib(CPURISCVState *env, target_ulong addr, target_ulong cfg, int lvl);
int dasics_get_mem_level_from_idx(CPURISCVState *env, int idx);
int dasics_get_jmp_level_from_idx(CPURISCVState *env, int idx);
int dasics_get_jmp_level(CPURISCVState *env, target_ulong pc);
int dasics_get_scratch_level(CPURISCVState *env);
int dasics_access_lib_csrs(int csrno);
enum BNDMV_TYPE {BNDMV_MEM, BNDMV_JMP};
enum BNDQUERY_TYPE {BNDQUERY_MEM, BNDQUERY_JMP};
enum BNDQUERY_STATUS {BNDQUERY_DENY, BNDQUERY_RO, BNDQUERY_RW, BNDQUERY_EMPTY};

#endif