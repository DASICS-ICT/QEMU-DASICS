#ifndef RISCV_DASICS_H
#define RISCV_DASICS_H

#define MCFG_UCLS   0x8ul
#define MCFG_SCLS   0x4ul
#define MCFG_UENA   0X2ul
#define MCFG_SENA   0x1ul

#define SMCFG_MASK  0xf
#define UMCFG_MASK  0xa

#define LIBCFG_MASK 0xful
#define LIBCFG_V    0x8ul
#define LIBCFG_X    0x4ul
#define LIBCFG_R    0x2ul
#define LIBCFG_W    0x1ul

#define MAX_DASICS_LIBBOUNDS 16

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

    target_ulong    dmaincall;
    target_ulong    dretpc;
    target_ulong    dretpcfz;
} dasics_table_t;

int dasics_in_trusted_zone(CPURISCVState *env, target_ulong pc);
int dasics_match_dlib(CPURISCVState *env, target_ulong addr, target_ulong cfg);

#endif