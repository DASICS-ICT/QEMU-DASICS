#ifndef RISCV_DASICS_H
#define RISCV_DASICS_H

#define MCFG_CSFT   0x200ul
#define MCFG_CSLT   0x100ul
#define MCFG_CSST   0x80ul
#define MCFG_CSET   0x40ul
#define MCFG_CUFT   0x20ul
#define MCFG_CULT   0x10ul
#define MCFG_CUST   0x8ul
#define MCFG_CUET   0x4ul
#define MCFG_UENA   0x2ul
#define MCFG_SENA   0x1ul

#define UMCFG_MASK (MCFG_CUFT | MCFG_CULT | MCFG_CUST | MCFG_CUET | MCFG_UENA)
#define SMCFG_MASK (MCFG_CSFT | MCFG_CSLT | MCFG_CSST | MCFG_CSET | MCFG_CUFT | MCFG_CULT | MCFG_CUST | MCFG_CUET | MCFG_UENA | MCFG_SENA)

// #define MCFG_UCLS           0x8ul
// #define MCFG_SCLS           0x4ul
// #define MCFG_UENA           0X2ul
// #define MCFG_SENA           0x1ul

// #define SMCFG_MASK          0xf
// #define UMCFG_MASK          0xa

#define LIBCFG_MASK         0xbul
#define LIBCFG_V            0x8ul
#define LIBCFG_U            0x4ul
#define LIBCFG_R            0x2ul
#define LIBCFG_W            0x1ul

#define LIBJMPCFG_MASK      0x0001ul
#define LIBJMPCFG_V         0x0001ul

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
    target_ulong    dretpc;
    target_ulong    dretpcactz;
    target_ulong    dfreason;
} dasics_table_t;

int dasics_in_trusted_zone(CPURISCVState *env, target_ulong pc);
int dasics_in_active_zone(CPURISCVState *env, target_ulong pc);
int dasics_match_dlib(CPURISCVState *env, target_ulong addr, target_ulong cfg);

#endif