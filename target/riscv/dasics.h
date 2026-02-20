#ifndef RISCV_DASICS_H
#define RISCV_DASICS_H

#define MCFG_CSSRG  0x800ul
#define MCFG_CUSRG  0x400ul
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

#define UMCFG_MASK (MCFG_CUSRG | MCFG_CUFT | MCFG_CULT | MCFG_CUST | MCFG_CUET | MCFG_UENA)
#define SMCFG_MASK (MCFG_CSSRG | MCFG_CUSRG | MCFG_CSFT | MCFG_CSLT | MCFG_CSST | MCFG_CSET | MCFG_CUFT | MCFG_CULT | MCFG_CUST | MCFG_CUET | MCFG_UENA | MCFG_SENA)

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

#define DASICS_SREG_COUNT         12
#define SREG_PHASE_INIT_LOCKED    0
#define SREG_PHASE_ACTIVE         1
#define SREG_PHASE_RESTORED_LOCKED 2

typedef struct {
    target_ulong hi;
    target_ulong lo;
} dasics_bound_t;

typedef struct {
    uint8_t         phase[DASICS_SREG_COUNT];
    uint8_t         saved_once[DASICS_SREG_COUNT];
    target_ulong    sp_off[DASICS_SREG_COUNT]; /* record only offset to sp */
    target_ulong    shadow_cipher[DASICS_SREG_COUNT];
    /* crypto framework v1 draft state (algorithm-swappable path) */
    uint8_t         crypto_algo; /* v1 default: A (PRF+MAC) */
    uint8_t         tag_bits;    /* 64 or 128 */
    target_ulong    shadow_tag_lo[DASICS_SREG_COUNT];
    target_ulong    shadow_tag_hi[DASICS_SREG_COUNT];
} dasics_sreg_guard_state_t;

typedef struct {
    uint16_t        maincfg;
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

    /* s-register guard (s0-s11, phase-1 minimal POC) */
    dasics_sreg_guard_state_t sreg;
} dasics_table_t;

int dasics_in_trusted_zone(CPURISCVState *env, target_ulong pc);
int dasics_in_active_zone(CPURISCVState *env, target_ulong pc);
int dasics_match_dlib(CPURISCVState *env, target_ulong addr, target_ulong cfg);
bool dasics_sreg_guard_enabled(CPURISCVState *env);

#endif
