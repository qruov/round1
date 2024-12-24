#pragma once
#include "qruov_misc.h"
#include "mgf.h"

/* =====================================================================
   F_q
   ===================================================================== */

typedef uint8_t Fq ;

inline static Fq  Fq_ncRANDOM(){ return random() % QRUOV_q ; } // not for cryptography

// ============================================================================
// Fq add/sub ...
// ============================================================================

inline static Fq Fq_add(Fq X, Fq Y){ return (Fq)(((int) X + (int) Y) % QRUOV_q) ; }
inline static Fq Fq_sub(Fq X, Fq Y){ return (Fq)(((int) X - (int) Y + QRUOV_q) % QRUOV_q) ; }
inline static Fq Fq_mul(Fq X, Fq Y){ return (Fq)(((int) X * (int) Y) % QRUOV_q) ; }
inline static Fq Fq_inv(Fq X){ extern Fq Fq_inv_table[QRUOV_q] ; return Fq_inv_table[X] ; }

// ============================================================================
// F_q^L = F_q[X]/(f(X))
// ============================================================================

typedef struct Fql_t {
  Fq c[QRUOV_L] ;
} Fql ;

extern Fql Fql_zero ;

// ============================================================================
// F_q^L House keeping
// ============================================================================

inline static void Fql_fprint_n(FILE *stream, int n, char * header, void * A_){
  Fql * A = (Fql *) A_ ;
  fprintf(stream, "%s",header) ;
  for(int i=n-1;i>=0;i--)fprintf(stream, "%04x", A->c[i]) ;
  fprintf(stream, "\n") ;
}

inline static void Fql_print_n  (int n, char * header, void * A_){ Fql_fprint_n(stderr, n,   header, A_) ; }
inline static void Fql_print    (       char * header, Fql A    ){ Fql_print_n (QRUOV_L,  header, &A) ; }

#define Fql_PRINT(a)      Fql_print(#a " = ", a)

inline static int Fql_eq(Fql a, Fql b){ return memcmp(&a, &b, sizeof(Fql)) == 0 ; }
inline static int Fql_ne(Fql a, Fql b){ return ! Fql_eq(a, b) ; }

inline static Fq  Fql2Fq(Fql Z, int i){ return Z.c[i] ; }
inline static Fql Fq2Fql(uint16_t c[QRUOV_L]){ return *(Fql*)c ; }

inline static Fql Fql_ncRANDOM(){
  uint16_t c[QRUOV_L] ;
  for(int i=0;i<QRUOV_L;i++)c[i]=Fq_ncRANDOM();
  return Fq2Fql(c) ;
}

// ============================================================================
// Fq^L add/sub
// ============================================================================

inline static Fql Fql_add(Fql X, Fql Y){
  for(int i=0; i<QRUOV_L; i++) X.c[i] = Fq_add(X.c[i], Y.c[i]);
  return X ;
}

inline static Fql Fql_sub(Fql X, Fql Y){
  for(int i=0; i<QRUOV_L; i++) X.c[i] = Fq_sub(X.c[i], Y.c[i]);
  return X ;
}

// ============================================================================
// Fq^L mul
// ============================================================================

inline static Fql Fql_mul(Fql X, Fql Y){
  int T[2*QRUOV_L-1] ;
  memset(T, 0, sizeof(T)) ;

  for(size_t i=0; i<QRUOV_L; i++){
    for(size_t j=0; j<QRUOV_L; j++){
      T[i+j] += (int) X.c[i] * (int) Y.c[j] ;
    }
  }

  for(size_t i = 2*QRUOV_L-2; i >= QRUOV_L; i--){
      T[i-QRUOV_L]          += QRUOV_fc0 * T[i] ;
      T[i-QRUOV_L+QRUOV_fe] += QRUOV_fc  * T[i] ;
  }

  Fql Z ;
  for(size_t i=0; i<QRUOV_L; i++) Z.c[i] = (Fq)(T[i] % QRUOV_q) ;
  return Z ;
}

/* =====================================================================
   pseudo random number generator
   ===================================================================== */

TYPEDEF_STRUCT ( Fql_RANDOM_CTX,
  MGF_CTX   mgf_ctx ;
  unsigned  pool_bits ;
  uint64_t  pool ;
) ;

typedef uint8_t QRUOV_SEED  [QRUOV_SEED_LEN] ;
typedef uint8_t QRUOV_SALT  [QRUOV_SALT_LEN] ;

inline static void Fql_srandom_init(const uint8_t * seed, const size_t n0, Fql_RANDOM_CTX ctx){
  MGF_init(seed, n0, ctx->mgf_ctx) ;
  ctx->pool      = 0 ;
  ctx->pool_bits = 0 ;
  return ;
}

inline static void Fql_srandom(const QRUOV_SEED seed, Fql_RANDOM_CTX ctx){
  Fql_srandom_init(seed, QRUOV_SEED_LEN, ctx) ;
  return ;
}

inline static void Fql_srandom_update(const uint8_t * seed, const size_t n0, Fql_RANDOM_CTX ctx){
  MGF_update(seed, n0, ctx->mgf_ctx) ;
  return ;
}

/* random bits -> {0,...,q-1} */
extern Fq Fq_random (Fql_RANDOM_CTX ctx) ;

/* random bits -> (1) */
extern Fql   Fql_random (Fql_RANDOM_CTX ctx) ;
extern Fql * Fql_random_vector (Fql_RANDOM_CTX ctx, const size_t n0, Fql vec[]) ;

inline static void Fq_random_final (Fql_RANDOM_CTX ctx) {
  MGF_final(ctx->mgf_ctx) ;
  ctx->pool = 0 ;
}

inline static void Fql_random_final (Fql_RANDOM_CTX ctx) {
  Fq_random_final (ctx) ;
}

inline static void Fql_RANDOM_CTX_copy (Fql_RANDOM_CTX src, Fql_RANDOM_CTX dst) {
  memcpy(dst, src, sizeof(Fql_RANDOM_CTX)) ;
  MGF_CTX_copy(src->mgf_ctx, dst->mgf_ctx) ;
}

/* =====================================================================
   signature
   ===================================================================== */

typedef uint8_t QRUOV_SALT  [QRUOV_SALT_LEN] ;

TYPEDEF_STRUCT(QRUOV_SIGNATURE,
  QRUOV_SALT r           ;
  Fql        s [QRUOV_N] ;
) ;
