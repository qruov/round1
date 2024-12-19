#pragma once

#define Fql_h_DEBUG 0

#if (Fql_h_DEBUG==2)

#  define QRUOV_q                           7
#  define QRUOV_L                          10

#  if   (QRUOV_q==127) && (QRUOV_L== 3)
#    define QRUOV_fc                        1
#    define QRUOV_fe                        1
#    define QRUOV_fc0                       1
#  elif (QRUOV_q== 31) && (QRUOV_L== 3)
#    define QRUOV_fc                        1
#    define QRUOV_fe                        1
#    define QRUOV_fc0                       1
#  elif (QRUOV_q== 31) && (QRUOV_L==10)
#    define QRUOV_fc                        5
#    define QRUOV_fe                        3
#    define QRUOV_fc0                       1
#  elif (QRUOV_q==  7) && (QRUOV_L==10)
#    define QRUOV_fc                        2
#    define QRUOV_fe                        1
#    define QRUOV_fc0                       1
#  else
#    error "unknown (QRUOV_q, QRUOV_L)"
#  endif

#  define QRUOV_security_strength_category 1
#  define QRUOV_v                          156
#  define QRUOV_m                          54

#  define QRUOV_PLATFORM                   portable64
#  define DO_NOT_QRUOV_CONFIG
#endif

#include "qruov_misc.h"

#if ! ((QRUOV_q == 127) && (QRUOV_L ==  3 )|| \
       (QRUOV_q ==  31) && (QRUOV_L ==  3 )|| \
       (QRUOV_q ==  31) && (QRUOV_L == 10 )|| \
       (QRUOV_q ==   7) && (QRUOV_L == 10 ))
#    error "unsupported QRUOV_q and QRUOV_L in Fql_acc_reduce_1()"
#endif

#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include "mgf.h"

#if Fql_h_DEBUG
#  define Fq_reduction(X)    Fq_reduction_debug(X)
#  define Fql_reduction(X)   Fql_reduction_debug(X)
#  define Fql_acc_refresh(X) Fql_acc_refresh_debug(X)
#  define Fql_acc_reduce(X)  Fql_acc_reduce_debug(X)
#  define Fql_mul(X,Y)       Fql_mul_debug(X,Y)
#else
#  define Fq_reduction(X)    Fq_reduction_1(X)
#  define Fql_reduction(X)   Fql_reduction_1(X)
#  define Fql_acc_refresh(X) Fql_acc_refresh_1(X)
#  define Fql_acc_reduce(X)  Fql_acc_reduce_1(X)
#  define Fql_mul(X,Y)       Fql_mul_1(X,Y)
#endif

// ============================================================================
// F_q  (q = 2^c - 1)
// ============================================================================

typedef uint8_t Fq ;

inline static Fq  Fq_ncRANDOM(){ return random() % QRUOV_q ; } // not for cryptography

// ============================================================================
// Fq_reduction
// ============================================================================

inline static int Fq_reduction_0(int Z){ return Z % QRUOV_q ; }

inline static int Fq_reduction_1(int Z){
      Z = (Z & QRUOV_q) + ((Z & ~QRUOV_q) >> QRUOV_ceil_log_2_q) ;
  int C = ((Z+1) & ~QRUOV_q) ;
      Z += (C>>QRUOV_ceil_log_2_q) ;
      Z -= C ;
  return Z ;
}

inline static int Fq_reduction_debug(int Z);

// ============================================================================
// Fq add/sub ...
// ============================================================================

inline static Fq Fq_add(Fq X, Fq Y){ return (Fq)Fq_reduction((int)X+(int)Y) ; }
inline static Fq Fq_sub(Fq X, Fq Y){ return (Fq)Fq_reduction((int)X-(int)Y+QRUOV_q) ; }
inline static Fq Fq_mul(Fq X, Fq Y){ return (Fq)Fq_reduction((int)X*(int)Y) ; }
inline static Fq Fq_inv(Fq X){ extern Fq Fq_inv_table[QRUOV_q] ; return Fq_inv_table[X] ; }

// ============================================================================
// hardware
// ============================================================================
// ws: word size
// wm: word mask

#if QRUOV_L == 3 
#  define Fql_ws               (24)
#  define Fql_wm               ((1ULL<<Fql_ws)-1)
#  define Fql_mask_(n)         (((uint64_t)QRUOV_q)<<(Fql_ws*(n)))
#  define Fql_mask             (Fql_mask_(0)|Fql_mask_(1)|Fql_mask_(2))
#  define Fql_mask_one_(n)     (((uint64_t)1ULL)<<(Fql_ws*(n)))
#  define Fql_mask_one         (Fql_mask_one_(0)|Fql_mask_one_(1)|Fql_mask_one_(2))
#  define Fql_2_mask_(n)       (((uint64_t)((1<<(QRUOV_ceil_log_2_q*2))-1))<<(Fql_ws*(n)))
#  define Fql_2_mask           (Fql_2_mask_(0)|Fql_2_mask_(1)|Fql_2_mask_(2))
#  define Fql_acc_mask_(n)     (((UINT128_T)QRUOV_q)<<(Fql_ws*(n)))
#  define Fql_acc_mask         (Fql_acc_mask_(0)|Fql_acc_mask_(1)|Fql_acc_mask_(2)|Fql_acc_mask_(3)|Fql_acc_mask_(4))
#  define Fql_acc_mask_one_(n) (((UINT128_T)1ULL)<<(Fql_ws*(n)))
#  define Fql_acc_mask_one     (Fql_acc_mask_one_(0)|Fql_acc_mask_one_(1)|Fql_acc_mask_one_(2)|Fql_acc_mask_one_(3)|Fql_acc_mask_one_(4))
#  define Fql_2_acc_mask_(n)   (((UINT128_T)((1<<(QRUOV_ceil_log_2_q*2))-1))<<(Fql_ws*(n)))
#  define Fql_2_acc_mask       (Fql_2_acc_mask_(0)|Fql_2_acc_mask_(1)|Fql_2_acc_mask_(2)|Fql_2_acc_mask_(3)|Fql_2_acc_mask_(4))
#  define Fql_U_SIZE 1
#elif QRUOV_L == 10 
#  define Fql_ws               (16)
#  define Fql_wm               ((1ULL<<Fql_ws)-1)
#  define Fql_mask_(n)         (((uint64_t)QRUOV_q)<<(Fql_ws*(n)))
#  define Fql_mask             (Fql_mask_(0)|Fql_mask_(1)|Fql_mask_(2)|Fql_mask_(3))
#  define Fql_mask_one_(n)     (((uint64_t)1ULL)<<(Fql_ws*(n)))
#  define Fql_mask_one         (Fql_mask_one_(0)|Fql_mask_one_(1)|Fql_mask_one_(2)|Fql_mask_one_(3))
#  define Fql_2_mask_(n)       (((uint64_t)((1<<(QRUOV_ceil_log_2_q*2))-1))<<(Fql_ws*(n)))
#  define Fql_2_mask           (Fql_2_mask_(0)|Fql_2_mask_(1)|Fql_2_mask_(2)|Fql_2_mask_(3))
#  define Fql_U_SIZE 3
#endif
#define Fql_AU_SIZE  (2*(Fql_U_SIZE))

typedef union Fql_union_t {
  uint64_t c64[Fql_U_SIZE*1] ;
  uint32_t c32[Fql_U_SIZE*2] ;
  uint16_t c16[Fql_U_SIZE*4] ;
  uint8_t  c8 [Fql_U_SIZE*8] ;
} Fql_union ;

typedef union Fql_acc_union_t {
  uint64_t  c64[Fql_AU_SIZE*1] ;
  uint32_t  c32[Fql_AU_SIZE*2] ;
  uint16_t  c16[Fql_AU_SIZE*4] ;
  uint8_t   c8 [Fql_AU_SIZE*8] ;
  Fql_union c                  ;
} Fql_acc_union ;

#if QRUOV_L == 3
typedef   uint64_t     Fql ;
typedef   UINT128_T    Fql_acc ;
#  define Fql_zero     ((Fql)0)
#  define Fql_acc_zero ((Fql_acc)0)
#elif QRUOV_L == 10
typedef Fql_union      Fql ;
typedef Fql_acc_union  Fql_acc ;
extern  Fql            Fql_zero ;
extern  Fql_acc        Fql_acc_zero ;
#endif

// ============================================================================
// F_q^L House keeping
// ============================================================================

inline static void Fql_fprint_n(FILE *stream, int n, char * header, void * A_){
  Fql_acc_union * A = (Fql_acc_union *) A_ ;
  fprintf(stream, "%s",header) ;
  for(int i=n-1;i>=0;i--)fprintf(stream, "%016lx", A->c64[i]) ;
  fprintf(stream, "\n") ;
}

inline static void Fql_print_n  (int n, char * header, void * A_){ Fql_fprint_n(stderr, n,   header, A_) ; }
inline static void Fql_print    (       char * header, Fql A    ){ Fql_print_n (Fql_U_SIZE,  header, &A) ; }
inline static void Fql_acc_print(       char * header, Fql_acc A){ Fql_print_n (Fql_AU_SIZE, header, &A) ; }

#define Fql_PRINT(a)      Fql_print(#a " = ", a)
#define Fql_acc_PRINT(a)  Fql_acc_print(#a " = ", a)

inline static int Fql_eq(Fql a, Fql b){ return memcmp(&a, &b, sizeof(Fql)) == 0 ; }
inline static int Fql_ne(Fql a, Fql b){ return ! Fql_eq(a, b) ; }
inline static int Fql_acc_eq(Fql_acc a, Fql_acc b){ return memcmp(&a, &b, sizeof(Fql_acc)) == 0 ; }
inline static int Fql_acc_ne(Fql_acc a, Fql_acc b){ return ! Fql_acc_eq(a, b) ; }

#if QRUOV_L ==  3
inline static Fq  Fql2Fq(Fql Z, int i){ return ((Z >> ((Fql_ws)*i)) & QRUOV_q) ; }
inline static Fql Fq2Fql(Fql z0, Fql z1, Fql z2){ return z0|(z1<<Fql_ws)|(z2<<(Fql_ws*2)) ; }
inline static Fql_acc Fq2Fql_acc(Fql z0, Fql z1, Fql z2, Fql z3, Fql z4){
  return ((UINT128_T)z0<<(Fql_ws*0))|
         ((UINT128_T)z1<<(Fql_ws*1))|
	 ((UINT128_T)z2<<(Fql_ws*2))|
	 ((UINT128_T)z3<<(Fql_ws*3))|
	 ((UINT128_T)z4<<(Fql_ws*4));
}
// non cryptographic random
inline static Fql Fql_ncRANDOM(){ return Fq2Fql(Fq_ncRANDOM(), Fq_ncRANDOM(), Fq_ncRANDOM()) ; }
inline static Fql Fql_acc_ncRANDOM(){ return Fq2Fql_acc(Fq_ncRANDOM(), Fq_ncRANDOM(), Fq_ncRANDOM(), Fq_ncRANDOM(), Fq_ncRANDOM()) ; }
#elif QRUOV_L == 10
#  if   __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#    define WORD_ORDER(i)   (i)
#  elif   __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#    define WORD_ORDER(i)   (((i>>2)<<2)+(3-(i&3)))
#  else 
#    error "unsupported WORD_ORDER()"
#  endif
inline static Fq  Fql2Fq(Fql Z, int i){ return Z.c16[WORD_ORDER(i)] ; }
inline static Fql Fq2Fql(uint16_t c[QRUOV_L]){
  Fql Z ;
  Z.c64[Fql_U_SIZE-1] = 0 ;
  for(int i=0; i<QRUOV_L; i++) Z.c16[WORD_ORDER(i)] = c[i] ;
  return Z ;
}
inline static Fql_acc Fq2Fql_acc(uint16_t c[2*QRUOV_L-1]){
  Fql_acc Z ;
  Z.c64[Fql_AU_SIZE-1] = 0 ;
  for(int i=0; i<2*QRUOV_L-1; i++) Z.c16[WORD_ORDER(i)] = c[i] ;
  return Z ;
}
inline static Fql Fql_ncRANDOM(){
  uint16_t c[QRUOV_L] ;
  for(int i=0;i<QRUOV_L;i++)c[i]=Fq_ncRANDOM();
  return Fq2Fql(c) ;
}
inline static Fql_acc Fql_acc_ncRANDOM(){
  uint16_t c[2*QRUOV_L-1] ;
  for(int i=0;i<2*QRUOV_L-1;i++)c[i]=Fq_ncRANDOM();
  return Fq2Fql_acc(c) ;
}
#endif

// ============================================================================
// Fql_reduction
// ============================================================================

// ============================================================================
// Fq^L add/sub
// ============================================================================

// ============================================================================
// Fq^L accumulator add/sub
// ============================================================================

// ============================================================================
// Fq^L accumulator refresh
// ============================================================================

// ============================================================================
// Fq^L accumulator reduce
// ============================================================================

// ============================================================================
// Fq^L mul
// ============================================================================

#if   (QRUOV_q == 127) && (QRUOV_L == 3)
#  include "Fql_L3.h"
#elif (QRUOV_q ==  31) && (QRUOV_L == 3)
#  include "Fql_L3.h"
#elif (QRUOV_q ==  31) && (QRUOV_L == 10)
#  include "Fql_L10.h"
#  include "Fql_q31L10.h"
#elif (QRUOV_q ==   7) && (QRUOV_L == 10)
#  include "Fql_L10.h"
#  include "Fql_q7L10.h"
#else
#  error "unknown (QRUOV_q, QRUOV_L)"
#endif

// ============================================================================
// for debug
// ============================================================================

inline static int Fq_reduction_debug(int z){
  int z0 = Fq_reduction_0(z) ;
  static int flag = 1 ;
  _Pragma("omp shared(flag)")
  if(flag){
    int z1 = Fq_reduction_1(z) ;
    if(z0!=z1){
      _Pragma("omp single")
      {
        fprintf(stderr, "error : Fq_reduction(z)\n") ;
        flag = 0 ;
      }
    }
  }
  return z0 ;
}

inline static Fql Fql_reduction_debug(Fql z){
  Fql z0 = Fql_reduction_0(z) ;
  static int flag = 1 ;
  _Pragma("omp shared(flag)")
  if(flag){
    Fql z1 = Fql_reduction_1(z) ;
    if(Fql_ne(z0,z1)){
      _Pragma("omp single")
      {
        fprintf(stderr, "error: Fql_reduction(z)\n") ;
        Fql_PRINT(z) ;
        Fql_PRINT(z0) ;
        Fql_PRINT(z1) ;
        flag = 0 ;
      }
    }
  }
  return z0 ;
}

inline static Fql_acc Fql_acc_refresh_debug(Fql_acc Z){
  Fql_acc z0 = Fql_acc_refresh_0(Z) ;
  static int flag = 1 ;
  _Pragma("omp shared(flag)")
  if(flag){
    Fql_acc z1 = Fql_acc_refresh_1(Z) ;
    if(Fql_acc_ne(z0,z1)){
      _Pragma("omp single")
      {
        fprintf(stderr, "error: Fql_acc_refresh(z)\n") ;
        flag = 0 ;
      }
    }
  }
  return z0 ;
}

inline static Fql Fql_acc_reduce_debug(Fql_acc z){
  Fql z0 = Fql_acc_reduce_0(z) ;
  static int flag = 1 ;
  _Pragma("omp shared(flag)")
  if(flag){
    Fql z1 = Fql_acc_reduce_1(z) ;
    if(Fql_ne(z0,z1)){
      _Pragma("omp single")
      {
        fprintf(stderr, "error: Fql_acc_reduce(z)\n") ;
        flag = 0 ;
      }
    }
  }
  return z0 ;
}

inline static Fql Fql_mul_debug(Fql X, Fql Y){
  Fql z0 = Fql_mul_0(X, Y);
  static int flag = 1 ;
  _Pragma("omp shared(flag)")
  if(flag){
    Fql z1 = Fql_mul_1(X, Y) ;
    if(Fql_ne(z0,z1)){
      _Pragma("omp single")
      {
        fprintf(stderr, "error : Fql_mul\n") ;
        Fql_PRINT(X) ;
        Fql_PRINT(Y) ;
        Fql_PRINT(z0) ;
        Fql_PRINT(z1) ;
        flag = 0 ;
      }
    }
  }
  return z0 ;
}

/* =====================================================================
   for debug
   ===================================================================== */

#if (Fql_h_DEBUG==2)

#if QRUOV_L == 10
Fql             Fql_zero ;
Fql_acc         Fql_acc_zero ;
#endif

int main(int argc, char * argv[]){

  if(argc < 4) {
    fprintf(stderr, "usage: %s FUNC ID N\n", argv[0]) ;
    fprintf(stderr, "  %s\n" "  %s\n" "  %s\n",
          "FUNC \\in {0,...,4}", "ID   \\in {0,1,2}", "N    \\in \\N" ) ;
    return 1 ;
  }

  uint64_t func = atoll(argv[1])     ;
  uint64_t ID   = atoll(argv[2])?1:0 ;
  uint64_t n    = atoll(argv[3])     ;

  Fql_acc  TT= Fql_acc_zero ;
  Fql      T = Fql_zero ;
  uint64_t t = 0 ;

  printf("FUNC=%ld, ID=%ld, N=%ld\n",func,ID,n);
  switch(ID){
    case 0:
      switch(func){
        case 0:  for(uint64_t i=0; i<n; i++) t += Fq_reduction_0(i) ; break ;
        case 1:  for(uint64_t i=0; i<n; i++) T = Fql_add(T, Fql_reduction_0(Fql_ncRANDOM())) ; break ;
        case 2:  for(uint64_t i=0; i<n; i++) TT= Fql_acc_add(TT, Fql_acc_refresh_0(Fql_acc_ncRANDOM())) ; break ;
        case 3:  for(uint64_t i=0; i<n; i++) T = Fql_add(T, Fql_acc_reduce_0(Fql_acc_ncRANDOM())) ; break ;
        default: for(uint64_t i=0; i<n; i++) T = Fql_add(T, Fql_mul_0(Fql_ncRANDOM(), Fql_ncRANDOM())); break ;
      }
      break ;
    case 1:
      switch(func){
        case 0:  for(uint64_t i=0; i<n; i++) t += Fq_reduction_1(i) ; break ;
        case 1:  for(uint64_t i=0; i<n; i++) T = Fql_add(T, Fql_reduction_1(Fql_ncRANDOM())) ; break ;
        case 2:  for(uint64_t i=0; i<n; i++) TT= Fql_acc_add(TT, Fql_acc_refresh_1(Fql_acc_ncRANDOM())) ; break ;
        case 3:  for(uint64_t i=0; i<n; i++) T = Fql_add(T, Fql_acc_reduce_1(Fql_acc_ncRANDOM())) ; break ;
        default: for(uint64_t i=0; i<n; i++) T = Fql_add(T, Fql_mul_1(Fql_ncRANDOM(), Fql_ncRANDOM())); break ;
      }
      break;
    default:
      switch(func){
        case 0:  for(uint64_t i=0; i<n; i++) t += Fq_reduction(i) ; break ;
        case 1:  for(uint64_t i=0; i<n; i++) T = Fql_add(T, Fql_reduction(Fql_ncRANDOM())) ; break ;
        case 2:  for(uint64_t i=0; i<n; i++) TT= Fql_acc_add(TT, Fql_acc_refresh(Fql_acc_ncRANDOM())) ; break ;
        case 3:  for(uint64_t i=0; i<n; i++) T = Fql_add(T, Fql_acc_reduce(Fql_acc_ncRANDOM())) ; break ;
        default: for(uint64_t i=0; i<n; i++) T = Fql_add(T, Fql_mul(Fql_ncRANDOM(), Fql_ncRANDOM())); break ;
      }
      break;
  }
  printf("%ld\n", t) ;
  Fql_PRINT(T) ;
  Fql_acc_PRINT(TT) ;
  return 0 ;
}

#endif

/* =====================================================================
   pseudo random number generator
   ===================================================================== */

TYPEDEF_STRUCT ( Fql_RANDOM_CTX,
  MGF_CTX   mgf_ctx ;
  unsigned  pool_bits ;
  uint64_t  pool ;
) ;

typedef uint8_t QRUOV_SEED  [QRUOV_SEED_LEN] ;

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
