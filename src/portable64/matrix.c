#include "qruov.h"

// C = A*B
#define MATRIX_MUL(N, K, M, A, B, C) {                             \
  int _i,_j,_k ;                                                   \
  _Pragma("omp parallel for private(_i,_j,_k) shared(A, B, C)")    \
  for(_i=0;_i<N;_i++){                                             \
    for(_j=0;_j<M;_j++){                                           \
      Fql_ACC(_t) ;                                                \
      Fql_ACC_ZERO(_t) ;                                           \
      for(_k=0;_k<K;_k++){                                         \
        Fql_ACC_MUL_ADD(A[_i][_k], B[_k][_j], _t) ;                \
      }                                                            \
      Fql_ACC_REDUCE(_t, C[_i][_j]) ;                              \
    }                                                              \
  }                                                                \
}

// C += A*B
#define MATRIX_MUL_ADD(N, K, M, A, B, C) {                         \
  int _i,_j,_k ;                                                   \
  _Pragma("omp parallel for private(_i,_j,_k) shared(A, B, C)")    \
  for(_i=0;_i<N;_i++){                                             \
    for(_j=0;_j<M;_j++){                                           \
      Fql_ACC(_t) ;                                                \
      Fql_ACC_ZERO(_t) ;                                           \
      for(_k=0;_k<K;_k++){                                         \
        Fql_ACC_MUL_ADD(A[_i][_k], B[_k][_j], _t) ;                \
      }                                                            \
      Fql _v ;                                                     \
      Fql_ACC_REDUCE(_t, _v) ;                                     \
      Fql_ADD(_v, C[_i][_j], C[_i][_j]) ;                          \
    }                                                              \
  }                                                                \
}

// C = A+B
#define MATRIX_ADD(N, M, A, B, C) {                          \
  int _i,_j ;                                                \
  _Pragma("omp parallel for private(_i,_j) shared(A, B, C)") \
  for(_i=0;_i<N;_i++){                                       \
    for(_j=0;_j<M;_j++){                                     \
      Fql_ADD(A[_i][_j], B[_i][_j], C[_i][_j]) ;             \
    }                                                        \
  }                                                          \
}

// C = A-B
#define MATRIX_SUB(N, M, A, B, C) {                          \
  int _i,_j ;                                                \
  _Pragma("omp parallel for private(_i,_j) shared(A, B, C)") \
  for(_i=0;_i<N;_i++){                                       \
    for(_j=0;_j<M;_j++){                                     \
      Fql_SUB(A[_i][_j], B[_i][_j], C[_i][_j]) ;             \
    }                                                        \
  }                                                          \
}

// C = A^T
#define MATRIX_TRANSPOSE(N, M, A, C) {                    \
  int _i,_j ;                                             \
  _Pragma("omp parallel for private(_i,_j) shared(A, C)") \
  for(_i=0;_i<N;_i++){                                    \
    for(_j=0;_j<M;_j++){                                  \
      Fql_COPY(A[_i][_j], C[_j][_i]) ;                    \
    }                                                     \
  }                                                       \
}

#define overflow_THRESHOLD                   (1<<(Fql_ws-2*QRUOV_ceil_log_2_q))

#define Fql_ACC(T)                           Fql_acc T ; int overflow_POOL ;
#define Fql_ACC_ZERO(A)                      { A = Fql_acc_zero ; overflow_POOL = 0 ; }

#  if (QRUOV_L== 3)
#  define overflow_DELTA 1
#elif (QRUOV_L==10)
#  define overflow_DELTA 5
#else
#  error "unsupported QRUOV_L"
#endif

#define Fql_ACC_MUL_ADD_0(A,B,C) {                                \
        if(overflow_POOL + overflow_DELTA > overflow_THRESHOLD){  \
          C = Fql_acc_refresh(C) ;                                \
          overflow_POOL = 0 ;                                     \
        } ;                                                       \
        C = Fql_acc_add(C, Fql_acc_mul(A,B)) ;                    \
        overflow_POOL += overflow_DELTA ;                         \
     }

#define Fql_ACC_DOUBLE_0(A,C)    {                                \
        if((overflow_POOL<<1) > overflow_THRESHOLD){              \
          C = Fql_acc_refresh(C) ;                                \
          overflow_POOL = 0 ;                                     \
        } ;                                                       \
        C = Fql_acc_add(C,C) ;                                    \
        overflow_POOL <<= 1 ;                                     \
     }

#define Fql_ACC_MUL_ADD_1(A,B,C) { C = Fql_acc_add(C, Fql_acc_mul(A,B)) ; }
#define Fql_ACC_DOUBLE_1(A,C)    { C = Fql_acc_add(C,C) ; }

#if (QRUOV_V * overflow_DELTA > overflow_THRESHOLD)
#  define Fql_ACC_MUL_ADD(A,B,C)  Fql_ACC_MUL_ADD_0(A,B,C)
#  define Fql_ACC_DOUBLE(A,C)     Fql_ACC_DOUBLE_0(A,C)                
#else
#  define Fql_ACC_MUL_ADD(A,B,C)  Fql_ACC_MUL_ADD_1(A,B,C)
#  define Fql_ACC_DOUBLE(A,C)     Fql_ACC_DOUBLE_1(A,C)                
#endif

#define Fql_ACC_REDUCE(A,C)                  { C = Fql_acc_reduce(A) ; }

#define Fql_ACC_DEBUG                        Fql
#define Fql_ACC_ZERO_DEBUG(A)                { A = Fql_zero ; }
#define Fql_ACC_MUL_ADD_DEBUG(A,B,C)         { C = Fql_add(C, Fql_mul(A,B)) ; }
#define Fql_ACC_REDUCE_DEBUG(A,C)            { C = A ; }

#define Fql_ADD(A,B,C)                       { C = Fql_add(A,B) ; }
#define Fql_SUB(A,B,C)                       { C = Fql_sub(A,B) ; }
#define Fql_COPY(A,C)                        { C = A ; }

void MATRIX_MUL_MxV_VxV(MATRIX_MxV A, MATRIX_VxV B, MATRIX_MxV C){
  // V
  MATRIX_MUL(QRUOV_M, QRUOV_V, QRUOV_V, A, B, C) ;
}

void MATRIX_MUL_MxV_VxM(MATRIX_MxV A, MATRIX_VxM B, MATRIX_MxM C){
  // V
  MATRIX_MUL(QRUOV_M, QRUOV_V, QRUOV_M, A, B, C) ;
}

void MATRIX_MUL_ADD_MxV_VxM(MATRIX_MxV A, MATRIX_VxM B, MATRIX_MxM C){
  // V
  MATRIX_MUL_ADD(QRUOV_M, QRUOV_V, QRUOV_M, A, B, C) ;
}

void MATRIX_SUB_MxV(MATRIX_MxV A, MATRIX_MxV B, MATRIX_MxV C){
  MATRIX_SUB(QRUOV_M, QRUOV_V, A, B, C) ;
}

void MATRIX_ADD_MxM(MATRIX_MxM A, MATRIX_MxM B, MATRIX_MxM C){
  MATRIX_ADD(QRUOV_M, QRUOV_M, A, B, C) ;
}

void MATRIX_TRANSPOSE_VxM(MATRIX_VxM A, MATRIX_MxV C){
  MATRIX_TRANSPOSE(QRUOV_V, QRUOV_M, A, C) ;
}

void EQN_GEN(VECTOR_V vineger, MATRIX_MxV F2T[QRUOV_m], Fq eqn[QRUOV_m][QRUOV_m]){
  int i,j,k ;
#pragma omp parallel for private(i,j,k) shared(vineger, F2T, eqn)
  for(i=0; i<QRUOV_m; i++){
    for(j=0; j<QRUOV_M; j++){
      Fql_ACC(t) ;
      Fql_ACC_ZERO(t) ; // V
      for(k=0; k<QRUOV_V; k++){
        Fql_ACC_MUL_ADD(vineger[k], F2T[i][j][k], t) ;
      }
      Fql u ;
      Fql_ACC_REDUCE(t, u) ;
      Fql_ADD(u, u, u) ;
      for(int l=0; l<QRUOV_L; l++){
        eqn[i][QRUOV_L*j+l] = Fql2Fq(u, QRUOV_perm(l)) ; // <- unpack_1(...)
      }
    }
  }
}

void C_GEN(VECTOR_V vineger, MATRIX_VxV F1[QRUOV_m], Fq c[QRUOV_m]){
  int i,j,k ;
#pragma omp parallel for private(i,j,k) shared(vineger, F1, c)
  for(i=0; i<QRUOV_m; i++){
    Fql tmp [QRUOV_V] ;
    for(j=0; j<QRUOV_V; j++){
      Fql_ACC(t) ;
      Fql_ACC_ZERO(t) ; // V
      for(k=0; k<QRUOV_V; k++){
        Fql_ACC_MUL_ADD(vineger[k], F1[i][j][k], t) ;
      }
      Fql_ACC_REDUCE(t, tmp[j]) ;
    }
    uint64_t c_i = 0 ;
    for(k=0; k<QRUOV_V; k++){
      c_i += (uint64_t) Fql2Fq(Fql_mul(tmp[k],vineger[k]), QRUOV_perm(0)) ; // <-- shrink
    }
    c[i] = (Fq)(c_i % QRUOV_q) ;
  }
}

#undef Fql_ACC_MUL_ADD
#undef Fql_ACC_DOUBLE
#if (QRUOV_M * overflow_DELTA > overflow_THRESHOLD)
#  define Fql_ACC_MUL_ADD(A,B,C)  Fql_ACC_MUL_ADD_0(A,B,C)
#  define Fql_ACC_DOUBLE(A,C)     Fql_ACC_DOUBLE_0(A,C)                
#else
#  define Fql_ACC_MUL_ADD(A,B,C)  Fql_ACC_MUL_ADD_1(A,B,C)
#  define Fql_ACC_DOUBLE(A,C)     Fql_ACC_DOUBLE_1(A,C)                
#endif

void SIG_GEN(VECTOR_M oil, MATRIX_MxV SdT, VECTOR_V vineger, QRUOV_SIGNATURE sig){
  int i,j ;
#pragma omp parallel for private(i,j) shared(oil, SdT, vineger, sig)
  for(i=0;i<QRUOV_V;i++){
    Fql_ACC(t) ;
    Fql_ACC_ZERO(t) ; // M
    for(j=0;j<QRUOV_M;j++){
      Fql_ACC_MUL_ADD(oil[j], SdT[j][i], t) ;
    }
    Fql u ;
    Fql_ACC_REDUCE(t, u) ;
    sig->s[i] = Fql_sub(vineger[i], u) ;
  }
  for(i=QRUOV_V;i<QRUOV_N;i++){
    sig->s[i] = oil[i-QRUOV_V] ;
  }
}

void RESULT_GEN(const QRUOV_P1 P1, const QRUOV_P2T P2T, const QRUOV_P3 P3, const VECTOR_M oil, const VECTOR_V vineger, const Fq msg [QRUOV_m], uint8_t result[QRUOV_m]) {
  int i,j,k ;
#pragma omp parallel for private(i,j,k) shared(P1, P2T, P3, oil, vineger, msg, result)
  for(i=0; i<QRUOV_m; i++){
    Fql tmp_v [QRUOV_V] ;
    Fql tmp_o [QRUOV_M] ;

#undef Fql_ACC_MUL_ADD
#undef Fql_ACC_DOUBLE
#if ((2*QRUOV_M+QRUOV_V) * overflow_DELTA > overflow_THRESHOLD)
#  define Fql_ACC_MUL_ADD(A,B,C)  Fql_ACC_MUL_ADD_0(A,B,C)
#  define Fql_ACC_DOUBLE(A,C)     Fql_ACC_DOUBLE_0(A,C)                
#else
#  define Fql_ACC_MUL_ADD(A,B,C)  Fql_ACC_MUL_ADD_1(A,B,C)
#  define Fql_ACC_DOUBLE(A,C)     Fql_ACC_DOUBLE_1(A,C)                
#endif

    Fql_ACC(t) ;
    for(j=0;j<QRUOV_V;j++){
      Fql_ACC_ZERO(t) ; // 2M+V
      for(k=0;k<QRUOV_M;k++){
        Fql_ACC_MUL_ADD(P2T[i][k][j],oil[k], t) ;
      }
      Fql_ACC_DOUBLE(t, t) ;
      for(k=0;k<QRUOV_V;k++){
        Fql_ACC_MUL_ADD(P1[i][j][k],vineger[k], t) ;
      }
      Fql_ACC_REDUCE(t, tmp_v[j]) ;
    }

#undef Fql_ACC_MUL_ADD
#undef Fql_ACC_DOUBLE
#if (QRUOV_M * overflow_DELTA > overflow_THRESHOLD)
#  define Fql_ACC_MUL_ADD(A,B,C)  Fql_ACC_MUL_ADD_0(A,B,C)
#  define Fql_ACC_DOUBLE(A,C)     Fql_ACC_DOUBLE_0(A,C)                
#else
#  define Fql_ACC_MUL_ADD(A,B,C)  Fql_ACC_MUL_ADD_1(A,B,C)
#  define Fql_ACC_DOUBLE(A,C)     Fql_ACC_DOUBLE_1(A,C)                
#endif

    for(j=0;j<QRUOV_M;j++){
      Fql_ACC_ZERO(t) ; // M
      for(k=0;k<QRUOV_M;k++){
        Fql_ACC_MUL_ADD(P3[i][j][k],oil[k],t) ;
      }
      Fql_ACC_REDUCE(t, tmp_o[j]) ;
    }

#undef Fql_ACC_MUL_ADD
#undef Fql_ACC_DOUBLE
#if ((QRUOV_V+QRUOV_M) * overflow_DELTA > overflow_THRESHOLD)
#  define Fql_ACC_MUL_ADD(A,B,C)  Fql_ACC_MUL_ADD_0(A,B,C)
#  define Fql_ACC_DOUBLE(A,C)     Fql_ACC_DOUBLE_0(A,C)                
#else
#  define Fql_ACC_MUL_ADD(A,B,C)  Fql_ACC_MUL_ADD_1(A,B,C)
#  define Fql_ACC_DOUBLE(A,C)     Fql_ACC_DOUBLE_1(A,C)                
#endif

    Fql_ACC_ZERO(t) ; // V+M
    for(j=0;j<QRUOV_V;j++){
      Fql_ACC_MUL_ADD(vineger[j],tmp_v[j],t) ;
    }
    for(j=0;j<QRUOV_M;j++){
      Fql_ACC_MUL_ADD(oil[j],tmp_o[j],t) ;
    }
    Fql t_dash ;
    Fql_ACC_REDUCE(t, t_dash) ;
    if(msg[i] != Fql2Fq(t_dash,QRUOV_perm(0))){ // <-- shrink
      result[i] = 0 ;
    }else{
      result[i] = 1 ;
    }
  }
}
