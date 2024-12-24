### the Round 1 Reference Implementation of qruov
- Wed May 31 03:08:39 JST 2023
  - done:
    - sha2_evp
    - shake128/shake256 streaming input/output
      - openssl-1.1.1t
      - openssl-3.1.0
    - sampling order of P1 and P2
    - ref
      - portable
    - portable64
      - 22 bit accumulation for extension of degree 3
      - 16 bit accumulation
  - working:
    - avx2
      - based on ref. not so optimized
    - avx512
      - based on ref. not so optimized
  - todo:
    - secret independent
      - rejection sampling
      - linear equation solver
    - pending
      - aes256_ctr_drbg
      - strassen algorithm
      - krylov subspace methods
      - montgomery reduction

