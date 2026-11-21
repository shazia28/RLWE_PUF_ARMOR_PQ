#ifndef RLWE_CORE_H
#define RLWE_CORE_H

#include <stdint.h>
#include <stdlib.h>

// RLWE parameters (q = 12289 < 2^14, fits in 16-bit signed integer)
#define RLWE_N 512
#define RLWE_Q 12289
#define RLWE_SIGMA 3.2
#define RLWE_PACKED_BYTES ((RLWE_N * 14) / 8) /* 896 bytes */

// Polynomial structure: 512 x int16_t = 1,024 bytes (1.0 KB)
typedef struct {
    int16_t coeffs[RLWE_N];
} Polynomial;

// Function declarations
void polynomial_init(Polynomial* poly);
void hex_to_polynomial(const char* hex_str, Polynomial* poly);
void polynomial_clear(Polynomial* poly);
void polynomial_free(Polynomial* poly);
void polynomial_copy(Polynomial* dest, const Polynomial* src);
void polynomial_uniform(Polynomial* poly);
void polynomial_gaussian(Polynomial* poly);
void polynomial_add(const Polynomial* a, const Polynomial* b, Polynomial* result);
void polynomial_sub(const Polynomial* a, const Polynomial* b, Polynomial* result);
int16_t mod_q(int32_t a);
void polynomial_multiply_ntt(const Polynomial* a, const Polynomial* b, Polynomial* result);
void polynomial_multiply_ntt_inplace(Polynomial* a_inout, Polynomial* b_scratch);
void polynomial_ntt(Polynomial* poly);
void polynomial_inv_ntt(Polynomial* poly);
void polynomial_pack14(const Polynomial* poly, uint8_t packed[RLWE_PACKED_BYTES]);
void polynomial_unpack14(const uint8_t packed[RLWE_PACKED_BYTES], Polynomial* poly);

#endif
