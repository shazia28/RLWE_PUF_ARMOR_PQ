#ifndef RLWE_CORE_H
#define RLWE_CORE_H

#include <stdint.h>
#include <stdlib.h>

// RLWE parameters
#define RLWE_N 512
#define RLWE_Q 12289
#define RLWE_SIGMA 3.2

// Polynomial structure
typedef struct {
    int32_t coeffs[RLWE_N];
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
int32_t mod_q(int32_t a);
void polynomial_multiply_ntt(const Polynomial* a, const Polynomial* b, Polynomial* result);
void polynomial_ntt(Polynomial* poly);
void polynomial_inv_ntt(Polynomial* poly);

#endif
