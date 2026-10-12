#include "rlwe_core.h"
#include "ntt.h"
#include <string.h>
#include <stdio.h>

// Modular arithmetic
int32_t mod_q(int32_t a) {
    a %= RLWE_Q;
    if (a < 0) a += RLWE_Q;
    return a;
}

// Initialize polynomial
void polynomial_init(Polynomial* poly) {
    memset(poly->coeffs, 0, RLWE_N * sizeof(int32_t));
}

// Clear polynomial
void polynomial_clear(Polynomial* poly) {
    memset(poly->coeffs, 0, RLWE_N * sizeof(int32_t));
}

/* No dynamic allocation was used for Polynomial structures, so free is a no‑op. */
void polynomial_free(Polynomial* poly) {
    (void)poly; /* suppress unused‑parameter warning */
}

// Copy polynomial
void polynomial_copy(Polynomial* dest, const Polynomial* src) {
    memcpy(dest->coeffs, src->coeffs, RLWE_N * sizeof(int32_t));
}

// Generate uniform polynomial
void polynomial_uniform(Polynomial* poly) {
    for (int i = 0; i < RLWE_N; i++) {
        poly->coeffs[i] = rand() % RLWE_Q;
    }
}

// Generate Gaussian polynomial (simplified)
void polynomial_gaussian(Polynomial* poly) {
    for (int i = 0; i < RLWE_N; i++) {
        // Simple approximation of Gaussian distribution
        int32_t val = 0;
        for (int j = 0; j < 12; j++) {
            val += rand() % 3 - 1;
        }
        poly->coeffs[i] = mod_q(val);
    }
}

// Polynomial addition
void polynomial_add(const Polynomial* a, const Polynomial* b, Polynomial* result) {
    for (int i = 0; i < RLWE_N; i++) {
        result->coeffs[i] = mod_q(a->coeffs[i] + b->coeffs[i]);
    }
}

// Polynomial subtraction
void polynomial_sub(const Polynomial* a, const Polynomial* b, Polynomial* result) {
    for (int i = 0; i < RLWE_N; i++) {
        result->coeffs[i] = mod_q(a->coeffs[i] - b->coeffs[i]);
    }
}

// Novel Hardware-Optimized NTT multiplication 
void polynomial_multiply_ntt(const Polynomial* a, const Polynomial* b, Polynomial* result) {
    Polynomial ntt_a, ntt_b;
    polynomial_copy(&ntt_a, a);
    polynomial_copy(&ntt_b, b);
    
    // Transform to frequency domain
    ntt(&ntt_a);
    ntt(&ntt_b);
    
    // Point-wise multiplication in NTT domain
    for (int i = 0; i < RLWE_N; i++) {
        result->coeffs[i] = (ntt_a.coeffs[i] * ntt_b.coeffs[i]) % RLWE_Q;
    }
    
    // Transform back to time domain
    inv_ntt(result);
}

// Forward NTT wrapper
void polynomial_ntt(Polynomial* poly) {
    ntt(poly);
}

// Inverse NTT wrapper
void polynomial_inv_ntt(Polynomial* poly) {
    inv_ntt(poly);
}
