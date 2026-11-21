#include "rlwe_core.h"
#include "ntt.h"
#include <string.h>
#include <stdio.h>

// Canonical modular reduction into [0, RLWE_Q - 1]
int16_t mod_q(int32_t a) {
    a %= RLWE_Q;
    if (a < 0) a += RLWE_Q;
    return (int16_t)a;
}

// Initialize 1,024-byte polynomial buffer
void polynomial_init(Polynomial* poly) {
    memset(poly->coeffs, 0, RLWE_N * sizeof(int16_t));
}

// Zeroize polynomial buffer in volatile SRAM
void polynomial_clear(Polynomial* poly) {
    volatile int16_t* p = poly->coeffs;
    for (int i = 0; i < RLWE_N; i++) {
        p[i] = 0;
    }
}

/* No dynamic heap allocation is used for Polynomial structures. */
void polynomial_free(Polynomial* poly) {
    (void)poly;
}

// Copy 1,024-byte polynomial
void polynomial_copy(Polynomial* dest, const Polynomial* src) {
    memcpy(dest->coeffs, src->coeffs, RLWE_N * sizeof(int16_t));
}

// Generate uniform polynomial over R_q
void polynomial_uniform(Polynomial* poly) {
    for (int i = 0; i < RLWE_N; i++) {
        poly->coeffs[i] = (int16_t)(rand() % RLWE_Q);
    }
}

// Generate centered discrete Gaussian polynomial (sigma approx 3.2)
void polynomial_gaussian(Polynomial* poly) {
    for (int i = 0; i < RLWE_N; i++) {
        int32_t val = 0;
        for (int j = 0; j < 15; j++) {
            val += (rand() % 3) - 1;
        }
        poly->coeffs[i] = mod_q(val);
    }
}

// Coefficient-wise addition mod q (supports in-place result == a or result == b)
void polynomial_add(const Polynomial* a, const Polynomial* b, Polynomial* result) {
    for (int i = 0; i < RLWE_N; i++) {
        result->coeffs[i] = mod_q((int32_t)a->coeffs[i] + (int32_t)b->coeffs[i]);
    }
}

// Coefficient-wise subtraction mod q
void polynomial_sub(const Polynomial* a, const Polynomial* b, Polynomial* result) {
    for (int i = 0; i < RLWE_N; i++) {
        result->coeffs[i] = mod_q((int32_t)a->coeffs[i] - (int32_t)b->coeffs[i]);
    }
}

// Zero-extra-buffer in-place NTT multiplication: a_inout = INTT(NTT(a_inout) o NTT(b_scratch))
void polynomial_multiply_ntt_inplace(Polynomial* a_inout, Polynomial* b_scratch) {
    ntt(a_inout);
    ntt(b_scratch);
    for (int i = 0; i < RLWE_N; i++) {
        a_inout->coeffs[i] = (int16_t)(((int32_t)a_inout->coeffs[i] * (int32_t)b_scratch->coeffs[i]) % RLWE_Q);
    }
    inv_ntt(a_inout);
}

// Hardware-Optimized NTT multiplication using result buffer in-place + 1 working polynomial (1,024 B)
void polynomial_multiply_ntt(const Polynomial* a, const Polynomial* b, Polynomial* result) {
    Polynomial ntt_b;
    polynomial_copy(&ntt_b, b);
    if (result != a) {
        polynomial_copy(result, a);
    }
    polynomial_multiply_ntt_inplace(result, &ntt_b);
    polynomial_clear(&ntt_b);
}

// Forward NTT wrapper
void polynomial_ntt(Polynomial* poly) {
    ntt(poly);
}

// Inverse NTT wrapper
void polynomial_inv_ntt(Polynomial* poly) {
    inv_ntt(poly);
}

// 14-bit lossless bitstream packing: 512 x 14 bits = 896 bytes
void polynomial_pack14(const Polynomial* poly, uint8_t packed[RLWE_PACKED_BYTES]) {
    memset(packed, 0, RLWE_PACKED_BYTES);
    uint32_t bit_pos = 0;
    for (int i = 0; i < RLWE_N; i++) {
        uint16_t val = (uint16_t)(mod_q(poly->coeffs[i])) & 0x3FFFU;
        for (int b = 0; b < 14; b++) {
            if ((val >> b) & 1U) {
                packed[bit_pos >> 3] |= (uint8_t)(1U << (bit_pos & 7U));
            }
            bit_pos++;
        }
    }
}

// 14-bit lossless bitstream unpacking: 896 bytes -> 512 x int16_t
void polynomial_unpack14(const uint8_t packed[RLWE_PACKED_BYTES], Polynomial* poly) {
    uint32_t bit_pos = 0;
    for (int i = 0; i < RLWE_N; i++) {
        uint16_t val = 0;
        for (int b = 0; b < 14; b++) {
            if ((packed[bit_pos >> 3] >> (bit_pos & 7U)) & 1U) {
                val |= (uint16_t)(1U << b);
            }
            bit_pos++;
        }
        poly->coeffs[i] = (int16_t)(val % RLWE_Q);
    }
}
