#include "ntt.h"

// Optimized In-Place Cooley-Tukey NTT for RLWE (N=512, Q=12289)
// Primitive 1024-th root of unity (zeta) modulo 12289 is 10302
#define ZETA 10302

static int32_t ntt_table[RLWE_N];
static int32_t inv_ntt_table[RLWE_N];

// Fast modular exponentiation
static int32_t power(int32_t base, int32_t exp) {
    int32_t res = 1;
    base = base % RLWE_Q;
    while (exp > 0) {
        if (exp % 2 == 1) res = (res * base) % RLWE_Q;
        base = (base * base) % RLWE_Q;
        exp /= 2;
    }
    return res;
}

// Bit-reversal for pre-computing Twiddle Factors
static uint16_t bit_reverse(uint16_t n) {
    uint16_t res = 0;
    for (int i = 0; i < 9; i++) {
        if ((n >> i) & 1) res |= (1 << (8 - i));
    }
    return res;
}

// Generate NTT Twiddle factor tables
void create_ntt_table(void) {
    for (int i = 0; i < RLWE_N; i++) {
        int rev = bit_reverse(i);
        ntt_table[i] = power(ZETA, rev);
        inv_ntt_table[i] = power(power(ZETA, RLWE_Q - 2), rev); // Modular inverse Euler
    }
}

// Novel Memory-Optimized In-Place NTT (Cooley-Tukey)
void ntt(Polynomial* a) {
    int k = 1;
    for (int len = RLWE_N / 2; len > 0; len >>= 1) {
        for (int i = 0; i < RLWE_N; i += 2 * len) {
            int32_t zeta = ntt_table[k++];
            for (int j = 0; j < len; j++) {
                int32_t t = a->coeffs[i + j];
                int32_t u = (a->coeffs[i + j + len] * zeta) % RLWE_Q;
                a->coeffs[i + j] = (t + u) % RLWE_Q;
                a->coeffs[i + j + len] = (t - u + RLWE_Q) % RLWE_Q;
            }
        }
    }
}

// Novel Memory-Optimized In-Place Inverse NTT (Gentleman-Sande)
void inv_ntt(Polynomial* a) {
    for (int len = 1; len < RLWE_N; len <<= 1) {
        int k = RLWE_N / (2 * len);
        for (int i = 0; i < RLWE_N; i += 2 * len) {
            int32_t zeta = inv_ntt_table[k++];
            for (int j = 0; j < len; j++) {
                int32_t t = a->coeffs[i + j];
                int32_t u = a->coeffs[i + j + len];
                a->coeffs[i + j] = (t + u) % RLWE_Q;
                a->coeffs[i + j + len] = ((t - u + RLWE_Q) * zeta) % RLWE_Q;
            }
        }
    }
    
    // Multiply by N^-1 mod Q (512^-1 mod 12289 = 12265)
    int32_t n_inv = 12265;
    for (int i = 0; i < RLWE_N; i++) {
        a->coeffs[i] = (a->coeffs[i] * n_inv) % RLWE_Q;
    }
}
