#include "rlwe_puf_auth.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include "sha_portable.h"
#include "ntt.h"

// Convert 64-byte SHA-512 binary digest to 128-char hex string
static void digest_to_hex(const uint8_t digest[SHA512_DIGEST_LENGTH], char output[MAX_HASH_LENGTH]) {
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        sprintf(output + i * 2, "%02x", digest[i]);
    }
    output[128] = '\0';
}

// Stream a 16-bit polynomial (packed 14-bit representation) into an active SHA-512 context
// using a 56-byte (32-coefficient) chunk buffer (zero 896-byte or 8,192-byte stack buffers)
static __attribute__((noinline)) void sha512_update_polynomial(sha512_context* ctx, const Polynomial* poly) {
    uint8_t chunk[56]; /* 32 coefficients x 14 bits = 448 bits = 56 bytes */
    for (int blk = 0; blk < RLWE_N; blk += 32) {
        memset(chunk, 0, sizeof(chunk));
        uint32_t bit_pos = 0;
        for (int i = 0; i < 32; i++) {
            uint16_t val = (uint16_t)(mod_q(poly->coeffs[blk + i])) & 0x3FFFU;
            for (int b = 0; b < 14; b++) {
                if ((val >> b) & 1U) {
                    chunk[bit_pos >> 3] |= (uint8_t)(1U << (bit_pos & 7U));
                }
                bit_pos++;
            }
        }
        sha512_update(ctx, chunk, sizeof(chunk));
    }
}

void sha3_512(const char* input, char* output) {
    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512_simple((const unsigned char*)input, strlen(input), hash);
    digest_to_hex(hash, output);
}

void sha512(const char* input, size_t length, char* output) {
    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512_simple((const unsigned char*)input, length, hash);
    digest_to_hex(hash, output);
}

// Exact Peikert Shift Reconciliation Hint (Eq. 10):
// w_k = round(4 * x / q) mod 2 = floor((4 * x + q/2) / q) mod 2
void peikert_signal(const Polynomial* poly, uint8_t* w_signal) {
    for (int i = 0; i < RLWE_N / 8; i++) {
        uint8_t byte = 0;
        for (int j = 0; j < 8; j++) {
            int32_t val = poly->coeffs[i * 8 + j] % RLWE_Q;
            if (val < 0) val += RLWE_Q;
            int w = ((4 * val + (RLWE_Q / 2)) / RLWE_Q) & 1;
            if (w) byte |= (uint8_t)(1U << j);
        }
        w_signal[i] = byte;
    }
}

// Exact Unified Peikert Shift Reconciliation (Eqs. 11-12):
// x' = (x - w_k * 3072) mod q, K_k = round(2 * x' / q) mod 2
void peikert_reconcile(const Polynomial* poly, const uint8_t* w_signal, char* hex_str) {
    const int32_t q_quarter = 3072; /* round(12289 / 4) = 3072 */
    for (int i = 0; i < RLWE_N / 8; i++) {
        uint8_t key_byte = 0;
        uint8_t w_byte = w_signal[i];
        for (int j = 0; j < 8; j++) {
            int32_t val = poly->coeffs[i * 8 + j] % RLWE_Q;
            if (val < 0) val += RLWE_Q;
            int w = (w_byte >> j) & 1;
            int32_t shifted = (val - w * q_quarter) % RLWE_Q;
            if (shifted < 0) shifted += RLWE_Q;
            int k = ((2 * shifted + (RLWE_Q / 2)) / RLWE_Q) & 1;
            if (k) key_byte |= (uint8_t)(1U << j);
        }
        sprintf(hex_str + i * 2, "%02x", key_byte);
    }
    hex_str[(RLWE_N / 8) * 2] = '\0';
}

void hex_to_polynomial(const char* hex_str, Polynomial* poly) {
    for (int i = 0; i < RLWE_N; i++) {
        unsigned int byte;
        sscanf(hex_str + i * 2, "%02x", &byte);
        poly->coeffs[i] = (int16_t)byte;
    }
}

// Check that polynomial coefficients are in [0, q-1] and not identically zero
int polynomial_is_valid_nonzero(const Polynomial* poly) {
    if (!poly) return 0;
    int all_zero = 1;
    for (int i = 0; i < RLWE_N; i++) {
        if (poly->coeffs[i] < 0 || poly->coeffs[i] >= RLWE_Q) return 0;
        if (poly->coeffs[i] != 0) all_zero = 0;
    }
    return !all_zero;
}

// Algorithm 5 Line 13: Prevent exact cancellation, near-cancellation (p_i = -pk_i + delta),
// and zero-divisor attacks in R_q by enforcing:
// 1. Centered infinity norm ||(p_i + pk_i) mod^+- q||_inf > 19 (6*sigma)
// 2. Unit invertibility in R_q^*: for all m in [0, 511], NTT(p_i + pk_i)[m] != 0 mod q
int polynomial_is_valid_unit(const Polynomial* poly) {
    if (!poly) return 0;
    int max_centered = 0;
    for (int i = 0; i < RLWE_N; i++) {
        int32_t c = poly->coeffs[i] % RLWE_Q;
        if (c < 0) c += RLWE_Q;
        int32_t centered = (c > RLWE_Q / 2) ? (RLWE_Q - c) : c;
        if (centered > max_centered) max_centered = (int)centered;
    }
    if (max_centered <= 19) return 0; /* Reject zero or tiny perturbation delta */

    Polynomial ntt_check;
    polynomial_copy(&ntt_check, poly);
    ntt(&ntt_check);
    for (int i = 0; i < RLWE_N; i++) {
        if ((ntt_check.coeffs[i] % RLWE_Q) == 0) {
            polynomial_clear(&ntt_check);
            return 0; /* Reject zero-divisor in R_q */
        }
    }
    polynomial_clear(&ntt_check);
    return 1;
}

// Deterministically derive 256-bit key material from PUF seed r_i via SHA-512
void puf_derive_key_from_response(const uint8_t* puf_response, uint8_t* derived_key) {
    uint8_t digest[SHA512_DIGEST_LENGTH];
    SHA512_simple(puf_response, PUF_RESPONSE_SIZE, digest);
    memcpy(derived_key, digest, PUF_KEY_SIZE);
}

// Algorithm 4 & 5: Deterministically reconstruct ternary secret key sk_i = KDF(r_i, "ARMOR-PQ-SK")
void puf_derive_secret_polynomial(const uint8_t* secret_seed, Polynomial* sk_out) {
    static const char domain_sep[] = "ARMOR-PQ-SK";
    sha512_context ctx;
    uint8_t digest[SHA512_DIGEST_LENGTH];
    int coeff_idx = 0;

    for (uint8_t ctr = 0; coeff_idx < RLWE_N; ctr++) {
        sha512_init(&ctx);
        sha512_update(&ctx, secret_seed, PUF_RESPONSE_SIZE);
        sha512_update(&ctx, (const uint8_t*)domain_sep, sizeof(domain_sep) - 1);
        sha512_update(&ctx, &ctr, 1);
        sha512_final(&ctx, digest);

        for (int i = 0; i < SHA512_DIGEST_LENGTH && coeff_idx < RLWE_N; i++) {
            int16_t centered = (int16_t)((digest[i] % 3) - 1); /* Ternary {-1, 0, 1} */
            sk_out->coeffs[coeff_idx++] = mod_q(centered);
        }
    }
}

int puf_verify_device_identity_wrapper(const PUFSmartDevice* device) {
    if (!device || !device->puf.is_enrolled) return 0;
    return puf_verify_device_identity(&device->puf);
}

// Trusted Authority Functions
void puf_trusted_authority_init(PUFTrustedAuthority* ta) {
    polynomial_init(&ta->sm);
    polynomial_init(&ta->pm);
    polynomial_init(&ta->a);

    ta->registry_size = 0;
    ta->registry_capacity = 10;
    ta->device_registry = malloc(ta->registry_capacity * sizeof(PUFDeviceRegistryEntry));

    ta->keys_size = 0;
    ta->keys_capacity = 10;
    ta->public_keys = malloc(ta->keys_capacity * sizeof(Polynomial));
    ta->key_identifiers = malloc(ta->keys_capacity * sizeof(char*));
}

void puf_trusted_authority_cleanup(PUFTrustedAuthority* ta) {
    polynomial_clear(&ta->sm);
    polynomial_clear(&ta->pm);
    polynomial_clear(&ta->a);

    for (size_t i = 0; i < ta->registry_size; i++) {
        free(ta->device_registry[i].device_id);
        free(ta->device_registry[i].pseudo_id);
        free(ta->device_registry[i].d_i);
        free(ta->device_registry[i].v_i);
    }
    free(ta->device_registry);

    for (size_t i = 0; i < ta->keys_size; i++) {
        free(ta->key_identifiers[i]);
        polynomial_clear(&ta->public_keys[i]);
    }
    free(ta->public_keys);
    free(ta->key_identifiers);
}

void puf_system_initialization(PUFTrustedAuthority* ta) {
    ta->q = RLWE_Q;
    ta->n = RLWE_N;
    ta->beta = RLWE_SIGMA;
    strncpy(ta->hash_name, "SHA512", sizeof(ta->hash_name) - 1);
    ta->hash_name[sizeof(ta->hash_name) - 1] = '\0';

    create_ntt_table();
    polynomial_uniform(&ta->a);

    Polynomial e_m;
    polynomial_init(&ta->sm);
    polynomial_init(&e_m);
    polynomial_gaussian(&ta->sm);
    polynomial_gaussian(&e_m);

    polynomial_multiply_ntt(&ta->a, &ta->sm, &ta->pm);
    for (int i = 0; i < RLWE_N; i++) {
        int32_t val = (int32_t)ta->pm.coeffs[i] + 2 * (int32_t)e_m.coeffs[i];
        ta->pm.coeffs[i] = mod_q(val);
    }

    ta->is_initialized = 1;
    polynomial_clear(&e_m);
}

int puf_register_device(PUFTrustedAuthority* ta, PUFSmartDevice* device,
                        const char* password, char* d_i_out, char* v_i_out) {
    (void)password;
    if (ta->registry_size >= ta->registry_capacity) {
        ta->registry_capacity *= 2;
        ta->device_registry = realloc(ta->device_registry,
                                      ta->registry_capacity * sizeof(PUFDeviceRegistryEntry));
    }

    // Recompute pk_i = a * sk_i + e_{pk,i} under TA's global public polynomial 'a'
    puf_derive_secret_polynomial(device->puf.enrolled_response.response, &device->sk_i);
    Polynomial e_pk;
    polynomial_init(&e_pk);
    polynomial_gaussian(&e_pk);
    polynomial_multiply_ntt(&ta->a, &device->sk_i, &device->pk_i);
    polynomial_add(&device->pk_i, &e_pk, &device->pk_i);
    polynomial_clear(&e_pk);
    polynomial_clear(&device->sk_i); /* Zeroize sk_i after enrollment */

    PUFDeviceRegistryEntry* entry = &ta->device_registry[ta->registry_size];
    entry->device_id = malloc(strlen(device->device_id) + 1);
    strcpy(entry->device_id, device->device_id);
    entry->pseudo_id = malloc(strlen(device->pseudo_id) + 1);
    strcpy(entry->pseudo_id, device->pseudo_id);

    memcpy(&entry->puf_response, &device->puf.enrolled_response, sizeof(PUFResponse));

    // Stream password_hash || puf_derived_key into SHA-512 (no 2,048-byte stack buffer)
    sha512_context ctx;
    uint8_t digest[SHA512_DIGEST_LENGTH];
    char password_hash_out[MAX_HASH_LENGTH];
    sha512_init(&ctx);
    sha512_update(&ctx, (const uint8_t*)device->password_hash, strlen(device->password_hash));
    sha512_update(&ctx, device->puf_derived_key, PUF_KEY_SIZE);
    sha512_final(&ctx, digest);
    digest_to_hex(digest, password_hash_out);

    int copy_len = 64; /* 256-bit (64 hex chars) each for d_i and v_i */
    memcpy(d_i_out, password_hash_out, copy_len);
    memcpy(v_i_out, password_hash_out + copy_len, copy_len);
    d_i_out[copy_len] = '\0';
    v_i_out[copy_len] = '\0';

    entry->d_i = malloc(copy_len + 1);
    entry->v_i = malloc(copy_len + 1);
    strcpy(entry->d_i, d_i_out);
    strcpy(entry->v_i, v_i_out);

    if (ta->keys_size >= ta->keys_capacity) {
        ta->keys_capacity *= 2;
        ta->public_keys = realloc(ta->public_keys, ta->keys_capacity * sizeof(Polynomial));
        ta->key_identifiers = realloc(ta->key_identifiers, ta->keys_capacity * sizeof(char*));
    }

    ta->key_identifiers[ta->keys_size] = malloc(strlen(device->pseudo_id) + 1);
    strcpy(ta->key_identifiers[ta->keys_size], device->pseudo_id);
    polynomial_copy(&ta->public_keys[ta->keys_size], &device->pk_i);
    ta->keys_size++;
    ta->registry_size++;
    return 1;
}

void puf_register_server(PUFTrustedAuthority* ta, const char* server_id, const Polynomial* public_key) {
    if (ta->keys_size >= ta->keys_capacity) {
        ta->keys_capacity *= 2;
        ta->public_keys = realloc(ta->public_keys, ta->keys_capacity * sizeof(Polynomial));
        ta->key_identifiers = realloc(ta->key_identifiers, ta->keys_capacity * sizeof(char*));
    }
    ta->key_identifiers[ta->keys_size] = malloc(strlen(server_id) + 1);
    strcpy(ta->key_identifiers[ta->keys_size], server_id);
    polynomial_copy(&ta->public_keys[ta->keys_size], public_key);
    ta->keys_size++;
}

const Polynomial* puf_get_public_key(const PUFTrustedAuthority* ta, const char* identifier) {
    for (size_t i = 0; i < ta->keys_size; i++) {
        if (strcmp(ta->key_identifiers[i], identifier) == 0) {
            return &ta->public_keys[i];
        }
    }
    return NULL;
}

// Smart Device Functions
void puf_smart_device_init(PUFSmartDevice* device, const char* device_id, const char* password) {
    strncpy(device->device_id, device_id, MAX_ID_LENGTH - 1);
    device->device_id[MAX_ID_LENGTH - 1] = '\0';

    sha512_context ctx;
    uint8_t digest[SHA512_DIGEST_LENGTH];
    sha512_init(&ctx);
    sha512_update(&ctx, (const uint8_t*)password, strlen(password));
    sha512_update(&ctx, (const uint8_t*)device_id, strlen(device_id));
    sha512_final(&ctx, digest);
    digest_to_hex(digest, device->password_hash);

    polynomial_init(&device->sk_i);
    polynomial_init(&device->pk_i);
    polynomial_init(&device->e_i);

    device->d_i[0] = '\0';
    device->v_i[0] = '\0';
    device->pseudo_id[0] = '\0';

    puf_device_init(&device->puf, device_id);
}

void puf_smart_device_cleanup(PUFSmartDevice* device) {
    polynomial_clear(&device->sk_i);
    polynomial_clear(&device->pk_i);
    polynomial_clear(&device->e_i);
}

void puf_smart_device_enroll_puf(PUFSmartDevice* device) {
    if (puf_enroll_device(&device->puf)) {
        puf_derive_key_from_response(device->puf.enrolled_response.response,
                                     device->puf_derived_key);
        puf_derive_secret_polynomial(device->puf.enrolled_response.response, &device->sk_i);
        polynomial_clear(&device->sk_i); /* Zeroize sk_i immediately after enrollment */
    }
}

int puf_smart_device_prepare_registration(PUFSmartDevice* device, char* device_id_out,
                                          char* pseudo_id_out, Polynomial* public_key_out,
                                          char* password_hash_out) {
    if (!device->puf.is_enrolled) return 0;

    strcpy(device_id_out, device->device_id);

    sha512_context ctx;
    uint8_t digest[SHA512_DIGEST_LENGTH];
    char pseudo_hash[MAX_HASH_LENGTH];
    sha512_init(&ctx);
    sha512_update(&ctx, (const uint8_t*)device->device_id, strlen(device->device_id));
    sha512_update(&ctx, device->puf.enrolled_response.response, PUF_RESPONSE_SIZE);
    sha512_final(&ctx, digest);
    digest_to_hex(digest, pseudo_hash);

    strncpy(pseudo_id_out, pseudo_hash, MAX_ID_LENGTH - 1);
    pseudo_id_out[MAX_ID_LENGTH - 1] = '\0';
    strcpy(device->pseudo_id, pseudo_id_out);

    polynomial_copy(public_key_out, &device->pk_i);
    strncpy(password_hash_out, device->password_hash, MAX_HASH_LENGTH);
    return 1;
}

void puf_smart_device_store_parameters(PUFSmartDevice* device, const char* d_i, const char* v_i) {
    strncpy(device->d_i, d_i, MAX_HASH_LENGTH - 1);
    strncpy(device->v_i, v_i, MAX_HASH_LENGTH - 1);
    device->d_i[MAX_HASH_LENGTH - 1] = '\0';
    device->v_i[MAX_HASH_LENGTH - 1] = '\0';
}

// Round 1 (Device -> Server): Reconstruct r_i and sk_i from SRAM PUF, compute p_i = a * e_i + e'_i
int puf_smart_device_initiate_authentication(PUFSmartDevice* device,
                                             const Polynomial* server_public_key,
                                             const Polynomial* trusted_authority_public_key,
                                             PUFAuthMessage* auth_msg, int* c_i) {
    (void)server_public_key;
    (void)c_i;

    if (!device->puf.is_enrolled) return 0;

    // 1. Sample 256-bit challenge nonce C_s
    for (int i = 0; i < PUF_CHALLENGE_SIZE; i++) {
        auth_msg->puf_challenge[i] = (uint8_t)(rand() & 0xFF);
    }

    // 2. Evaluate noisy SRAM PUF R'_i (reusing p_i's 1,024 B buffer as scratchpad before RLWE step)
    // and reconstruct 256-bit seed r_i via [15,1,15] majority decoder
    PUFResponse* scratch_resp = (PUFResponse*)&auth_msg->p_i;
    if (!puf_generate_response(&device->puf, NULL, scratch_resp, 1)) {
        return 0;
    }

    uint8_t clean_seed[PUF_RESPONSE_SIZE];
    if (!puf_error_correction(scratch_resp->raw_sram,
                              device->puf.enrolled_response.helper_data,
                              clean_seed)) {
        return 0;
    }

    // 3. Derive verification token and v_i in SRAM
    puf_derive_key_from_response(clean_seed, auth_msg->puf_verification_token);

    sha512_context ctx;
    uint8_t digest[SHA512_DIGEST_LENGTH];
    char hash_output[MAX_HASH_LENGTH];
    sha512_init(&ctx);
    sha512_update(&ctx, (const uint8_t*)device->password_hash, strlen(device->password_hash));
    sha512_update(&ctx, auth_msg->puf_verification_token, PUF_KEY_SIZE);
    sha512_final(&ctx, digest);
    digest_to_hex(digest, hash_output);
    memcpy(device->v_i, hash_output + 64, 64);
    device->v_i[64] = '\0';

    // 4. Compute session token tau = H(v_i || C_s || T_s)
    auth_msg->timestamp = (long long)time(NULL);
    sha512_init(&ctx);
    sha512_update(&ctx, (const uint8_t*)device->v_i, strlen(device->v_i));
    sha512_update(&ctx, auth_msg->puf_challenge, PUF_CHALLENGE_SIZE);
    sha512_update(&ctx, (const uint8_t*)&auth_msg->timestamp, sizeof(auth_msg->timestamp));
    sha512_final(&ctx, digest);
    memcpy(auth_msg->puf_token, digest, PUF_KEY_SIZE);

    // 5. Sample ephemeral e_i <- chi_sigma, compute p_i = a * e_i + e'_i mod q in-place
    // using device->sk_i as the 1,024 B NTT scratchpad (zero stack Polynomial allocation!),
    // then reconstruct sk_i = KDF(r_i, "ARMOR-PQ-SK") into device->sk_i.
    polynomial_gaussian(&device->e_i);
    polynomial_copy(&auth_msg->p_i, trusted_authority_public_key);
    polynomial_copy(&device->sk_i, &device->e_i);
    polynomial_multiply_ntt_inplace(&auth_msg->p_i, &device->sk_i);
    for (int i = 0; i < RLWE_N; i++) {
        int32_t e_prime = 0;
        for (int j = 0; j < 15; j++) e_prime += (rand() % 3) - 1;
        auth_msg->p_i.coeffs[i] = mod_q((int32_t)auth_msg->p_i.coeffs[i] + e_prime);
    }

    puf_derive_secret_polynomial(clean_seed, &device->sk_i);
    memset(clean_seed, 0, sizeof(clean_seed));
    return 1;
}

// Round 3 (Device verifies Server's Round 2 message and produces alpha_i)
int puf_smart_device_verify_server_response(PUFSmartDevice* device, const char* server_id,
                                            const Polynomial* server_public_key,
                                            const int* c_j, const char* alpha_j,
                                            long long int timestamp,
                                            const Polynomial* trusted_authority_public_key,
                                            PUFAuthMessage* auth_msg, const int* c_i) {
    (void)trusted_authority_public_key;
    (void)c_j;
    (void)c_i;
    (void)server_public_key;

    if (llabs((long long)time(NULL) - timestamp) > 300) return 0;
    if (!polynomial_is_valid_nonzero(&auth_msg->sigma_j)) return 0;

    // Step 16: In-place combined secret device->sk_i = (e_i + sk_i) mod q,
    // and in-place shared secret sh_D = p_j * (e_i + sk_i) mod q using zero extra stack polynomials!
    polynomial_add(&device->e_i, &device->sk_i, &device->sk_i);
    polynomial_copy(&device->e_i, &auth_msg->sigma_j);
    polynomial_multiply_ntt_inplace(&device->e_i, &device->sk_i); /* device->e_i now holds sh_D */

    char sh_hex[(RLWE_N / 8) * 2 + 1];
    peikert_reconcile(&device->e_i, auth_msg->w_signal, sh_hex);

    // Immediately zeroize volatile secret keys sk_i and e_i (sh_D) from SRAM!
    polynomial_clear(&device->sk_i);
    polynomial_clear(&device->e_i);

    // Verify alpha_j via streaming SHA-512 (zero 8,192-byte stack buffers!)
    sha512_context ctx;
    uint8_t digest[SHA512_DIGEST_LENGTH];
    char computed_alpha_j[MAX_HASH_LENGTH];

    sha512_init(&ctx);
    sha512_update(&ctx, (const uint8_t*)server_id, strlen(server_id));
    sha512_update(&ctx, (const uint8_t*)device->pseudo_id, strlen(device->pseudo_id));
    sha512_update_polynomial(&ctx, &auth_msg->p_i);
    sha512_update_polynomial(&ctx, &auth_msg->sigma_j);
    sha512_update(&ctx, auth_msg->w_signal, RLWE_N / 8);
    sha512_update(&ctx, (const uint8_t*)sh_hex, strlen(sh_hex));
    sha512_update(&ctx, auth_msg->puf_token, PUF_KEY_SIZE);
    sha512_update(&ctx, (const uint8_t*)&auth_msg->timestamp, sizeof(auth_msg->timestamp));
    sha512_update(&ctx, auth_msg->puf_challenge, PUF_CHALLENGE_SIZE);
    sha512_update(&ctx, (const uint8_t*)device->d_i, strlen(device->d_i));
    sha512_final(&ctx, digest);
    digest_to_hex(digest, computed_alpha_j);

    int match = (strcmp(computed_alpha_j, alpha_j) == 0);
    if (match) {
        // Compute Round 3 client authenticator alpha_i via streaming SHA-512
        sha512_init(&ctx);
        sha512_update(&ctx, (const uint8_t*)device->pseudo_id, strlen(device->pseudo_id));
        sha512_update(&ctx, (const uint8_t*)server_id, strlen(server_id));
        sha512_update_polynomial(&ctx, &auth_msg->p_i);
        sha512_update_polynomial(&ctx, &auth_msg->sigma_j);
        sha512_update(&ctx, auth_msg->w_signal, RLWE_N / 8);
        sha512_update(&ctx, (const uint8_t*)sh_hex, strlen(sh_hex));
        sha512_update(&ctx, (const uint8_t*)&auth_msg->timestamp, sizeof(auth_msg->timestamp));
        sha512_update(&ctx, auth_msg->puf_challenge, PUF_CHALLENGE_SIZE);
        sha512_update(&ctx, (const uint8_t*)device->v_i, strlen(device->v_i));
        sha512_final(&ctx, digest);
        digest_to_hex(digest, auth_msg->alpha_i);
    }

    return match;
}

// Edge Server Functions
void puf_edge_server_init(PUFEdgeServer* server, const char* server_id) {
    strncpy(server->server_id, server_id, MAX_ID_LENGTH - 1);
    server->server_id[MAX_ID_LENGTH - 1] = '\0';

    polynomial_init(&server->sk_j);
    polynomial_init(&server->pk_j);

    Polynomial a_tmp, e_sk_j;
    polynomial_init(&a_tmp);
    polynomial_init(&e_sk_j);
    polynomial_gaussian(&server->sk_j);
    polynomial_uniform(&a_tmp);
    polynomial_multiply_ntt(&a_tmp, &server->sk_j, &server->pk_j);
    polynomial_gaussian(&e_sk_j);
    polynomial_add(&server->pk_j, &e_sk_j, &server->pk_j);
    polynomial_clear(&a_tmp);
    polynomial_clear(&e_sk_j);
}

void puf_edge_server_cleanup(PUFEdgeServer* server) {
    polynomial_clear(&server->sk_j);
    polynomial_clear(&server->pk_j);
}

void puf_edge_server_prepare_registration(PUFEdgeServer* server, char* server_id_out,
                                          Polynomial* public_key_out) {
    strcpy(server_id_out, server->server_id);
    polynomial_copy(public_key_out, &server->pk_j);
}

// Round 2 (Server verifies M_1 and generates M_2 = {p_j, w, alpha_j})
int puf_edge_server_verify_device_authentication(PUFEdgeServer* server, const char* pseudo_id,
                                                 const Polynomial* device_public_key,
                                                 const int* c_i, const char* alpha_i,
                                                 long long int timestamp,
                                                 const Polynomial* trusted_authority_public_key,
                                                 PUFTrustedAuthority* ta, PUFAuthMessage* auth_msg, int* c_j) {
    (void)device_public_key;
    (void)c_i;
    (void)alpha_i;
    (void)c_j;

    if (llabs((long long)time(NULL) - timestamp) > 300) return 0;
    if (!polynomial_is_valid_nonzero(&auth_msg->p_i)) return 0;

    PUFDeviceRegistryEntry* entry = NULL;
    const Polynomial* pk_i = puf_get_public_key(ta, pseudo_id);
    for (size_t i = 0; i < ta->registry_size; i++) {
        if (strcmp(ta->device_registry[i].pseudo_id, pseudo_id) == 0) {
            entry = &ta->device_registry[i];
            break;
        }
    }
    if (!entry || !pk_i) return 0;

    // Algorithm 5 Line 13: Combine (p_i + pk_i) and verify centered norm > 6*sigma & NTT unit invertibility
    Polynomial p_combined, ej;
    polynomial_init(&p_combined);
    polynomial_init(&ej);
    polynomial_add(&auth_msg->p_i, pk_i, &p_combined);
    if (!polynomial_is_valid_unit(&p_combined)) {
        polynomial_clear(&p_combined);
        return 0;
    }

    // Sample e_j <- chi_sigma, compute p_j = a * e_j + e''_j mod q and sh_S = (p_i + pk_i) * e_j mod q in-place
    polynomial_gaussian(&ej);
    polynomial_multiply_ntt(trusted_authority_public_key, &ej, &auth_msg->sigma_j);
    for (int i = 0; i < RLWE_N; i++) {
        int32_t e_pprime = 0;
        for (int j = 0; j < 15; j++) e_pprime += (rand() % 3) - 1;
        auth_msg->sigma_j.coeffs[i] = mod_q((int32_t)auth_msg->sigma_j.coeffs[i] + e_pprime);
    }

    // Compute sh_S = (p_i + pk_i) * e_j mod q in-place inside p_combined
    polynomial_multiply_ntt_inplace(&p_combined, &ej);

    char sh_hex[(RLWE_N / 8) * 2 + 1];
    peikert_signal(&p_combined, auth_msg->w_signal);
    peikert_reconcile(&p_combined, auth_msg->w_signal, sh_hex);
    strcpy(auth_msg->K_hex, sh_hex);

    // Compute alpha_j via streaming SHA-512 (zero 8,192-byte stack buffers!)
    sha512_context ctx;
    uint8_t digest[SHA512_DIGEST_LENGTH];
    sha512_init(&ctx);
    sha512_update(&ctx, (const uint8_t*)server->server_id, strlen(server->server_id));
    sha512_update(&ctx, (const uint8_t*)pseudo_id, strlen(pseudo_id));
    sha512_update_polynomial(&ctx, &auth_msg->p_i);
    sha512_update_polynomial(&ctx, &auth_msg->sigma_j);
    sha512_update(&ctx, auth_msg->w_signal, RLWE_N / 8);
    sha512_update(&ctx, (const uint8_t*)sh_hex, strlen(sh_hex));
    sha512_update(&ctx, auth_msg->puf_token, PUF_KEY_SIZE);
    sha512_update(&ctx, (const uint8_t*)&auth_msg->timestamp, sizeof(auth_msg->timestamp));
    sha512_update(&ctx, auth_msg->puf_challenge, PUF_CHALLENGE_SIZE);
    sha512_update(&ctx, (const uint8_t*)entry->d_i, strlen(entry->d_i));
    sha512_final(&ctx, digest);
    digest_to_hex(digest, auth_msg->alpha_j);

    polynomial_clear(&p_combined);
    polynomial_clear(&ej);
    return 1;
}

int puf_edge_server_verify_client_auth(PUFEdgeServer* server, const char* pseudo_id,
                                       PUFTrustedAuthority* ta, PUFAuthMessage* auth_msg) {
    PUFDeviceRegistryEntry* entry = NULL;
    for (size_t i = 0; i < ta->registry_size; i++) {
        if (strcmp(ta->device_registry[i].pseudo_id, pseudo_id) == 0) {
            entry = &ta->device_registry[i];
            break;
        }
    }
    if (!entry) return 0;

    sha512_context ctx;
    uint8_t digest[SHA512_DIGEST_LENGTH];
    char computed_alpha_i[MAX_HASH_LENGTH];

    sha512_init(&ctx);
    sha512_update(&ctx, (const uint8_t*)pseudo_id, strlen(pseudo_id));
    sha512_update(&ctx, (const uint8_t*)server->server_id, strlen(server->server_id));
    sha512_update_polynomial(&ctx, &auth_msg->p_i);
    sha512_update_polynomial(&ctx, &auth_msg->sigma_j);
    sha512_update(&ctx, auth_msg->w_signal, RLWE_N / 8);
    sha512_update(&ctx, (const uint8_t*)auth_msg->K_hex, strlen(auth_msg->K_hex));
    sha512_update(&ctx, (const uint8_t*)&auth_msg->timestamp, sizeof(auth_msg->timestamp));
    sha512_update(&ctx, auth_msg->puf_challenge, PUF_CHALLENGE_SIZE);
    sha512_update(&ctx, (const uint8_t*)entry->v_i, strlen(entry->v_i));
    sha512_final(&ctx, digest);
    digest_to_hex(digest, computed_alpha_i);

    return (strcmp(computed_alpha_i, auth_msg->alpha_i) == 0);
}

void puf_compute_session_key(const char* pseudo_id, const char* server_id,
                             const Polynomial* p_i, const int* w_i, const int* sigma_i,
                             const char* alpha_i, const Polynomial* p_j, const int* w_j,
                             const int* sigma_j, const char* alpha_j,
                             const char* K_hex, const char* v_i, char* session_key) {
    (void)w_i; (void)sigma_i; (void)w_j; (void)sigma_j;

    sha512_context ctx;
    uint8_t digest[SHA512_DIGEST_LENGTH];
    sha512_init(&ctx);
    sha512_update(&ctx, (const uint8_t*)pseudo_id, strlen(pseudo_id));
    sha512_update(&ctx, (const uint8_t*)server_id, strlen(server_id));
    sha512_update_polynomial(&ctx, p_i);
    sha512_update_polynomial(&ctx, p_j);
    sha512_update(&ctx, (const uint8_t*)alpha_i, strlen(alpha_i));
    sha512_update(&ctx, (const uint8_t*)alpha_j, strlen(alpha_j));
    sha512_update(&ctx, (const uint8_t*)K_hex, strlen(K_hex));
    sha512_update(&ctx, (const uint8_t*)v_i, strlen(v_i));
    sha512_final(&ctx, digest);
    digest_to_hex(digest, session_key);
}

int puf_smart_device_rotate_pseudo_id(PUFSmartDevice* device, PUFTrustedAuthority* ta, char* new_pseudo_id_out) {
    if (!device || !ta) return 0;

    long long ts = (long long)time(NULL);
    sha512_context ctx;
    uint8_t digest[SHA512_DIGEST_LENGTH];
    char pseudo_hash[MAX_HASH_LENGTH];

    sha512_init(&ctx);
    sha512_update(&ctx, (const uint8_t*)device->device_id, strlen(device->device_id));
    sha512_update(&ctx, (const uint8_t*)&ts, sizeof(ts));
    if (device->puf.is_enrolled) {
        sha512_update(&ctx, device->puf.enrolled_response.response, PUF_RESPONSE_SIZE);
    }
    sha512_final(&ctx, digest);
    digest_to_hex(digest, pseudo_hash);

    strncpy(new_pseudo_id_out, pseudo_hash, MAX_ID_LENGTH - 1);
    new_pseudo_id_out[MAX_ID_LENGTH - 1] = '\0';

    char old_pseudo[MAX_ID_LENGTH];
    memcpy(old_pseudo, device->pseudo_id, MAX_ID_LENGTH);
    memcpy(device->pseudo_id, new_pseudo_id_out, MAX_ID_LENGTH);

    for (size_t i = 0; i < ta->registry_size; i++) {
        if (ta->device_registry[i].pseudo_id && strcmp(ta->device_registry[i].pseudo_id, old_pseudo) == 0) {
            free(ta->device_registry[i].pseudo_id);
            ta->device_registry[i].pseudo_id = malloc(strlen(new_pseudo_id_out) + 1);
            strcpy(ta->device_registry[i].pseudo_id, new_pseudo_id_out);
            break;
        }
    }

    for (size_t i = 0; i < ta->keys_size; i++) {
        if (ta->key_identifiers[i] && strcmp(ta->key_identifiers[i], old_pseudo) == 0) {
            free(ta->key_identifiers[i]);
            ta->key_identifiers[i] = malloc(strlen(new_pseudo_id_out) + 1);
            strcpy(ta->key_identifiers[i], new_pseudo_id_out);
            break;
        }
    }
    return 1;
}

int puf_smart_device_change_password(PUFSmartDevice* device, PUFTrustedAuthority* ta, const char* old_pwd, const char* new_pwd) {
    if (!device || !ta || !old_pwd || !new_pwd) return 0;

    sha512_context ctx;
    uint8_t digest[SHA512_DIGEST_LENGTH];
    char old_pw_salted_hash[MAX_HASH_LENGTH];

    sha512_init(&ctx);
    sha512_update(&ctx, (const uint8_t*)old_pwd, strlen(old_pwd));
    sha512_update(&ctx, (const uint8_t*)device->device_id, strlen(device->device_id));
    sha512_final(&ctx, digest);
    digest_to_hex(digest, old_pw_salted_hash);

    if (strcmp(device->password_hash, old_pw_salted_hash) != 0) return 0;

    sha512_init(&ctx);
    sha512_update(&ctx, (const uint8_t*)new_pwd, strlen(new_pwd));
    sha512_update(&ctx, (const uint8_t*)device->device_id, strlen(device->device_id));
    sha512_final(&ctx, digest);
    digest_to_hex(digest, device->password_hash);

    char password_hash_out[MAX_HASH_LENGTH];
    sha512_init(&ctx);
    sha512_update(&ctx, (const uint8_t*)device->password_hash, strlen(device->password_hash));
    sha512_update(&ctx, device->puf_derived_key, PUF_KEY_SIZE);
    sha512_final(&ctx, digest);
    digest_to_hex(digest, password_hash_out);

    char d_i_new[65], v_i_new[65];
    memcpy(d_i_new, password_hash_out, 64);
    memcpy(v_i_new, password_hash_out + 64, 64);
    d_i_new[64] = '\0';
    v_i_new[64] = '\0';

    puf_smart_device_store_parameters(device, d_i_new, v_i_new);

    for (size_t i = 0; i < ta->registry_size; i++) {
        if (ta->device_registry[i].pseudo_id && strcmp(ta->device_registry[i].pseudo_id, device->pseudo_id) == 0) {
            free(ta->device_registry[i].d_i);
            free(ta->device_registry[i].v_i);
            ta->device_registry[i].d_i = malloc(65);
            ta->device_registry[i].v_i = malloc(65);
            strcpy(ta->device_registry[i].d_i, d_i_new);
            strcpy(ta->device_registry[i].v_i, v_i_new);
            return 1;
        }
    }
    return 0;
}

int puf_perform_mutual_auth(PUFSmartDevice* device, PUFEdgeServer* server, PUFTrustedAuthority* ta) {
    if (!device || !server || !ta) return 0;

    PUFAuthMessage auth_msg;
    memset(&auth_msg, 0, sizeof(auth_msg));

    if (!puf_smart_device_initiate_authentication(device, &server->pk_j, &ta->a, &auth_msg, NULL)) {
        return 0;
    }
    if (!puf_edge_server_verify_device_authentication(server, device->pseudo_id, &device->pk_i, NULL,
                                                      auth_msg.alpha_i, auth_msg.timestamp, &ta->a, ta, &auth_msg, NULL)) {
        return 0;
    }
    if (!puf_smart_device_verify_server_response(device, server->server_id, &server->pk_j, NULL,
                                                 auth_msg.alpha_j, auth_msg.timestamp, &ta->a, &auth_msg, NULL)) {
        return 0;
    }
    if (!puf_edge_server_verify_client_auth(server, device->pseudo_id, ta, &auth_msg)) {
        return 0;
    }
    return 1;
}
