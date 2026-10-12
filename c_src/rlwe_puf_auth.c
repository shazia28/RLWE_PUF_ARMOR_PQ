#include "rlwe_puf_auth.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include "sha_portable.h"
#include "ntt.h"

// Enhanced utility functions with PUF integration
void sha3_512(const char* input, char* output) {
    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512_simple((const unsigned char*)input, strlen(input), hash);
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        sprintf(output + i * 2, "%02x", hash[i]);
    }
}

void sha512(const char* input, size_t length, char* output) {
    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512_simple((const unsigned char*)input, length, hash);
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        sprintf(output + i * 2, "%02x", hash[i]);
    }
}

void polynomial_to_hex(const Polynomial* poly, char* hex_str) {
    for (int i = 0; i < RLWE_N; i++) {
        sprintf(hex_str + i * 2, "%02x", (unsigned char)(poly->coeffs[i] & 0xFF));
    }
    hex_str[RLWE_N * 2] = '\0';
}

void peikert_signal(const Polynomial* poly, uint8_t* w_signal) {
    for (int i = 0; i < RLWE_N / 8; i++) {
        uint8_t byte = 0;
        for (int j = 0; j < 8; j++) {
            int32_t val = poly->coeffs[i*8 + j] % RLWE_Q;
            if (val < 0) val += RLWE_Q;
            int region = (val * 8) / RLWE_Q;
            int w = 0;
            if (region == 1 || region == 2 || region == 5 || region == 6) {
                w = 1;
            }
            if (w) byte |= (1 << j);
        }
        w_signal[i] = byte;
    }
}

void peikert_reconcile(const Polynomial* poly, const uint8_t* w_signal, char* hex_str) {
    for (int i = 0; i < RLWE_N / 8; i++) {
        uint8_t key_byte = 0;
        uint8_t w_byte = w_signal[i];
        for (int j = 0; j < 8; j++) {
            int32_t val = poly->coeffs[i*8 + j] % RLWE_Q;
            if (val < 0) val += RLWE_Q;
            int w = (w_byte >> j) & 1;
            int k = 0;
            if (w == 0) {
                if (val >= RLWE_Q/4 && val <= (3*RLWE_Q)/4) k = 1;
            } else {
                if (val >= 0 && val <= RLWE_Q/2) k = 0;
                else k = 1;
            }
            if (k) key_byte |= (1 << j);
        }
        sprintf(hex_str + i * 2, "%02x", key_byte);
    }
    hex_str[(RLWE_N / 8) * 2] = '\0';
}

void hex_to_polynomial(const char* hex_str, Polynomial* poly) {
    for (int i = 0; i < RLWE_N; i++) {
        unsigned int byte;
        sscanf(hex_str + i * 2, "%02x", &byte);
        poly->coeffs[i] = byte;
    }
}

// Check that polynomial coefficients are within [0, q-1] and not identically zero
int polynomial_is_valid_nonzero(const Polynomial* poly) {
    if (!poly) return 0;
    int all_zero = 1;
    for (int i = 0; i < RLWE_N; i++) {
        if (poly->coeffs[i] < 0 || poly->coeffs[i] >= RLWE_Q) return 0;
        if (poly->coeffs[i] != 0) all_zero = 0;
    }
    return !all_zero;
}

// Derive cryptographic key from PUF response
void puf_derive_key_from_response(const uint8_t* puf_response, uint8_t* derived_key) {
    // Safe key derivation mask
    for (int i = 0; i < PUF_KEY_SIZE; i++) {
        derived_key[i] = puf_response[i] ^ (uint8_t)(0x5A ^ (i * 3));
    }
}

// Verify device identity using PUF - WRAPPER FUNCTION
int puf_verify_device_identity_wrapper(const PUFSmartDevice* device) {
    if (!device || !device->puf.is_enrolled) {
        printf("PUF not enrolled or device invalid\n");
        return 0;
    }
    
    printf("Verifying PUF identity for device %s...\n", device->device_id);
    int result = puf_verify_device_identity(&device->puf);
    return result;
}

// Enhanced Trusted Authority Functions
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
    // 1) Set system parameters (from rlwe_core.h constants)
    ta->q = RLWE_Q;
    ta->n = RLWE_N;
    ta->beta = RLWE_SIGMA; // discrete Gaussian parameter (beta)
    strncpy(ta->hash_name, "SHA512", sizeof(ta->hash_name)-1);
    ta->hash_name[sizeof(ta->hash_name)-1] = '\0';

    // 2) Sample public ring element a uniformly from R_q
    create_ntt_table(); // Initialize NTT twiddle factors
    polynomial_uniform(&ta->a);

    // 3) Sample master secret s_m and error e_m from discrete Gaussian chi_beta
    Polynomial s_m;
    Polynomial e_m;
    polynomial_init(&s_m);
    polynomial_init(&e_m);
    polynomial_gaussian(&s_m); // s_m <- chi_beta
    polynomial_gaussian(&e_m); // e_m <- chi_beta

    // 4) Compute p_m = a * s_m + 2 * e_m  (arithmetic mod q)
    Polynomial as;
    polynomial_init(&as);
    polynomial_multiply_ntt(&ta->a, &s_m, &as); // as = a * s_m

    // Add 2*e_m to as (mod q)
    for (int i = 0; i < RLWE_N; i++) {
        long long val = (long long)as.coeffs[i] + 2LL * (long long)e_m.coeffs[i];
        // reduce to canonical representative modulo RLWE_Q
        val %= RLWE_Q;
        if (val < 0) val += RLWE_Q;
        ta->pm.coeffs[i] = (int32_t)val;
    }

    // Store master secret in TA (kept in secure local/trusted zone)
    polynomial_copy(&ta->sm, &s_m);

    // Mark initialized and publish params (q,n,beta,a,pm,h)
    ta->is_initialized = 1;

    // Cleanup temporaries
    polynomial_clear(&s_m);
    polynomial_clear(&e_m);
    polynomial_clear(&as);

    printf("System Initialization completed: published public parameters {q=%d, n=%d, beta=%.4f, hash=%s}.\n",
           ta->q, ta->n, ta->beta, ta->hash_name);
}

int puf_register_device(PUFTrustedAuthority* ta, PUFSmartDevice* device, 
                       const char* password, char* d_i_out, char* v_i_out) {
    if (ta->registry_size >= ta->registry_capacity) {
        ta->registry_capacity *= 2;
        ta->device_registry = realloc(ta->device_registry, 
                                    ta->registry_capacity * sizeof(PUFDeviceRegistryEntry));
    }

    // Store device information with PUF data
    PUFDeviceRegistryEntry* entry = &ta->device_registry[ta->registry_size];
    entry->device_id = malloc(strlen(device->device_id) + 1);
    strcpy(entry->device_id, device->device_id);
    entry->pseudo_id = malloc(strlen(device->pseudo_id) + 1);
    strcpy(entry->pseudo_id, device->pseudo_id);
    
    // Store PUF enrollment data
    memcpy(&entry->puf_response, &device->puf.enrolled_response, sizeof(PUFResponse));
    
    // Generate device-specific parameters using PUF-enhanced method
    char id_input[2048];
    int id_len = strlen(device->device_id);
    memcpy(id_input, device->device_id, id_len);
    memcpy(id_input + id_len, device->puf_derived_key, PUF_KEY_SIZE);
    sha512(id_input, id_len + PUF_KEY_SIZE, v_i_out); // Use provided output param for demo
    
    char pwd_input[2048];
    int pwd_len = strlen(device->password_hash);
    memcpy(pwd_input, device->password_hash, pwd_len);
    memcpy(pwd_input + pwd_len, device->puf_derived_key, PUF_KEY_SIZE);
    char password_hash_out[MAX_HASH_LENGTH];
    sha512(pwd_input, pwd_len + PUF_KEY_SIZE, password_hash_out);
    
    // Generate d_i and v_i
    int copy_len = RLWE_N / 2;
    if (copy_len > MAX_HASH_LENGTH/2) copy_len = MAX_HASH_LENGTH/2;
    
    strncpy(d_i_out, password_hash_out, copy_len);
    strncpy(v_i_out, password_hash_out + copy_len, copy_len);
    d_i_out[copy_len] = '\0';
    v_i_out[copy_len] = '\0';
    
    entry->d_i = malloc(copy_len + 1);
    entry->v_i = malloc(copy_len + 1);
    strcpy(entry->d_i, d_i_out);
    strcpy(entry->v_i, v_i_out);

    // Store public key
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
    
    printf("PUF-Enhanced Device %s registered with pseudo-ID %s\n", 
           device->device_id, device->pseudo_id);
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
    
    printf("PUF-Enhanced Server %s registered\n", server_id);
}

const Polynomial* puf_get_public_key(const PUFTrustedAuthority* ta, const char* identifier) {
    for (size_t i = 0; i < ta->keys_size; i++) {
        if (strcmp(ta->key_identifiers[i], identifier) == 0) {
            return &ta->public_keys[i];
        }
    }
    return NULL;
}

// Enhanced Smart Device Functions with PUF
void puf_smart_device_init(PUFSmartDevice* device, const char* device_id, const char* password) {
    strncpy(device->device_id, device_id, MAX_ID_LENGTH - 1);
    device->device_id[MAX_ID_LENGTH - 1] = '\0';
    
    char pw_salt_input[512];
    sprintf(pw_salt_input, "%s%s", password, device_id);
    sha3_512(pw_salt_input, device->password_hash);
    
    polynomial_init(&device->sk_i);
    polynomial_init(&device->pk_i);
    polynomial_init(&device->temp_poly);
    
    device->d_i[0] = '\0';
    device->v_i[0] = '\0';
    device->pseudo_id[0] = '\0';
    
    // Initialize PUF
    puf_device_init(&device->puf, device_id);
    
    // Algorithm 1, Step 3: sk_i sampled from Gaussian; pk_i = a * sk_i
    // Note: We'll use a local 'a' for now, but in system flow, this is ta->a
    Polynomial a_param;
    polynomial_init(&a_param);
    polynomial_uniform(&a_param); // Standard system parameter a
    
    polynomial_gaussian(&device->sk_i); // sk_i <- chi_beta
    polynomial_multiply_ntt(&a_param, &device->sk_i, &device->pk_i); // a * sk_i
    
    Polynomial e_sk;
    polynomial_init(&e_sk);
    polynomial_gaussian(&e_sk);
    polynomial_add(&device->pk_i, &device->pk_i, &e_sk); // pk_i = a * sk_i + e_sk
    polynomial_clear(&e_sk);
    
    polynomial_clear(&a_param);
    printf("PUF-Enhanced Smart Device %s initialized (PK derived via a*sk)\n", device_id);
}

void puf_smart_device_cleanup(PUFSmartDevice* device) {
    polynomial_clear(&device->sk_i);
    polynomial_clear(&device->pk_i);
    polynomial_clear(&device->temp_poly);
}

void puf_smart_device_enroll_puf(PUFSmartDevice* device) {
    if (puf_enroll_device(&device->puf)) {
        // Derive cryptographic key from PUF response
        puf_derive_key_from_response(device->puf.enrolled_response.response, 
                                   device->puf_derived_key);
        printf("PUF enrolled and key derived for device %s\n", device->device_id);
    } else {
        printf("PUF enrollment failed for device %s\n", device->device_id);
    }
}

int puf_smart_device_prepare_registration(PUFSmartDevice* device, char* device_id_out,
                                         char* pseudo_id_out, Polynomial* public_key_out,
                                         char* password_hash_out) {
    // Verify PUF is enrolled first
    if (!device->puf.is_enrolled) {
        printf("PUF not enrolled for device %s\n", device->device_id);
        return 0;
    }
    
    strcpy(device_id_out, device->device_id);
    
    // Generate pseudo ID with PUF enhancement
    char pseudo_input[MAX_ID_LENGTH + PUF_RESPONSE_SIZE];
    sprintf(pseudo_input, "%s", device->device_id);
    
    // Include PUF response in pseudo ID generation
    memcpy(pseudo_input + strlen(pseudo_input), 
           device->puf.enrolled_response.response, 
           PUF_RESPONSE_SIZE);
    
    char pseudo_hash[MAX_HASH_LENGTH];
    sha3_512(pseudo_input, pseudo_hash);
    strncpy(pseudo_id_out, pseudo_hash, MAX_ID_LENGTH - 1);
    pseudo_id_out[MAX_ID_LENGTH - 1] = '\0';
    strcpy(device->pseudo_id, pseudo_id_out);
    
    polynomial_copy(public_key_out, &device->pk_i);
    
    // Return stored password hash
    strncpy(password_hash_out, device->password_hash, MAX_HASH_LENGTH);
    
    return 1;
}

void puf_smart_device_store_parameters(PUFSmartDevice* device, const char* d_i, const char* v_i) {
    int copy_len = RLWE_N - 1;
    strncpy(device->d_i, d_i, copy_len);
    strncpy(device->v_i, v_i, copy_len);
    device->d_i[copy_len] = '\0';
    device->v_i[copy_len] = '\0';
}

int puf_smart_device_initiate_authentication(PUFSmartDevice* device,
                                           const Polynomial* server_public_key,
                                           const Polynomial* trusted_authority_public_key,
                                           PUFAuthMessage* auth_msg, int* c_i) {
    (void)server_public_key; (void)c_i;
    
    printf("Starting PULSE-PQ (Final Scheme) authentication for device %s...\n", device->device_id);
    
    if (!device->puf.is_enrolled) {
        printf("PUF not enrolled for device %s\n", device->device_id);
        return 0;
    }
    
    // 1. Cs <- {0,1}^256 (Simplified to PUF_CHALLENGE_SIZE)
    for (int i = 0; i < PUF_CHALLENGE_SIZE; i++) {
        auth_msg->puf_challenge[i] = rand() % 256;
    }
    
    // 2 & 3. r'_i <- PUF.Eval(); r_i <- FE.Rep(r'_i, h_i)
    PUFResponse session_response;
    if (!puf_generate_response(&device->puf, NULL, &session_response, 1)) {
        return 0;
    }
    
    // Perform error correction to recover the clean SRAM fingerprint
    uint8_t clean_puf_response[PUF_RESPONSE_SIZE];
    if (!puf_error_correction(session_response.response, device->puf.enrolled_response.helper_data, clean_puf_response)) {
        printf("PUF error correction failed (noise > threshold)\n");
        return 0;
    }
    
    puf_derive_key_from_response(clean_puf_response, auth_msg->puf_verification_token);
    
    // 4. tau <- H(r'_i || C_s)
    char tau_input[PUF_RESPONSE_SIZE + PUF_CHALLENGE_SIZE + 1];
    memcpy(tau_input, session_response.response, PUF_RESPONSE_SIZE); // tau uses the noisy response r'_i
    memcpy(tau_input + PUF_RESPONSE_SIZE, auth_msg->puf_challenge, PUF_CHALLENGE_SIZE);
    tau_input[PUF_RESPONSE_SIZE + PUF_CHALLENGE_SIZE] = '\0';
    
    char tau_hash[MAX_HASH_LENGTH];
    sha3_512(tau_input, tau_hash);
    memcpy(auth_msg->puf_token, tau_hash, PUF_KEY_SIZE);

    // 5 & 6. Sample ei, epi; pi = a * ei + epi
    Polynomial ei, epi, temp;
    polynomial_init(&ei); polynomial_init(&epi); polynomial_init(&temp);
    polynomial_gaussian(&ei);
    polynomial_gaussian(&epi);
    
    // We use the TA public parameter 'a' (trusted_authority_public_key)
    polynomial_multiply_ntt(trusted_authority_public_key, &ei, &temp);
    polynomial_add(&temp, &epi, &auth_msg->p_i);
    
    // Store ei in device locally for shared secret computation
    polynomial_copy(&device->sk_i, &ei);
    
    // 7. alpha_i = SHA512(PID_i || pi || Ts || ki)
    auth_msg->timestamp = (long long)time(NULL);
    char pi_hex[RLWE_N * 2 + 1];
    polynomial_to_hex(&auth_msg->p_i, pi_hex);
    
    // Dynamically reconstruct v_i using CLEAN PUF response r_i
    char hash_input[2048];
    int pw_len = strlen(device->password_hash);
    memcpy(hash_input, device->password_hash, pw_len);
    memcpy(hash_input + pw_len, device->puf_derived_key, PUF_KEY_SIZE);
    char hash_output[MAX_HASH_LENGTH];
    sha512(hash_input, pw_len + PUF_KEY_SIZE, hash_output);
    
    int copy_len = RLWE_N / 2;
    if (copy_len > MAX_HASH_LENGTH/2) copy_len = MAX_HASH_LENGTH/2;
    strncpy(device->v_i, hash_output + copy_len, copy_len);
    device->v_i[copy_len] = '\0';
    
    char alpha_input[2048];
    int len = snprintf(alpha_input, sizeof(alpha_input), "%s%s%lld%s", 
                       device->pseudo_id, pi_hex, auth_msg->timestamp, device->v_i);
    sha3_512(alpha_input, auth_msg->alpha_i);
    
    polynomial_clear(&ei); polynomial_clear(&epi); polynomial_clear(&temp);
    return 1;
}

int puf_smart_device_verify_server_response(PUFSmartDevice* device, const char* server_id,
                                           const Polynomial* server_public_key,
                                           const int* c_j, const char* alpha_j,
                                           long long int timestamp,
                                           const Polynomial* trusted_authority_public_key,
                                           PUFAuthMessage* auth_msg, const int* c_i) {
    (void)trusted_authority_public_key; (void)c_j; (void)c_i; (void)server_public_key;
    
    // Verify Timestamp (Step 8 in Algorithm Round 2, but on device side)
    if (llabs((long long)time(NULL) - timestamp) > 300) return 0;

    // Verify Server polynomial is valid and non-zero (prevents zero-polynomial attack)
    if (!polynomial_is_valid_nonzero(&auth_msg->sigma_j)) return 0;

    // Step 16: sh_D = pj * ei
    Polynomial sh_D;
    polynomial_init(&sh_D);
    polynomial_multiply_ntt(&auth_msg->sigma_j, &device->sk_i, &sh_D); // Use sigma_j as pj here
    
    // Step 17: Verify alpha_j = H(server_id || PID_i || p_i || p_j || w || K_D || tau || T_s || C_s || d_i)
    char pi_hex[RLWE_N * 2 + 1];
    char pj_hex[RLWE_N * 2 + 1];
    char sh_hex[(RLWE_N / 8) * 2 + 1];
    char w_hex[(RLWE_N / 8) * 2 + 1];
    polynomial_to_hex(&auth_msg->p_i, pi_hex);
    polynomial_to_hex(&auth_msg->sigma_j, pj_hex);
    peikert_reconcile(&sh_D, auth_msg->w_signal, sh_hex);
    printf("[Device] Reconciled K_D: %.32s...\n", sh_hex);
    
    for (int i = 0; i < RLWE_N / 8; i++) {
        sprintf(w_hex + i * 2, "%02x", auth_msg->w_signal[i]);
    }
    
    char verify_input[8192];
    int input_len = snprintf(verify_input, sizeof(verify_input), "%s%s%s%s%s%s", 
                             server_id, device->pseudo_id, pi_hex, pj_hex, w_hex, sh_hex);
    memcpy(verify_input + input_len, auth_msg->puf_token, PUF_KEY_SIZE);
    input_len += PUF_KEY_SIZE;
    
    char ts_str[64];
    int ts_len = snprintf(ts_str, sizeof(ts_str), "%lld", auth_msg->timestamp);
    memcpy(verify_input + input_len, ts_str, ts_len);
    input_len += ts_len;
    
    memcpy(verify_input + input_len, auth_msg->puf_challenge, PUF_CHALLENGE_SIZE);
    input_len += PUF_CHALLENGE_SIZE;
    
    int di_len = strlen(device->d_i);
    memcpy(verify_input + input_len, device->d_i, di_len);
    input_len += di_len;
    
    char computed_alpha_j[MAX_HASH_LENGTH];
    sha512(verify_input, input_len, computed_alpha_j);
    
    int match = (strcmp(computed_alpha_j, alpha_j) == 0);
    
    if (match) {
        // Generate alpha_i = H(PID_i || server_id || p_i || p_j || w || K_D || T_s || C_s || v_i)
        char alpha_input[8192];
        int a_len = snprintf(alpha_input, sizeof(alpha_input), "%s%s%s%s%s%s", 
                             device->pseudo_id, server_id, pi_hex, pj_hex, w_hex, sh_hex);
        
        memcpy(alpha_input + a_len, ts_str, ts_len);
        a_len += ts_len;
        
        memcpy(alpha_input + a_len, auth_msg->puf_challenge, PUF_CHALLENGE_SIZE);
        a_len += PUF_CHALLENGE_SIZE;
        
        int vi_len = strlen(device->v_i);
        memcpy(alpha_input + a_len, device->v_i, vi_len);
        a_len += vi_len;
        
        sha512(alpha_input, a_len, auth_msg->alpha_i);
    }
    
    polynomial_clear(&sh_D);
    return match;
}

// Enhanced Edge Server Functions
void puf_edge_server_init(PUFEdgeServer* server, const char* server_id) {
    strncpy(server->server_id, server_id, MAX_ID_LENGTH - 1);
    server->server_id[MAX_ID_LENGTH - 1] = '\0';
    
    polynomial_init(&server->sk_j);
    polynomial_init(&server->pk_j);
    polynomial_init(&server->temp_poly);
    
    polynomial_gaussian(&server->sk_j); // Changed from uniform to gaussian for security
    polynomial_uniform(&server->temp_poly);
    polynomial_multiply_ntt(&server->temp_poly, &server->sk_j, &server->pk_j);
    
    Polynomial e_sk_j;
    polynomial_init(&e_sk_j);
    polynomial_gaussian(&e_sk_j);
    polynomial_add(&server->pk_j, &server->pk_j, &e_sk_j); // pk_j = a * sk_j + e_sk_j
    polynomial_clear(&e_sk_j);    
    printf("PUF-Enhanced Edge Server %s initialized\n", server_id);
}

void puf_edge_server_cleanup(PUFEdgeServer* server) {
    polynomial_clear(&server->sk_j);
    polynomial_clear(&server->pk_j);
    polynomial_clear(&server->temp_poly);
}

void puf_edge_server_prepare_registration(PUFEdgeServer* server, char* server_id_out,
                                         Polynomial* public_key_out) {
    strcpy(server_id_out, server->server_id);
    polynomial_copy(public_key_out, &server->pk_j);
}

int puf_edge_server_verify_device_authentication(PUFEdgeServer* server, const char* pseudo_id,
                                                const Polynomial* device_public_key,
                                                const int* c_i, const char* alpha_i,
                                                long long int timestamp,
                                                const Polynomial* trusted_authority_public_key,
                                                PUFTrustedAuthority* ta, PUFAuthMessage* auth_msg, int* c_j) {
    (void)device_public_key; (void)c_i; (void)c_j;
    
    // Step 8: Verify Ts and alpha_i
    if (llabs((long long)time(NULL) - timestamp) > 300) return 0;
    
    // Verify Device polynomial is valid and non-zero (prevents zero-polynomial attack)
    if (!polynomial_is_valid_nonzero(&auth_msg->p_i)) return 0;
    
    PUFDeviceRegistryEntry* entry = NULL;
    for (size_t i = 0; i < ta->registry_size; i++) {
        if (strcmp(ta->device_registry[i].pseudo_id, pseudo_id) == 0) {
            entry = &ta->device_registry[i];
            break;
        }
    }
    if (!entry) return 0;
    
    // (alpha_i verification moved to Round 3)
    
    // Step 11 & 12: Sample ej, e''j; pj = a * ej + e''j
    Polynomial ej, epj, temp;
    polynomial_init(&ej); polynomial_init(&epj); polynomial_init(&temp);
    polynomial_gaussian(&ej);
    polynomial_gaussian(&epj);
    
    polynomial_multiply_ntt(trusted_authority_public_key, &ej, &temp);
    polynomial_add(&temp, &epj, &auth_msg->sigma_j); // sigma_j acts as pj
    
    // Step 13: sh_S = pi * ej
    Polynomial sh_S;
    polynomial_init(&sh_S);
    polynomial_multiply_ntt(&auth_msg->p_i, &ej, &sh_S);
    
    // Step 14: alpha_j = H(server_id || PID_i || p_i || p_j || w || K_S || tau || T_s || C_s || d_i)
    char pi_hex[RLWE_N * 2 + 1];
    char pj_hex[RLWE_N * 2 + 1];
    char sh_hex[(RLWE_N / 8) * 2 + 1];
    char w_hex[(RLWE_N / 8) * 2 + 1];
    polynomial_to_hex(&auth_msg->p_i, pi_hex);
    polynomial_to_hex(&auth_msg->sigma_j, pj_hex);
    peikert_signal(&sh_S, auth_msg->w_signal);
    peikert_reconcile(&sh_S, auth_msg->w_signal, sh_hex);
    
    for (int i = 0; i < RLWE_N / 8; i++) {
        sprintf(w_hex + i * 2, "%02x", auth_msg->w_signal[i]);
    }
    
    char alpha_input[8192];
    int input_len = snprintf(alpha_input, sizeof(alpha_input), "%s%s%s%s%s%s", 
                             server->server_id, pseudo_id, pi_hex, pj_hex, w_hex, sh_hex);
    memcpy(alpha_input + input_len, auth_msg->puf_token, PUF_KEY_SIZE);
    input_len += PUF_KEY_SIZE;
    
    char ts_str[64];
    int ts_len = snprintf(ts_str, sizeof(ts_str), "%lld", auth_msg->timestamp);
    memcpy(alpha_input + input_len, ts_str, ts_len);
    input_len += ts_len;
    
    memcpy(alpha_input + input_len, auth_msg->puf_challenge, PUF_CHALLENGE_SIZE);
    input_len += PUF_CHALLENGE_SIZE;
    
    int di_len = strlen(entry->d_i);
    memcpy(alpha_input + input_len, entry->d_i, di_len);
    input_len += di_len;
    
    sha512(alpha_input, input_len, auth_msg->alpha_j);
    strcpy(auth_msg->K_hex, sh_hex);
    printf("[Server] Generated K_S: %.32s...\n", sh_hex);
    
    // Cleanup
    polynomial_clear(&ej); polynomial_clear(&epj); polynomial_clear(&temp); polynomial_clear(&sh_S);
    return 1;
}


int puf_edge_server_verify_client_auth(PUFEdgeServer *server, const char *pseudo_id,
                                       PUFTrustedAuthority *ta, PUFAuthMessage *auth_msg) {
    PUFDeviceRegistryEntry* entry = NULL;
    for (size_t i = 0; i < ta->registry_size; i++) {
        if (strcmp(ta->device_registry[i].pseudo_id, pseudo_id) == 0) {
            entry = &ta->device_registry[i];
            break;
        }
    }
    if (!entry) return 0;
    
    char pi_hex[RLWE_N * 2 + 1];
    char pj_hex[RLWE_N * 2 + 1];
    char w_hex[(RLWE_N / 8) * 2 + 1];
    polynomial_to_hex(&auth_msg->p_i, pi_hex);
    polynomial_to_hex(&auth_msg->sigma_j, pj_hex);
    for (int i = 0; i < RLWE_N / 8; i++) {
        sprintf(w_hex + i * 2, "%02x", auth_msg->w_signal[i]);
    }

    char verify_input[8192];
    int input_len = snprintf(verify_input, sizeof(verify_input), "%s%s%s%s%s%s", 
                             pseudo_id, server->server_id, pi_hex, pj_hex, w_hex, auth_msg->K_hex);
    
    char ts_str[64];
    int ts_len = snprintf(ts_str, sizeof(ts_str), "%lld", auth_msg->timestamp);
    memcpy(verify_input + input_len, ts_str, ts_len);
    input_len += ts_len;
    
    memcpy(verify_input + input_len, auth_msg->puf_challenge, PUF_CHALLENGE_SIZE);
    input_len += PUF_CHALLENGE_SIZE;
    
    int vi_len = strlen(entry->v_i);
    memcpy(verify_input + input_len, entry->v_i, vi_len);
    input_len += vi_len;
    
    char computed_alpha_i[MAX_HASH_LENGTH];
    sha512(verify_input, input_len, computed_alpha_i);
    
    if (strcmp(computed_alpha_i, auth_msg->alpha_i) != 0) {
        printf("Server rejected Round 3 alpha_i authentication!\n");
        return 0;
    }
    return 1;
}

// Enhanced session key computation with PUF
void puf_compute_session_key(const char* pseudo_id, const char* server_id,
                             const Polynomial* p_i, const int* w_i, const int* sigma_i,
                             const char* alpha_i, const Polynomial* p_j, const int* w_j,
                             const int* sigma_j, const char* alpha_j,
                             const char* K_hex, const char* v_i, char* session_key) {
    (void)w_i; (void)sigma_i; (void)w_j; (void)sigma_j;
    
    char p_i_hex[RLWE_N * 2 + 1];
    char p_j_hex[RLWE_N * 2 + 1];
    
    polynomial_to_hex(p_i, p_i_hex);
    polynomial_to_hex(p_j, p_j_hex);
    
    char session_input[8192];
    int len = snprintf(session_input, sizeof(session_input), "%s%s%s%s%s%s%s%s",
                       pseudo_id, server_id, p_i_hex, p_j_hex, alpha_i, alpha_j, K_hex, v_i);
    
    sha3_512(session_input, session_key);
}

// Rotate pseudo-id for a device and update TA registry accordingly
int puf_smart_device_rotate_pseudo_id(PUFSmartDevice* device, PUFTrustedAuthority* ta, char* new_pseudo_id_out) {
    if (!device || !ta) return 0;

    // Generate new pseudo id: use timestamp + device id + PUF response
    char timestamp[64];
    sprintf(timestamp, "%ld", time(NULL));
    char pseudo_input[MAX_ID_LENGTH + 64 + PUF_RESPONSE_SIZE];
    snprintf(pseudo_input, sizeof(pseudo_input), "%s%s", device->device_id, timestamp);
    if (device->puf.is_enrolled) {
        memcpy(pseudo_input + strlen(pseudo_input), device->puf.enrolled_response.response, PUF_RESPONSE_SIZE);
    }

    char pseudo_hash[MAX_HASH_LENGTH];
    sha3_512(pseudo_input, pseudo_hash);
    strncpy(new_pseudo_id_out, pseudo_hash, MAX_ID_LENGTH - 1);
    new_pseudo_id_out[MAX_ID_LENGTH - 1] = '\0';

    // Update device
    char old_pseudo[MAX_ID_LENGTH];
    strncpy(old_pseudo, device->pseudo_id, MAX_ID_LENGTH);
    strncpy(device->pseudo_id, new_pseudo_id_out, MAX_ID_LENGTH);

    // Update TA registry entry and key identifiers
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

    printf("Pseudo-ID rotated: %s -> %s\n", old_pseudo, new_pseudo_id_out);
    return 1;
}

// Change device password and update TA stored parameters (d_i/v_i) accordingly
int puf_smart_device_change_password(PUFSmartDevice* device, PUFTrustedAuthority* ta, const char* old_pwd, const char* new_pwd) {
    if (!device || !ta || !old_pwd || !new_pwd) return 0;
    
    char old_pw_salt_input[512];
    char old_pw_salted_hash[MAX_HASH_LENGTH];
    sprintf(old_pw_salt_input, "%s%s", old_pwd, device->device_id);
    sha3_512(old_pw_salt_input, old_pw_salted_hash);
    
    if (strcmp(device->password_hash, old_pw_salted_hash) != 0) {
        printf("Old password mismatch for device %s\n", device->device_id);
        return 0;
    }

    // Update device password hash
    char new_pw_salt_input[512];
    sprintf(new_pw_salt_input, "%s%s", new_pwd, device->device_id);
    sha3_512(new_pw_salt_input, device->password_hash);

    // Recompute password-hash and derived d_i/v_i like registration
    char hash_input[2048];
    int pw_len = strlen(new_pwd);
    memcpy(hash_input, new_pwd, pw_len);
    memcpy(hash_input + pw_len, device->puf_derived_key, PUF_KEY_SIZE);
    char password_hash_out[MAX_HASH_LENGTH];
    sha512(hash_input, pw_len + PUF_KEY_SIZE, password_hash_out);

    int copy_len = RLWE_N / 2;
    if (copy_len > MAX_HASH_LENGTH/2) copy_len = MAX_HASH_LENGTH/2;
    char d_i_new[RLWE_N];
    char v_i_new[RLWE_N];
    strncpy(d_i_new, password_hash_out, copy_len);
    strncpy(v_i_new, password_hash_out + copy_len, copy_len);
    d_i_new[copy_len] = '\0';
    v_i_new[copy_len] = '\0';

    // Update device local copy
    puf_smart_device_store_parameters(device, d_i_new, v_i_new);

    // Update TA registry entry for this pseudo id
    for (size_t i = 0; i < ta->registry_size; i++) {
        if (ta->device_registry[i].pseudo_id && strcmp(ta->device_registry[i].pseudo_id, device->pseudo_id) == 0) {
            free(ta->device_registry[i].d_i);
            free(ta->device_registry[i].v_i);
            ta->device_registry[i].d_i = malloc(strlen(d_i_new) + 1);
            ta->device_registry[i].v_i = malloc(strlen(v_i_new) + 1);
            strcpy(ta->device_registry[i].d_i, d_i_new);
            strcpy(ta->device_registry[i].v_i, v_i_new);
            printf("TA updated stored credentials for pseudo-id %s\n", device->pseudo_id);
            return 1;
        }
    }

    printf("TA registry entry not found for pseudo-id %s\n", device->pseudo_id);
    return 0;
}

// Orchestrate a simple mutual authentication (happy-path wrapper)
int puf_perform_mutual_auth(PUFSmartDevice* device, PUFEdgeServer* server, PUFTrustedAuthority* ta) {
    if (!device || !server || !ta) return 0;

    PUFAuthMessage auth_msg;
    int c_i[RLWE_N];
    int c_j[RLWE_N];

    // Device initiates (produces auth_msg and c_i)
    if (!puf_smart_device_initiate_authentication(device, &server->pk_j, &ta->a, &auth_msg, c_i)) {
        printf("Device initiation failed\n");
        return 0;
    }

    // Server verifies/generates response (fills auth_msg.sigma_j, alpha_j, and c_j)
    if (!puf_edge_server_verify_device_authentication(server, device->pseudo_id, &device->pk_i, c_i, auth_msg.alpha_i, (long long)time(NULL), &ta->a, ta, &auth_msg, c_j)) {
        printf("Server verification failed\n");
        return 0;
    }

    // Device verifies server response
    if (!puf_smart_device_verify_server_response(device, server->server_id, &server->pk_j, c_j, auth_msg.alpha_j, (long long)time(NULL), &ta->a, &auth_msg, c_i)) {
        printf("Device verification of server response failed\n");
        return 0;
    }
    
    // Server verifies client final authenticator
    if (!puf_edge_server_verify_client_auth(server, device->pseudo_id, ta, &auth_msg)) {
        printf("Server verification of client final response failed\n");
        return 0;
    }

    printf("Mutual authentication succeeded between device %s and server %s\n", device->device_id, server->server_id);
    return 1;
}
