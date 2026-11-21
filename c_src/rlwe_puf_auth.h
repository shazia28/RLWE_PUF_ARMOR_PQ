#ifndef RLWE_PUF_AUTH_H
#define RLWE_PUF_AUTH_H

#include "puf.h"
#include "rlwe_core.h"

// Enhanced constants with PUF integration
#define MAX_ID_LENGTH 64
#define MAX_PASSWORD_LENGTH 64
#define MAX_HASH_LENGTH 129 // SHA512 produces 128 hex chars + null terminator
#define PUF_KEY_SIZE 32

// Compact authentication message with 16-bit polynomials (no unused w_i/sigma_i copies)
typedef struct {
  Polynomial p_i;                              /* 1,024 B: ephemeral client polynomial */
  Polynomial sigma_j;                          /* 1,024 B: ephemeral server polynomial p_j */
  char alpha_i[MAX_HASH_LENGTH];               /* 129 B: client authenticator */
  char alpha_j[MAX_HASH_LENGTH];               /* 129 B: server authenticator */
  uint8_t puf_challenge[PUF_CHALLENGE_SIZE];   /* 32 B: challenge nonce C_s */
  uint8_t puf_verification_token[PUF_KEY_SIZE];/* 32 B */
  long long int timestamp;                     /* 8 B: timestamp T_s */
  uint8_t puf_token[PUF_KEY_SIZE];             /* 32 B: session token tau */
  char K_hex[MAX_HASH_LENGTH];                 /* 129 B: reconciled 512-bit key hex */
  uint8_t w_signal[RLWE_N / 8];                /* 64 B: 512-bit Peikert hint vector w */
} PUFAuthMessage;

// Device registry entry on Trusted Authority / Authentication Server
typedef struct {
  char *device_id;
  char *pseudo_id;
  char *d_i;
  char *v_i;
  PUFResponse puf_response;
} PUFDeviceRegistryEntry;

// Trusted Authority structure
typedef struct {
  Polynomial sm; // System master key
  Polynomial pm; // Public matrix
  Polynomial a;  // Public parameter
  int q;
  int n;
  double beta;
  char hash_name[64];
  int is_initialized;

  PUFDeviceRegistryEntry *device_registry;
  size_t registry_size;
  size_t registry_capacity;

  Polynomial *public_keys;
  char **key_identifiers;
  size_t keys_size;
  size_t keys_capacity;
} PUFTrustedAuthority;

// Compact Smart Device state (volatile sk_i reconstructed on-demand from SRAM PUF)
typedef struct {
  char device_id[MAX_ID_LENGTH];
  char password_hash[MAX_HASH_LENGTH];
  char pseudo_id[MAX_ID_LENGTH];
  char d_i[MAX_HASH_LENGTH];
  char v_i[MAX_HASH_LENGTH];

  Polynomial sk_i; /* 1,024 B: volatile secret polynomial (zeroized after session) */
  Polynomial pk_i; /* 1,024 B: public key polynomial a*sk_i + e_{pk,i} */
  Polynomial e_i;  /* 1,024 B: volatile ephemeral secret polynomial */

  PUFDevice puf;   /* Integrated SRAM PUF & 480-byte helper data */
  uint8_t puf_derived_key[PUF_KEY_SIZE];
} PUFSmartDevice;

// Compact Edge Server state
typedef struct {
  char server_id[MAX_ID_LENGTH];
  Polynomial sk_j;
  Polynomial pk_j;
} PUFEdgeServer;

// Trusted Authority functions
void puf_trusted_authority_init(PUFTrustedAuthority *ta);
void puf_trusted_authority_cleanup(PUFTrustedAuthority *ta);
void puf_system_initialization(PUFTrustedAuthority *ta);
int puf_register_device(PUFTrustedAuthority *ta, PUFSmartDevice *device,
                        const char *password, char *d_i_out, char *v_i_out);
void puf_register_server(PUFTrustedAuthority *ta, const char *server_id,
                         const Polynomial *public_key);
const Polynomial *puf_get_public_key(const PUFTrustedAuthority *ta,
                                     const char *identifier);

// Account management helpers
int puf_smart_device_rotate_pseudo_id(PUFSmartDevice *device,
                                      PUFTrustedAuthority *ta,
                                      char *new_pseudo_id_out);
int puf_smart_device_change_password(PUFSmartDevice *device,
                                     PUFTrustedAuthority *ta,
                                     const char *old_pwd, const char *new_pwd);

// Mutual authentication orchestration
int puf_perform_mutual_auth(PUFSmartDevice *device, PUFEdgeServer *server,
                            PUFTrustedAuthority *ta);

// Smart Device functions
void puf_smart_device_init(PUFSmartDevice *device, const char *device_id,
                           const char *password);
void puf_smart_device_cleanup(PUFSmartDevice *device);
void puf_smart_device_enroll_puf(PUFSmartDevice *device);
int puf_smart_device_prepare_registration(PUFSmartDevice *device,
                                          char *device_id_out,
                                          char *pseudo_id_out,
                                          Polynomial *public_key_out,
                                          char *password_hash_out);
void puf_smart_device_store_parameters(PUFSmartDevice *device, const char *d_i,
                                       const char *v_i);
int puf_smart_device_initiate_authentication(
    PUFSmartDevice *device, const Polynomial *server_public_key,
    const Polynomial *trusted_authority_public_key, PUFAuthMessage *auth_msg,
    int *c_i);
int puf_smart_device_verify_server_response(
    PUFSmartDevice *device, const char *server_id,
    const Polynomial *server_public_key, const int *c_j, const char *alpha_j,
    long long int timestamp, const Polynomial *trusted_authority_public_key,
    PUFAuthMessage *auth_msg, const int *c_i);

// Edge Server functions
void puf_edge_server_init(PUFEdgeServer *server, const char *server_id);
void puf_edge_server_cleanup(PUFEdgeServer *server);
void puf_edge_server_prepare_registration(PUFEdgeServer *server,
                                          char *server_id_out,
                                          Polynomial *public_key_out);
int puf_edge_server_verify_device_authentication(
    PUFEdgeServer *server, const char *pseudo_id,
    const Polynomial *device_public_key, const int *c_i, const char *alpha_i,
    long long int timestamp, const Polynomial *trusted_authority_public_key,
    PUFTrustedAuthority *ta, PUFAuthMessage *auth_msg, int *c_j);
int puf_edge_server_verify_client_auth(
    PUFEdgeServer *server, const char *pseudo_id,
    PUFTrustedAuthority *ta, PUFAuthMessage *auth_msg);

// Session key computation
void puf_compute_session_key(const char *pseudo_id, const char *server_id,
                             const Polynomial *p_i, const int *w_i,
                             const int *sigma_i, const char *alpha_i,
                             const Polynomial *p_j, const int *w_j,
                             const int *sigma_j, const char *alpha_j,
                             const char* K_hex, const char* v_i, char* session_key);

// PUF key derivation & unit-invertibility validation
void puf_derive_key_from_response(const uint8_t *puf_response,
                                  uint8_t *derived_key);
void puf_derive_secret_polynomial(const uint8_t *secret_seed, Polynomial *sk_out);
int polynomial_is_valid_nonzero(const Polynomial* poly);
int polynomial_is_valid_unit(const Polynomial* poly);
int puf_verify_device_identity_wrapper(const PUFSmartDevice *device);

// Peikert Reconciliation functions (unified shift equations)
void peikert_signal(const Polynomial* poly, uint8_t* w_signal);
void peikert_reconcile(const Polynomial* poly, const uint8_t* w_signal, char* hex_str);

#endif
