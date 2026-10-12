#ifndef PUF_H
#define PUF_H

#include <stdint.h>
#include <stdlib.h>

#define PUF_RESPONSE_SIZE 32
#define PUF_CHALLENGE_SIZE 32
#define PUF_HELPER_DATA_SIZE 32
#define PUF_NOISE_THRESHOLD 0.10
// Entropy pool size used by the more advanced PUF implementation
#define PUF_ENTROPY_POOL_SIZE 256

// PUF Response structure
typedef struct {
    uint8_t response[PUF_RESPONSE_SIZE];
    uint8_t helper_data[PUF_HELPER_DATA_SIZE];
    uint8_t challenge[PUF_CHALLENGE_SIZE];
    int stability_score;
    /* Optional device fingerprint (32 bytes) stored with a response for advanced implementations */
    uint8_t device_fingerprint[32];
} PUFResponse;

// PUF Device structure
typedef struct {
    char device_id[64];
    PUFResponse enrolled_response;
    PUFResponse current_response;
    int is_enrolled;
    unsigned int random_seed;
    /* Advanced fields used by the realistic PUF implementation */
    uint8_t device_fingerprint[32];
    float process_variation;    /* manufacturing variation factor (0..1) */
    float temperature_effect;   /* dynamic temperature effect */
    float aging_factor;        /* degradation over time */
    float bit_error_rate;      /* tracked BER */
    int enrollment_count;      /* number of enrollments/samples taken */
    uint8_t entropy_pool[PUF_ENTROPY_POOL_SIZE]; /* local entropy for noise mixing */
} PUFDevice;

// PUF Functions
void puf_device_init(PUFDevice* puf, const char* device_id);
int puf_generate_challenge(PUFDevice* puf, uint8_t* challenge);
int puf_generate_response(PUFDevice* puf, const uint8_t* challenge, PUFResponse* response, int use_error_correction);
int puf_enroll_device(PUFDevice* puf);
int puf_verify_device(PUFDevice* puf, const PUFResponse* stored_response);
int puf_verify_device_identity(const PUFDevice* puf);
float puf_calculate_similarity(const uint8_t* resp1, const uint8_t* resp2, size_t length);
void puf_generate_helper_data(const uint8_t* response, uint8_t* helper_data);
int puf_error_correction(const uint8_t* noisy_response, const uint8_t* helper_data, uint8_t* corrected_response);
/* Realistic physical variation simulation (advanced API) */
void puf_simulate_physical_variation(PUFDevice* puf, uint8_t* response, float base_noise_level);
int puf_bit_error_rate(const uint8_t* resp1, const uint8_t* resp2, size_t length);

#endif
