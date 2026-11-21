#ifndef PUF_H
#define PUF_H

#include <stdint.h>
#include <stdlib.h>

#define PUF_RESPONSE_SIZE 32          /* 256-bit secret seed r_i (32 bytes) */
#define PUF_CHALLENGE_SIZE 32         /* 256-bit challenge C_s (32 bytes) */
#define PUF_REP_FACTOR 15             /* [15, 1, 15] repetition code */
#define PUF_HELPER_DATA_SIZE 480      /* 3,840-bit helper data h_i = R_i XOR Rep15(r_i) (480 bytes) */
#define PUF_NOISE_THRESHOLD 0.10

// Compact PUF Response & Helper Data structure
typedef struct {
    uint8_t response[PUF_RESPONSE_SIZE];           /* 32-byte seed r_i */
    uint8_t raw_sram[PUF_HELPER_DATA_SIZE];        /* 480-byte (3,840-bit) raw SRAM state R'_i */
    uint8_t helper_data[PUF_HELPER_DATA_SIZE];     /* 480-byte (3,840-bit) public helper data h_i */
    uint8_t challenge[PUF_CHALLENGE_SIZE];         /* 32-byte challenge */
    int stability_score;
} PUFResponse;

// Compact PUF Device structure
typedef struct {
    char device_id[64];
    PUFResponse enrolled_response;
    int is_enrolled;
    unsigned int random_seed;
} PUFDevice;

// PUF Functions
void puf_device_init(PUFDevice* puf, const char* device_id);
int puf_generate_challenge(PUFDevice* puf, uint8_t* challenge);
int puf_generate_response(PUFDevice* puf, const uint8_t* challenge, PUFResponse* response, int use_error_correction);
int puf_enroll_device(PUFDevice* puf);
int puf_verify_device(PUFDevice* puf, const PUFResponse* stored_response);
int puf_verify_device_identity(const PUFDevice* puf);
float puf_calculate_similarity(const uint8_t* resp1, const uint8_t* resp2, size_t length);
void puf_generate_helper_data(const uint8_t* raw_sram, const uint8_t* secret_seed, uint8_t* helper_data);
int puf_error_correction(const uint8_t* noisy_raw_sram, const uint8_t* helper_data, uint8_t* corrected_seed);
void puf_simulate_physical_variation(PUFDevice* puf, uint8_t* response, float base_noise_level);
int puf_bit_error_rate(const uint8_t* resp1, const uint8_t* resp2, size_t length);

#endif
