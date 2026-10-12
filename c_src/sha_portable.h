#ifndef SHA_PORTABLE_H
#define SHA_PORTABLE_H

#include <stddef.h>
#include <stdint.h>

#define SHA256_DIGEST_LENGTH 32
#define SHA512_DIGEST_LENGTH 64

// SHA-256
typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[64];
} sha256_context;

void sha256_init(sha256_context *ctx);
void sha256_update(sha256_context *ctx, const uint8_t *data, size_t len);
void sha256_final(sha256_context *ctx, uint8_t *digest);
void SHA256_simple(const unsigned char *d, size_t n, unsigned char *md);

// SHA-512
typedef struct {
    uint64_t state[8];
    uint64_t count[2];
    uint8_t buffer[128];
} sha512_context;

void sha512_init(sha512_context *ctx);
void sha512_update(sha512_context *ctx, const uint8_t *data, size_t len);
void sha512_final(sha512_context *ctx, uint8_t *digest);
void SHA512_simple(const unsigned char *d, size_t n, unsigned char *md);

#endif
