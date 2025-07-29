#ifndef LIB_KERNEL_CRYPTO_H
#define LIB_KERNEL_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

/* SHA-256 constants */
#define SHA256_DIGEST_SIZE 32
#define SHA256_BLOCK_SIZE 64

/* PBKDF2 constants */
#define PBKDF2_MIN_ITERATIONS 10000
#define PBKDF2_SALT_SIZE 16
#define PBKDF2_KEY_SIZE 16  /* 128-bit keys for AES */

/* SHA-256 context structure */
struct sha256_ctx {
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[SHA256_BLOCK_SIZE];
};

/* SHA-256 functions */
void sha256_init(struct sha256_ctx *ctx);
void sha256_update(struct sha256_ctx *ctx, const uint8_t *data, size_t len);
void sha256_final(struct sha256_ctx *ctx, uint8_t digest[SHA256_DIGEST_SIZE]);

/* HMAC-SHA256 functions */
void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t output[SHA256_DIGEST_SIZE]);

/* PBKDF2 with HMAC-SHA256 */
void pbkdf2_hmac_sha256(const char *password, size_t password_len,
                        const uint8_t *salt, size_t salt_len,
                        uint32_t iterations,
                        uint8_t *output, size_t output_len);

/* Secure random number generation */
void crypto_random_bytes(uint8_t *buffer, size_t size);

/* Secure memory operations */
void secure_zero(void *ptr, size_t size);

#endif /* lib/kernel/crypto.h */