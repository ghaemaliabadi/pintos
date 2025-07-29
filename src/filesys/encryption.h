#ifndef FILESYS_ENCRYPTION_H
#define FILESYS_ENCRYPTION_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "devices/block.h"

/* AES-128 constants */
#define AES_KEY_SIZE 16       /* 128 bits */
#define AES_BLOCK_SIZE 16     /* 128 bits */
#define AES_IV_SIZE 16        /* 128 bits */

/* Encryption salt size for PBKDF2 */
#define ENCRYPTION_SALT_SIZE 16

/* PBKDF2 iteration count (high for security) */
#define PBKDF2_ITERATIONS 10000

/* Maximum password length */
#define MAX_PASSWORD_LENGTH 256

/* Encryption block header stored at the beginning of each encrypted block */
struct encryption_block_header {
    uint8_t iv[AES_IV_SIZE];        /* Initialization vector */
    uint32_t checksum;              /* Simple checksum for integrity */
};

/* Encryption metadata stored in inode */
struct encryption_metadata {
    uint8_t salt[ENCRYPTION_SALT_SIZE];  /* Salt for key derivation */
    bool is_encrypted;                   /* Whether file is encrypted */
    uint8_t padding[3];                  /* Padding for alignment */
};

/* In-memory encryption context for a file */
struct encryption_context {
    uint8_t key[AES_KEY_SIZE];      /* Derived encryption key */
    bool key_valid;                 /* Whether key is available */
};

/* AES key schedule - internal use */
struct aes_key_schedule {
    uint32_t round_keys[44];        /* Expanded key for AES-128 */
};

/* Function declarations */

/* Core encryption functions */
void encryption_init(void);
bool aes_encrypt_block(const uint8_t *plaintext, uint8_t *ciphertext, 
                      const uint8_t *key, const uint8_t *iv);
bool aes_decrypt_block(const uint8_t *ciphertext, uint8_t *plaintext,
                      const uint8_t *key, const uint8_t *iv);

/* Key derivation and management */
bool pbkdf2_derive_key(const char *password, const uint8_t *salt,
                      uint8_t *key);
void generate_random_salt(uint8_t *salt);
void generate_random_iv(uint8_t *iv);

/* Block-level encryption/decryption */
bool encrypt_sector(const void *plaintext, void *ciphertext,
                   const struct encryption_context *ctx);
bool decrypt_sector(const void *ciphertext, void *plaintext,
                   const struct encryption_context *ctx);

/* Encryption context management */
void encryption_context_init(struct encryption_context *ctx);
bool encryption_context_set_password(struct encryption_context *ctx,
                                    const char *password,
                                    const struct encryption_metadata *metadata);
void encryption_context_clear(struct encryption_context *ctx);

/* Utility functions */
uint32_t calculate_checksum(const void *data, size_t size);
void secure_zero(void *ptr, size_t size);

#endif /* filesys/encryption.h */