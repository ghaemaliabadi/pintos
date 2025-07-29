#ifndef FILESYS_ENCRYPTION_H
#define FILESYS_ENCRYPTION_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* AES constants */
#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE 16  /* AES-128 */
#define AES_IV_SIZE 16

/* Encryption constants */
#define ENCRYPTION_SALT_SIZE 16
#define ENCRYPTION_PASSWORD_MAX 256

/* Forward declarations */
struct inode;

/* AES context structure */
struct aes_ctx {
    uint32_t round_keys[44]; /* 11 round keys for AES-128 */
};

/* Encryption metadata structure */
struct encryption_meta {
    bool encrypted;
    uint8_t salt[ENCRYPTION_SALT_SIZE];
    uint8_t iv[AES_IV_SIZE];
    uint32_t pbkdf2_iterations;
};

/* AES functions */
void aes_init(void);
void aes_set_key(struct aes_ctx *ctx, const uint8_t key[AES_KEY_SIZE]);
void aes_encrypt_block(const struct aes_ctx *ctx, 
                       const uint8_t input[AES_BLOCK_SIZE],
                       uint8_t output[AES_BLOCK_SIZE]);
void aes_decrypt_block(const struct aes_ctx *ctx,
                       const uint8_t input[AES_BLOCK_SIZE], 
                       uint8_t output[AES_BLOCK_SIZE]);

/* CBC mode functions */
void aes_cbc_encrypt(const struct aes_ctx *ctx,
                     const uint8_t *input, uint8_t *output, size_t length,
                     const uint8_t iv[AES_IV_SIZE]);
void aes_cbc_decrypt(const struct aes_ctx *ctx,
                     const uint8_t *input, uint8_t *output, size_t length,
                     const uint8_t iv[AES_IV_SIZE]);

/* Key derivation functions */
void derive_key_from_password(const char *password,
                              const uint8_t salt[ENCRYPTION_SALT_SIZE],
                              uint32_t iterations,
                              uint8_t key[AES_KEY_SIZE]);

/* High-level encryption functions */
bool encrypt_file_data(struct inode *inode, const char *password);
bool decrypt_file_data(struct inode *inode, const char *password);
bool change_file_password(struct inode *inode, 
                          const char *old_password,
                          const char *new_password);
bool is_file_encrypted(struct inode *inode);

/* Block-level encryption functions */
void encrypt_block(const uint8_t *input, uint8_t *output,
                   const struct encryption_meta *meta,
                   const uint8_t key[AES_KEY_SIZE],
                   uint32_t block_index);
void decrypt_block(const uint8_t *input, uint8_t *output,
                   const struct encryption_meta *meta,
                   const uint8_t key[AES_KEY_SIZE],
                   uint32_t block_index);

/* Key caching for performance */
struct key_cache_entry {
    uint32_t inode_number;
    uint8_t key[AES_KEY_SIZE];
    uint32_t last_access;
};

#define KEY_CACHE_SIZE 16
extern struct key_cache_entry key_cache[KEY_CACHE_SIZE];

bool cache_get_key(uint32_t inode_number, uint8_t key[AES_KEY_SIZE]);
void cache_store_key(uint32_t inode_number, const uint8_t key[AES_KEY_SIZE]);
void cache_invalidate_key(uint32_t inode_number);
void cache_clear_all(void);

#endif /* filesys/encryption.h */