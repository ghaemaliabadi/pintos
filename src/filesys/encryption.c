#include "filesys/encryption.h"
#include "lib/kernel/hash.h"
#include "lib/random.h"
#include "lib/string.h"
#include "threads/malloc.h"
#include <debug.h>

/* AES S-box for SubBytes transformation */
static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16
};

/* Inverse S-box for InvSubBytes transformation */
static const uint8_t inv_sbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
    0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32,
    0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
    0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
    0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
    0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
    0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
    0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
    0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59,
    0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d,
    0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
    0x55, 0x21, 0x0c, 0x7d
};

/* Rcon constants for key expansion */
static const uint32_t rcon[10] = {
    0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
    0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000
};

/* Helper functions */
static uint32_t rotl(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

static uint32_t sub_word(uint32_t word) {
    return (sbox[(word >> 24) & 0xff] << 24) |
           (sbox[(word >> 16) & 0xff] << 16) |
           (sbox[(word >> 8) & 0xff] << 8) |
           (sbox[word & 0xff]);
}

/* AES key expansion */
static void aes_key_expansion(const uint8_t *key, struct aes_key_schedule *ks) {
    uint32_t *w = ks->round_keys;
    
    /* First 4 words are the original key */
    for (int i = 0; i < 4; i++) {
        w[i] = (key[4*i] << 24) | (key[4*i+1] << 16) | 
               (key[4*i+2] << 8) | key[4*i+3];
    }
    
    /* Generate remaining 40 words */
    for (int i = 4; i < 44; i++) {
        uint32_t temp = w[i-1];
        if (i % 4 == 0) {
            temp = sub_word(rotl(temp, 8)) ^ rcon[i/4 - 1];
        }
        w[i] = w[i-4] ^ temp;
    }
}

/* AES SubBytes transformation */
static void sub_bytes(uint8_t state[16]) {
    for (int i = 0; i < 16; i++) {
        state[i] = sbox[state[i]];
    }
}

static void inv_sub_bytes(uint8_t state[16]) {
    for (int i = 0; i < 16; i++) {
        state[i] = inv_sbox[state[i]];
    }
}

/* AES ShiftRows transformation */
static void shift_rows(uint8_t state[16]) {
    uint8_t temp;
    
    /* Row 1: shift left by 1 */
    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;
    
    /* Row 2: shift left by 2 */
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;
    
    /* Row 3: shift left by 3 */
    temp = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = temp;
}

static void inv_shift_rows(uint8_t state[16]) {
    uint8_t temp;
    
    /* Row 1: shift right by 1 */
    temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;
    
    /* Row 2: shift right by 2 */
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;
    
    /* Row 3: shift right by 3 */
    temp = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = state[3];
    state[3] = temp;
}

/* Galois field multiplication for MixColumns */
static uint8_t gf_mul(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    while (b) {
        if (b & 1) {
            result ^= a;
        }
        if (a & 0x80) {
            a = (a << 1) ^ 0x1b;
        } else {
            a <<= 1;
        }
        b >>= 1;
    }
    return result;
}

/* AES MixColumns transformation */
static void mix_columns(uint8_t state[16]) {
    for (int c = 0; c < 4; c++) {
        uint8_t s0 = state[c*4], s1 = state[c*4+1], s2 = state[c*4+2], s3 = state[c*4+3];
        state[c*4] = gf_mul(0x02, s0) ^ gf_mul(0x03, s1) ^ s2 ^ s3;
        state[c*4+1] = s0 ^ gf_mul(0x02, s1) ^ gf_mul(0x03, s2) ^ s3;
        state[c*4+2] = s0 ^ s1 ^ gf_mul(0x02, s2) ^ gf_mul(0x03, s3);
        state[c*4+3] = gf_mul(0x03, s0) ^ s1 ^ s2 ^ gf_mul(0x02, s3);
    }
}

static void inv_mix_columns(uint8_t state[16]) {
    for (int c = 0; c < 4; c++) {
        uint8_t s0 = state[c*4], s1 = state[c*4+1], s2 = state[c*4+2], s3 = state[c*4+3];
        state[c*4] = gf_mul(0x0e, s0) ^ gf_mul(0x0b, s1) ^ gf_mul(0x0d, s2) ^ gf_mul(0x09, s3);
        state[c*4+1] = gf_mul(0x09, s0) ^ gf_mul(0x0e, s1) ^ gf_mul(0x0b, s2) ^ gf_mul(0x0d, s3);
        state[c*4+2] = gf_mul(0x0d, s0) ^ gf_mul(0x09, s1) ^ gf_mul(0x0e, s2) ^ gf_mul(0x0b, s3);
        state[c*4+3] = gf_mul(0x0b, s0) ^ gf_mul(0x0d, s1) ^ gf_mul(0x09, s2) ^ gf_mul(0x0e, s3);
    }
}

/* AddRoundKey transformation */
static void add_round_key(uint8_t state[16], const uint32_t *round_key) {
    for (int i = 0; i < 4; i++) {
        state[4*i] ^= (round_key[i] >> 24) & 0xff;
        state[4*i+1] ^= (round_key[i] >> 16) & 0xff;
        state[4*i+2] ^= (round_key[i] >> 8) & 0xff;
        state[4*i+3] ^= round_key[i] & 0xff;
    }
}

/* Initialize encryption subsystem */
void encryption_init(void) {
    /* Initialize random number generator if not already done */
    /* PintOS should have random_init() called during system initialization */
}

/* AES encryption of a single block */
bool aes_encrypt_block(const uint8_t *plaintext, uint8_t *ciphertext, 
                      const uint8_t *key, const uint8_t *iv) {
    if (!plaintext || !ciphertext || !key || !iv) {
        return false;
    }
    
    struct aes_key_schedule ks;
    uint8_t state[16];
    
    /* Expand the key */
    aes_key_expansion(key, &ks);
    
    /* XOR plaintext with IV for CBC mode */
    for (int i = 0; i < 16; i++) {
        state[i] = plaintext[i] ^ iv[i];
    }
    
    /* Initial AddRoundKey */
    add_round_key(state, &ks.round_keys[0]);
    
    /* 9 main rounds */
    for (int round = 1; round < 10; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, &ks.round_keys[round * 4]);
    }
    
    /* Final round (no MixColumns) */
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, &ks.round_keys[40]);
    
    /* Copy result to output */
    memcpy(ciphertext, state, 16);
    
    /* Clear sensitive data */
    secure_zero(&ks, sizeof(ks));
    secure_zero(state, sizeof(state));
    
    return true;
}

/* AES decryption of a single block */
bool aes_decrypt_block(const uint8_t *ciphertext, uint8_t *plaintext,
                      const uint8_t *key, const uint8_t *iv) {
    if (!ciphertext || !plaintext || !key || !iv) {
        return false;
    }
    
    struct aes_key_schedule ks;
    uint8_t state[16];
    
    /* Expand the key */
    aes_key_expansion(key, &ks);
    
    /* Copy ciphertext to state */
    memcpy(state, ciphertext, 16);
    
    /* Initial AddRoundKey (last round key) */
    add_round_key(state, &ks.round_keys[40]);
    
    /* 9 inverse rounds */
    for (int round = 9; round >= 1; round--) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, &ks.round_keys[round * 4]);
        inv_mix_columns(state);
    }
    
    /* Final inverse round (no InvMixColumns) */
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, &ks.round_keys[0]);
    
    /* XOR with IV for CBC mode */
    for (int i = 0; i < 16; i++) {
        plaintext[i] = state[i] ^ iv[i];
    }
    
    /* Clear sensitive data */
    secure_zero(&ks, sizeof(ks));
    secure_zero(state, sizeof(state));
    
    return true;
}

/* Generate random salt */
void generate_random_salt(uint8_t *salt) {
    for (int i = 0; i < ENCRYPTION_SALT_SIZE; i++) {
        salt[i] = random_ulong() & 0xff;
    }
}

/* Generate random IV */
void generate_random_iv(uint8_t *iv) {
    for (int i = 0; i < AES_IV_SIZE; i++) {
        iv[i] = random_ulong() & 0xff;
    }
}

/* Simple PBKDF2 implementation using hash_bytes */
bool pbkdf2_derive_key(const char *password, const uint8_t *salt, uint8_t *key) {
    if (!password || !salt || !key) {
        return false;
    }
    
    size_t password_len = strlen(password);
    if (password_len == 0 || password_len > MAX_PASSWORD_LENGTH) {
        return false;
    }
    
    /* Simple PBKDF2 implementation - concatenate password and salt, then hash iteratively */
    uint8_t buffer[MAX_PASSWORD_LENGTH + ENCRYPTION_SALT_SIZE];
    uint8_t derived[AES_KEY_SIZE];
    
    /* Initial concatenation */
    memcpy(buffer, password, password_len);
    memcpy(buffer + password_len, salt, ENCRYPTION_SALT_SIZE);
    
    /* Use hash_bytes as our PRF - iterate to strengthen the key */
    unsigned hash_result = hash_bytes(buffer, password_len + ENCRYPTION_SALT_SIZE);
    
    /* Convert hash result to key material and iterate */
    for (int iter = 0; iter < PBKDF2_ITERATIONS; iter++) {
        hash_result = hash_bytes(&hash_result, sizeof(hash_result));
    }
    
    /* Expand hash result to key size */
    for (int i = 0; i < AES_KEY_SIZE; i++) {
        derived[i] = (hash_result >> (8 * (i % 4))) & 0xff;
        if (i % 4 == 3) {
            hash_result = hash_bytes(&hash_result, sizeof(hash_result));
        }
    }
    
    memcpy(key, derived, AES_KEY_SIZE);
    
    /* Clear sensitive data */
    secure_zero(buffer, sizeof(buffer));
    secure_zero(derived, sizeof(derived));
    
    return true;
}

/* Calculate simple checksum for integrity verification */
uint32_t calculate_checksum(const void *data, size_t size) {
    const uint8_t *bytes = data;
    uint32_t checksum = 0;
    
    for (size_t i = 0; i < size; i++) {
        checksum = (checksum << 1) ^ bytes[i];
    }
    
    return checksum;
}

/* Secure memory clearing */
void secure_zero(void *ptr, size_t size) {
    volatile uint8_t *p = ptr;
    for (size_t i = 0; i < size; i++) {
        p[i] = 0;
    }
}

/* Encryption context management */
void encryption_context_init(struct encryption_context *ctx) {
    if (!ctx) return;
    
    memset(ctx, 0, sizeof(*ctx));
    ctx->key_valid = false;
}

bool encryption_context_set_password(struct encryption_context *ctx,
                                    const char *password,
                                    const struct encryption_metadata *metadata) {
    if (!ctx || !password || !metadata) {
        return false;
    }
    
    /* Derive key from password and salt */
    bool success = pbkdf2_derive_key(password, metadata->salt, ctx->key);
    ctx->key_valid = success;
    
    return success;
}

void encryption_context_clear(struct encryption_context *ctx) {
    if (!ctx) return;
    
    secure_zero(ctx, sizeof(*ctx));
    ctx->key_valid = false;
}

/* Encrypt a full sector */
bool encrypt_sector(const void *plaintext, void *ciphertext,
                   const struct encryption_context *ctx) {
    if (!plaintext || !ciphertext || !ctx || !ctx->key_valid) {
        return false;
    }
    
    const uint8_t *plain_data = plaintext;
    uint8_t *cipher_data = ciphertext;
    struct encryption_block_header *header = (struct encryption_block_header *)cipher_data;
    
    /* Generate random IV */
    generate_random_iv(header->iv);
    
    /* Calculate checksum of plaintext */
    header->checksum = calculate_checksum(plaintext, BLOCK_SECTOR_SIZE);
    
    /* Encrypt data in 16-byte blocks */
    size_t data_start = sizeof(struct encryption_block_header);
    size_t data_size = BLOCK_SECTOR_SIZE - data_start;
    uint8_t current_iv[AES_IV_SIZE];
    
    memcpy(current_iv, header->iv, AES_IV_SIZE);
    
    for (size_t offset = 0; offset < data_size; offset += AES_BLOCK_SIZE) {
        size_t block_size = (offset + AES_BLOCK_SIZE <= data_size) ? 
                           AES_BLOCK_SIZE : (data_size - offset);
        
        uint8_t block[AES_BLOCK_SIZE] = {0};
        memcpy(block, plain_data + offset, block_size);
        
        if (!aes_encrypt_block(block, cipher_data + data_start + offset, 
                              ctx->key, current_iv)) {
            return false;
        }
        
        /* Update IV for next block (CBC mode) */
        memcpy(current_iv, cipher_data + data_start + offset, AES_IV_SIZE);
    }
    
    return true;
}

/* Decrypt a full sector */
bool decrypt_sector(const void *ciphertext, void *plaintext,
                   const struct encryption_context *ctx) {
    if (!ciphertext || !plaintext || !ctx || !ctx->key_valid) {
        return false;
    }
    
    const uint8_t *cipher_data = ciphertext;
    uint8_t *plain_data = plaintext;
    const struct encryption_block_header *header = 
        (const struct encryption_block_header *)cipher_data;
    
    /* Decrypt data in 16-byte blocks */
    size_t data_start = sizeof(struct encryption_block_header);
    size_t data_size = BLOCK_SECTOR_SIZE - data_start;
    uint8_t current_iv[AES_IV_SIZE];
    uint8_t prev_cipher[AES_IV_SIZE];
    
    memcpy(current_iv, header->iv, AES_IV_SIZE);
    
    for (size_t offset = 0; offset < data_size; offset += AES_BLOCK_SIZE) {
        size_t block_size = (offset + AES_BLOCK_SIZE <= data_size) ? 
                           AES_BLOCK_SIZE : (data_size - offset);
        
        /* Save current ciphertext block for next IV */
        memcpy(prev_cipher, cipher_data + data_start + offset, AES_IV_SIZE);
        
        uint8_t block[AES_BLOCK_SIZE];
        if (!aes_decrypt_block(cipher_data + data_start + offset, block,
                              ctx->key, current_iv)) {
            return false;
        }
        
        memcpy(plain_data + offset, block, block_size);
        
        /* Update IV for next block */
        memcpy(current_iv, prev_cipher, AES_IV_SIZE);
    }
    
    /* Verify checksum */
    uint32_t calculated_checksum = calculate_checksum(plaintext, BLOCK_SECTOR_SIZE);
    if (calculated_checksum != header->checksum) {
        /* Checksum mismatch - possible corruption or wrong key */
        return false;
    }
    
    return true;
}