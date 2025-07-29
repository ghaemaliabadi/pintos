#include "filesys/encryption.h"
#include "filesys/inode.h"
#include "lib/kernel/crypto.h"
#include "lib/string.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "devices/timer.h"

/* AES S-box */
static const uint8_t aes_sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

/* AES inverse S-box */
static const uint8_t aes_inv_sbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

/* Global key cache */
struct key_cache_entry key_cache[KEY_CACHE_SIZE];
static struct lock key_cache_lock;

/* Helper functions */
static uint32_t bytes_to_word(const uint8_t *bytes)
{
    return ((uint32_t)bytes[0] << 24) |
           ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) |
           ((uint32_t)bytes[3]);
}

static void word_to_bytes(uint32_t word, uint8_t *bytes)
{
    bytes[0] = (word >> 24) & 0xff;
    bytes[1] = (word >> 16) & 0xff;
    bytes[2] = (word >> 8) & 0xff;
    bytes[3] = word & 0xff;
}

static uint32_t sub_word(uint32_t word)
{
    uint8_t bytes[4];
    word_to_bytes(word, bytes);
    bytes[0] = aes_sbox[bytes[0]];
    bytes[1] = aes_sbox[bytes[1]];
    bytes[2] = aes_sbox[bytes[2]];
    bytes[3] = aes_sbox[bytes[3]];
    return bytes_to_word(bytes);
}

static uint32_t rot_word(uint32_t word)
{
    return (word << 8) | (word >> 24);
}

void
aes_init(void)
{
    lock_init(&key_cache_lock);
    cache_clear_all();
}

void
aes_set_key(struct aes_ctx *ctx, const uint8_t key[AES_KEY_SIZE])
{
    static const uint32_t rcon[] = {
        0x01000000, 0x02000000, 0x04000000, 0x08000000,
        0x10000000, 0x20000000, 0x40000000, 0x80000000,
        0x1b000000, 0x36000000
    };
    
    int i;
    
    /* Copy initial key */
    for (i = 0; i < 4; i++) {
        ctx->round_keys[i] = bytes_to_word(key + i * 4);
    }
    
    /* Generate round keys */
    for (i = 4; i < 44; i++) {
        uint32_t temp = ctx->round_keys[i - 1];
        
        if (i % 4 == 0) {
            temp = sub_word(rot_word(temp)) ^ rcon[i / 4 - 1];
        }
        
        ctx->round_keys[i] = ctx->round_keys[i - 4] ^ temp;
    }
}

static void
sub_bytes(uint8_t state[16])
{
    int i;
    for (i = 0; i < 16; i++) {
        state[i] = aes_sbox[state[i]];
    }
}

static void
inv_sub_bytes(uint8_t state[16])
{
    int i;
    for (i = 0; i < 16; i++) {
        state[i] = aes_inv_sbox[state[i]];
    }
}

static void
shift_rows(uint8_t state[16])
{
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

static void
inv_shift_rows(uint8_t state[16])
{
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

static uint8_t
gf_mult(uint8_t a, uint8_t b)
{
    uint8_t result = 0;
    uint8_t hi_bit_set;
    int i;
    
    for (i = 0; i < 8; i++) {
        if (b & 1) {
            result ^= a;
        }
        hi_bit_set = a & 0x80;
        a <<= 1;
        if (hi_bit_set) {
            a ^= 0x1b; /* x^8 + x^4 + x^3 + x + 1 */
        }
        b >>= 1;
    }
    
    return result;
}

static void
mix_columns(uint8_t state[16])
{
    uint8_t temp[4];
    int i;
    
    for (i = 0; i < 4; i++) {
        temp[0] = gf_mult(0x02, state[i * 4]) ^ gf_mult(0x03, state[i * 4 + 1]) ^
                  state[i * 4 + 2] ^ state[i * 4 + 3];
        temp[1] = state[i * 4] ^ gf_mult(0x02, state[i * 4 + 1]) ^
                  gf_mult(0x03, state[i * 4 + 2]) ^ state[i * 4 + 3];
        temp[2] = state[i * 4] ^ state[i * 4 + 1] ^
                  gf_mult(0x02, state[i * 4 + 2]) ^ gf_mult(0x03, state[i * 4 + 3]);
        temp[3] = gf_mult(0x03, state[i * 4]) ^ state[i * 4 + 1] ^
                  state[i * 4 + 2] ^ gf_mult(0x02, state[i * 4 + 3]);
        
        memcpy(state + i * 4, temp, 4);
    }
}

static void
inv_mix_columns(uint8_t state[16])
{
    uint8_t temp[4];
    int i;
    
    for (i = 0; i < 4; i++) {
        temp[0] = gf_mult(0x0e, state[i * 4]) ^ gf_mult(0x0b, state[i * 4 + 1]) ^
                  gf_mult(0x0d, state[i * 4 + 2]) ^ gf_mult(0x09, state[i * 4 + 3]);
        temp[1] = gf_mult(0x09, state[i * 4]) ^ gf_mult(0x0e, state[i * 4 + 1]) ^
                  gf_mult(0x0b, state[i * 4 + 2]) ^ gf_mult(0x0d, state[i * 4 + 3]);
        temp[2] = gf_mult(0x0d, state[i * 4]) ^ gf_mult(0x09, state[i * 4 + 1]) ^
                  gf_mult(0x0e, state[i * 4 + 2]) ^ gf_mult(0x0b, state[i * 4 + 3]);
        temp[3] = gf_mult(0x0b, state[i * 4]) ^ gf_mult(0x0d, state[i * 4 + 1]) ^
                  gf_mult(0x09, state[i * 4 + 2]) ^ gf_mult(0x0e, state[i * 4 + 3]);
        
        memcpy(state + i * 4, temp, 4);
    }
}

static void
add_round_key(uint8_t state[16], const uint32_t *round_key)
{
    int i;
    for (i = 0; i < 4; i++) {
        uint8_t key_bytes[4];
        word_to_bytes(round_key[i], key_bytes);
        state[i * 4] ^= key_bytes[0];
        state[i * 4 + 1] ^= key_bytes[1];
        state[i * 4 + 2] ^= key_bytes[2];
        state[i * 4 + 3] ^= key_bytes[3];
    }
}

void
aes_encrypt_block(const struct aes_ctx *ctx,
                  const uint8_t input[AES_BLOCK_SIZE],
                  uint8_t output[AES_BLOCK_SIZE])
{
    uint8_t state[16];
    int round;
    
    /* Copy input to state */
    memcpy(state, input, 16);
    
    /* Initial round */
    add_round_key(state, ctx->round_keys);
    
    /* Main rounds */
    for (round = 1; round < 10; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, ctx->round_keys + round * 4);
    }
    
    /* Final round */
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, ctx->round_keys + 40);
    
    /* Copy state to output */
    memcpy(output, state, 16);
}

void
aes_decrypt_block(const struct aes_ctx *ctx,
                  const uint8_t input[AES_BLOCK_SIZE],
                  uint8_t output[AES_BLOCK_SIZE])
{
    uint8_t state[16];
    int round;
    
    /* Copy input to state */
    memcpy(state, input, 16);
    
    /* Initial round */
    add_round_key(state, ctx->round_keys + 40);
    inv_shift_rows(state);
    inv_sub_bytes(state);
    
    /* Main rounds */
    for (round = 9; round >= 1; round--) {
        add_round_key(state, ctx->round_keys + round * 4);
        inv_mix_columns(state);
        inv_shift_rows(state);
        inv_sub_bytes(state);
    }
    
    /* Final round */
    add_round_key(state, ctx->round_keys);
    
    /* Copy state to output */
    memcpy(output, state, 16);
}

void
aes_cbc_encrypt(const struct aes_ctx *ctx,
                const uint8_t *input, uint8_t *output, size_t length,
                const uint8_t iv[AES_IV_SIZE])
{
    uint8_t prev_block[AES_BLOCK_SIZE];
    uint8_t temp_block[AES_BLOCK_SIZE];
    size_t i, j;
    
    memcpy(prev_block, iv, AES_IV_SIZE);
    
    for (i = 0; i < length; i += AES_BLOCK_SIZE) {
        /* XOR with previous ciphertext block */
        for (j = 0; j < AES_BLOCK_SIZE; j++) {
            temp_block[j] = input[i + j] ^ prev_block[j];
        }
        
        /* Encrypt */
        aes_encrypt_block(ctx, temp_block, output + i);
        
        /* Update previous block */
        memcpy(prev_block, output + i, AES_BLOCK_SIZE);
    }
}

void
aes_cbc_decrypt(const struct aes_ctx *ctx,
                const uint8_t *input, uint8_t *output, size_t length,
                const uint8_t iv[AES_IV_SIZE])
{
    uint8_t prev_block[AES_BLOCK_SIZE];
    uint8_t temp_block[AES_BLOCK_SIZE];
    size_t i, j;
    
    memcpy(prev_block, iv, AES_IV_SIZE);
    
    for (i = 0; i < length; i += AES_BLOCK_SIZE) {
        /* Decrypt */
        aes_decrypt_block(ctx, input + i, temp_block);
        
        /* XOR with previous ciphertext block */
        for (j = 0; j < AES_BLOCK_SIZE; j++) {
            output[i + j] = temp_block[j] ^ prev_block[j];
        }
        
        /* Update previous block */
        memcpy(prev_block, input + i, AES_BLOCK_SIZE);
    }
}

void
derive_key_from_password(const char *password,
                         const uint8_t salt[ENCRYPTION_SALT_SIZE],
                         uint32_t iterations,
                         uint8_t key[AES_KEY_SIZE])
{
    pbkdf2_hmac_sha256(password, strlen(password),
                       salt, ENCRYPTION_SALT_SIZE,
                       iterations, key, AES_KEY_SIZE);
}

/* Key cache management */
bool
cache_get_key(uint32_t inode_number, uint8_t key[AES_KEY_SIZE])
{
    int i;
    bool found = false;
    
    lock_acquire(&key_cache_lock);
    
    for (i = 0; i < KEY_CACHE_SIZE; i++) {
        if (key_cache[i].inode_number == inode_number) {
            memcpy(key, key_cache[i].key, AES_KEY_SIZE);
            key_cache[i].last_access = timer_ticks();
            found = true;
            break;
        }
    }
    
    lock_release(&key_cache_lock);
    return found;
}

void
cache_store_key(uint32_t inode_number, const uint8_t key[AES_KEY_SIZE])
{
    int i;
    int oldest_idx = 0;
    uint32_t oldest_access = key_cache[0].last_access;
    
    lock_acquire(&key_cache_lock);
    
    /* Look for existing entry or empty slot */
    for (i = 0; i < KEY_CACHE_SIZE; i++) {
        if (key_cache[i].inode_number == 0 || 
            key_cache[i].inode_number == inode_number) {
            key_cache[i].inode_number = inode_number;
            memcpy(key_cache[i].key, key, AES_KEY_SIZE);
            key_cache[i].last_access = timer_ticks();
            lock_release(&key_cache_lock);
            return;
        }
        
        if (key_cache[i].last_access < oldest_access) {
            oldest_access = key_cache[i].last_access;
            oldest_idx = i;
        }
    }
    
    /* Replace oldest entry */
    key_cache[oldest_idx].inode_number = inode_number;
    memcpy(key_cache[oldest_idx].key, key, AES_KEY_SIZE);
    key_cache[oldest_idx].last_access = timer_ticks();
    
    lock_release(&key_cache_lock);
}

void
cache_invalidate_key(uint32_t inode_number)
{
    int i;
    
    lock_acquire(&key_cache_lock);
    
    for (i = 0; i < KEY_CACHE_SIZE; i++) {
        if (key_cache[i].inode_number == inode_number) {
            secure_zero(key_cache[i].key, AES_KEY_SIZE);
            key_cache[i].inode_number = 0;
            key_cache[i].last_access = 0;
            break;
        }
    }
    
    lock_release(&key_cache_lock);
}

void
cache_clear_all(void)
{
    lock_acquire(&key_cache_lock);
    secure_zero(key_cache, sizeof(key_cache));
    lock_release(&key_cache_lock);
}

void
encrypt_block(const uint8_t *input, uint8_t *output,
              const struct encryption_meta *meta,
              const uint8_t key[AES_KEY_SIZE],
              uint32_t block_index)
{
    struct aes_ctx ctx;
    uint8_t iv_copy[AES_IV_SIZE];
    uint8_t padded_input[BLOCK_SECTOR_SIZE];
    
    /* Set up AES context */
    aes_set_key(&ctx, key);
    
    /* Create unique IV for this block by XORing with block index */
    memcpy(iv_copy, meta->iv, AES_IV_SIZE);
    iv_copy[12] ^= (block_index >> 24) & 0xff;
    iv_copy[13] ^= (block_index >> 16) & 0xff;
    iv_copy[14] ^= (block_index >> 8) & 0xff;
    iv_copy[15] ^= block_index & 0xff;
    
    /* Add PKCS#7 padding if necessary */
    memcpy(padded_input, input, BLOCK_SECTOR_SIZE);
    
    /* Encrypt using AES-CBC */
    aes_cbc_encrypt(&ctx, padded_input, output, BLOCK_SECTOR_SIZE, iv_copy);
    
    secure_zero(&ctx, sizeof(ctx));
    secure_zero(iv_copy, AES_IV_SIZE);
}

void
decrypt_block(const uint8_t *input, uint8_t *output,
              const struct encryption_meta *meta,
              const uint8_t key[AES_KEY_SIZE],
              uint32_t block_index)
{
    struct aes_ctx ctx;
    uint8_t iv_copy[AES_IV_SIZE];
    
    /* Set up AES context */
    aes_set_key(&ctx, key);
    
    /* Create unique IV for this block */
    memcpy(iv_copy, meta->iv, AES_IV_SIZE);
    iv_copy[12] ^= (block_index >> 24) & 0xff;
    iv_copy[13] ^= (block_index >> 16) & 0xff;
    iv_copy[14] ^= (block_index >> 8) & 0xff;
    iv_copy[15] ^= block_index & 0xff;
    
    /* Decrypt using AES-CBC */
    aes_cbc_decrypt(&ctx, input, output, BLOCK_SECTOR_SIZE, iv_copy);
    
    secure_zero(&ctx, sizeof(ctx));
    secure_zero(iv_copy, AES_IV_SIZE);
}