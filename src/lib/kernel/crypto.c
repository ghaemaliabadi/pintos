#include "lib/kernel/crypto.h"
#include "lib/string.h"
#include "lib/random.h"

/* SHA-256 constants */
static const uint32_t sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/* Helper macros for SHA-256 */
#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SIGMA0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define SIGMA1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define GAMMA0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define GAMMA1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

static uint32_t
bytes_to_uint32_be(const uint8_t *bytes)
{
    return ((uint32_t)bytes[0] << 24) |
           ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) |
           ((uint32_t)bytes[3]);
}

static void
uint32_to_bytes_be(uint32_t value, uint8_t *bytes)
{
    bytes[0] = (value >> 24) & 0xff;
    bytes[1] = (value >> 16) & 0xff;
    bytes[2] = (value >> 8) & 0xff;
    bytes[3] = value & 0xff;
}

void
sha256_init(struct sha256_ctx *ctx)
{
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
    ctx->count = 0;
    memset(ctx->buffer, 0, SHA256_BLOCK_SIZE);
}

static void
sha256_process_block(struct sha256_ctx *ctx, const uint8_t *block)
{
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t t1, t2;
    int i;

    /* Prepare message schedule */
    for (i = 0; i < 16; i++) {
        w[i] = bytes_to_uint32_be(block + i * 4);
    }
    
    for (i = 16; i < 64; i++) {
        w[i] = GAMMA1(w[i - 2]) + w[i - 7] + GAMMA0(w[i - 15]) + w[i - 16];
    }

    /* Initialize working variables */
    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    /* Main loop */
    for (i = 0; i < 64; i++) {
        t1 = h + SIGMA1(e) + CH(e, f, g) + sha256_k[i] + w[i];
        t2 = SIGMA0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    /* Add working variables to hash value */
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void
sha256_update(struct sha256_ctx *ctx, const uint8_t *data, size_t len)
{
    size_t buffer_pos = ctx->count % SHA256_BLOCK_SIZE;
    size_t remaining = SHA256_BLOCK_SIZE - buffer_pos;

    ctx->count += len;

    if (len >= remaining) {
        /* Fill buffer and process */
        memcpy(ctx->buffer + buffer_pos, data, remaining);
        sha256_process_block(ctx, ctx->buffer);
        data += remaining;
        len -= remaining;

        /* Process complete blocks */
        while (len >= SHA256_BLOCK_SIZE) {
            sha256_process_block(ctx, data);
            data += SHA256_BLOCK_SIZE;
            len -= SHA256_BLOCK_SIZE;
        }

        /* Copy remaining data to buffer */
        memcpy(ctx->buffer, data, len);
    } else {
        /* Just add to buffer */
        memcpy(ctx->buffer + buffer_pos, data, len);
    }
}

void
sha256_final(struct sha256_ctx *ctx, uint8_t digest[SHA256_DIGEST_SIZE])
{
    size_t buffer_pos = ctx->count % SHA256_BLOCK_SIZE;
    size_t padding_len;
    uint8_t padding[SHA256_BLOCK_SIZE * 2];
    uint64_t bit_count = ctx->count * 8;
    int i;

    /* Add padding */
    padding[0] = 0x80;
    if (buffer_pos < 56) {
        padding_len = 56 - buffer_pos;
    } else {
        padding_len = SHA256_BLOCK_SIZE + 56 - buffer_pos;
    }
    
    memset(padding + 1, 0, padding_len - 1);
    
    /* Add length in bits as big-endian 64-bit integer */
    for (i = 0; i < 8; i++) {
        padding[padding_len + i] = (bit_count >> (56 - i * 8)) & 0xff;
    }
    
    sha256_update(ctx, padding, padding_len + 8);

    /* Extract digest */
    for (i = 0; i < 8; i++) {
        uint32_to_bytes_be(ctx->state[i], digest + i * 4);
    }
}

void
hmac_sha256(const uint8_t *key, size_t key_len,
             const uint8_t *data, size_t data_len,
             uint8_t output[SHA256_DIGEST_SIZE])
{
    uint8_t key_pad[SHA256_BLOCK_SIZE];
    uint8_t inner_hash[SHA256_DIGEST_SIZE];
    struct sha256_ctx ctx;
    int i;

    /* Prepare key */
    memset(key_pad, 0, SHA256_BLOCK_SIZE);
    if (key_len > SHA256_BLOCK_SIZE) {
        sha256_init(&ctx);
        sha256_update(&ctx, key, key_len);
        sha256_final(&ctx, key_pad);
    } else {
        memcpy(key_pad, key, key_len);
    }

    /* Inner hash: H((K ⊕ ipad) || message) */
    for (i = 0; i < SHA256_BLOCK_SIZE; i++) {
        key_pad[i] ^= 0x36;
    }
    
    sha256_init(&ctx);
    sha256_update(&ctx, key_pad, SHA256_BLOCK_SIZE);
    sha256_update(&ctx, data, data_len);
    sha256_final(&ctx, inner_hash);

    /* Outer hash: H((K ⊕ opad) || inner_hash) */
    for (i = 0; i < SHA256_BLOCK_SIZE; i++) {
        key_pad[i] ^= 0x36 ^ 0x5c;
    }
    
    sha256_init(&ctx);
    sha256_update(&ctx, key_pad, SHA256_BLOCK_SIZE);
    sha256_update(&ctx, inner_hash, SHA256_DIGEST_SIZE);
    sha256_final(&ctx, output);

    /* Clear sensitive data */
    secure_zero(key_pad, SHA256_BLOCK_SIZE);
    secure_zero(inner_hash, SHA256_DIGEST_SIZE);
}

void
pbkdf2_hmac_sha256(const char *password, size_t password_len,
                   const uint8_t *salt, size_t salt_len,
                   uint32_t iterations,
                   uint8_t *output, size_t output_len)
{
    uint8_t u[SHA256_DIGEST_SIZE];
    uint8_t u_prev[SHA256_DIGEST_SIZE];
    uint8_t salt_block[salt_len + 4];
    uint32_t block_count = (output_len + SHA256_DIGEST_SIZE - 1) / SHA256_DIGEST_SIZE;
    uint32_t i, j, k;

    /* Copy salt and prepare for block counter */
    memcpy(salt_block, salt, salt_len);

    for (i = 1; i <= block_count; i++) {
        /* Append block counter in big-endian format */
        uint32_to_bytes_be(i, salt_block + salt_len);

        /* First iteration: U1 = HMAC(password, salt || block_counter) */
        hmac_sha256((const uint8_t *)password, password_len,
                    salt_block, salt_len + 4, u);
        memcpy(u_prev, u, SHA256_DIGEST_SIZE);

        /* Subsequent iterations: Ui = HMAC(password, Ui-1) */
        for (j = 1; j < iterations; j++) {
            hmac_sha256((const uint8_t *)password, password_len,
                        u_prev, SHA256_DIGEST_SIZE, u_prev);
            
            /* XOR with previous result */
            for (k = 0; k < SHA256_DIGEST_SIZE; k++) {
                u[k] ^= u_prev[k];
            }
        }

        /* Copy result to output buffer */
        size_t copy_len = (i == block_count) ? 
                         (output_len - (i - 1) * SHA256_DIGEST_SIZE) : 
                         SHA256_DIGEST_SIZE;
        memcpy(output + (i - 1) * SHA256_DIGEST_SIZE, u, copy_len);
    }

    /* Clear sensitive data */
    secure_zero(u, SHA256_DIGEST_SIZE);
    secure_zero(u_prev, SHA256_DIGEST_SIZE);
}

void
crypto_random_bytes(uint8_t *buffer, size_t size)
{
    size_t i;
    for (i = 0; i < size; i++) {
        buffer[i] = random_ulong() & 0xff;
    }
}

void
secure_zero(void *ptr, size_t size)
{
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    size_t i;
    for (i = 0; i < size; i++) {
        p[i] = 0;
    }
}