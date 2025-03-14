#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include <time.h>
#include <math.h>
#include "stego.h"
#include "image.h"
#include "png.h"

#define DELIMITER "#END#"
#define DELIMITER_LEN 5
#define SALT "emojify"
#define SALT_LEN 7
#define KEY_ITERATIONS 100000
#define CHACHA_KEY_SIZE 32
#define CHACHA_NONCE_SIZE 12
#define POLY1305_KEY_SIZE 32
#define POLY1305_TAG_SIZE 16
#define FERNET_PREFIX "FERNET:"
#define FERNET_PREFIX_LEN 7
#define MIN(a,b) ((a) < (b) ? (a) : (b))

// ChaCha20 quarter round operation
#define QUARTERROUND(a, b, c, d) \
    a += b; d ^= a; d = (d << 16) | (d >> 16); \
    c += d; b ^= c; b = (b << 12) | (b >> 20); \
    a += b; d ^= a; d = (d << 8) | (d >> 24); \
    c += d; b ^= c; b = (b << 7) | (b >> 25)

static void chacha20_block(uint32_t state[16], unsigned char block[64]) {
    uint32_t x[16];
    memcpy(x, state, sizeof(x));

    for (int i = 0; i < 10; i++) {
        // Column rounds
        QUARTERROUND(x[0], x[4], x[8], x[12]);
        QUARTERROUND(x[1], x[5], x[9], x[13]);
        QUARTERROUND(x[2], x[6], x[10], x[14]);
        QUARTERROUND(x[3], x[7], x[11], x[15]);
        // Diagonal rounds
        QUARTERROUND(x[0], x[5], x[10], x[15]);
        QUARTERROUND(x[1], x[6], x[11], x[12]);
        QUARTERROUND(x[2], x[7], x[8], x[13]);
        QUARTERROUND(x[3], x[4], x[9], x[14]);
    }

    for (int i = 0; i < 16; i++) {
        x[i] += state[i];
        block[4*i+0] = x[i];
        block[4*i+1] = x[i] >> 8;
        block[4*i+2] = x[i] >> 16;
        block[4*i+3] = x[i] >> 24;
    }
}

// Poly1305 implementation
typedef struct {
    uint32_t r[5];     // Key part r
    uint32_t h[5];     // Accumulator
    uint32_t pad[4];   // Key part s
    size_t leftover;
    unsigned char buffer[16];
    unsigned char final;
} poly1305_state;

static void poly1305_init(poly1305_state *state, const unsigned char key[32]) {
    // Clamp r
    state->r[0] = (*(uint32_t*)(key +  0) & 0x0fffffff) & 0x0fffffff;
    state->r[1] = (*(uint32_t*)(key +  3) >> 2) & 0x0ffffffc;
    state->r[2] = (*(uint32_t*)(key +  6) >> 4) & 0x0ffffffc;
    state->r[3] = (*(uint32_t*)(key +  9) >> 6) & 0x0ffffffc;
    state->r[4] = (*(uint32_t*)(key + 12) >> 8) & 0x0ffffffc;

    // Save pad (s)
    state->pad[0] = *(uint32_t*)(key + 16);
    state->pad[1] = *(uint32_t*)(key + 20);
    state->pad[2] = *(uint32_t*)(key + 24);
    state->pad[3] = *(uint32_t*)(key + 28);

    // Reset accumulator
    memset(state->h, 0, sizeof(state->h));
    state->leftover = 0;
    state->final = 0;
}

static void poly1305_blocks(poly1305_state *state, const unsigned char *in, size_t len, int final) {
    const uint32_t hibit = final ? 0 : (1UL << 24);
    uint64_t h0, h1, h2, h3, h4;
    uint64_t s1, s2, s3, s4;
    uint64_t r0, r1, r2, r3, r4;
    uint64_t d0, d1, d2, d3, d4;
    uint32_t c;

    r0 = state->r[0];
    r1 = state->r[1];
    r2 = state->r[2];
    r3 = state->r[3];
    r4 = state->r[4];

    s1 = r1 * 5;
    s2 = r2 * 5;
    s3 = r3 * 5;
    s4 = r4 * 5;

    h0 = state->h[0];
    h1 = state->h[1];
    h2 = state->h[2];
    h3 = state->h[3];
    h4 = state->h[4];

    while (len >= 16) {
        // h += msg
        h0 += (*(uint32_t*)(in + 0)) & 0x3ffffff;
        h1 += (*(uint32_t*)(in + 3) >> 2) & 0x3ffffff;
        h2 += (*(uint32_t*)(in + 6) >> 4) & 0x3ffffff;
        h3 += (*(uint32_t*)(in + 9) >> 6) & 0x3ffffff;
        h4 += (*(uint32_t*)(in + 12) >> 8) | hibit;

        // h *= r
        d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
        d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
        d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
        d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
        d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

        // (partial) h %= p
        c = (uint32_t)(d0 >> 26); h0 = d0 & 0x3ffffff;
        d1 += c;     c = (uint32_t)(d1 >> 26); h1 = d1 & 0x3ffffff;
        d2 += c;     c = (uint32_t)(d2 >> 26); h2 = d2 & 0x3ffffff;
        d3 += c;     c = (uint32_t)(d3 >> 26); h3 = d3 & 0x3ffffff;
        d4 += c;     c = (uint32_t)(d4 >> 26); h4 = d4 & 0x3ffffff;
        h0 += c * 5; c = h0 >> 26; h0 = h0 & 0x3ffffff;
        h1 += c;

        in += 16;
        len -= 16;
    }

    state->h[0] = h0;
    state->h[1] = h1;
    state->h[2] = h2;
    state->h[3] = h3;
    state->h[4] = h4;
}

static void poly1305_finish(poly1305_state *state, unsigned char mac[16]) {
    uint32_t h0, h1, h2, h3, h4, c;
    uint32_t g0, g1, g2, g3, g4;
    uint64_t f;
    uint32_t mask;

    // Process any partial block
    if (state->leftover) {
        size_t i = state->leftover;
        state->buffer[i++] = 1;
        for (; i < 16; i++)
            state->buffer[i] = 0;
        state->final = 1;
        poly1305_blocks(state, state->buffer, 16, 1);
    }

    // Fully reduce h
    h0 = state->h[0];
    h1 = state->h[1];
    h2 = state->h[2];
    h3 = state->h[3];
    h4 = state->h[4];

    c = h1 >> 26; h1 = h1 & 0x3ffffff;
    h2 += c; c = h2 >> 26; h2 = h2 & 0x3ffffff;
    h3 += c; c = h3 >> 26; h3 = h3 & 0x3ffffff;
    h4 += c; c = h4 >> 26; h4 = h4 & 0x3ffffff;
    h0 += c * 5; c = h0 >> 26; h0 = h0 & 0x3ffffff;
    h1 += c;

    // Compute h + -p
    g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    g4 = h4 + c - (1UL << 26);

    // Select h if h < p, or h + -p if h >= p
    mask = (g4 >> 31) - 1;
    g0 &= mask;
    g1 &= mask;
    g2 &= mask;
    g3 &= mask;
    g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    // h = h % (2^128)
    h0 = ((h0) | (h1 << 26)) & 0xffffffff;
    h1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffff;
    h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
    h3 = ((h3 >> 18) | (h4 << 8)) & 0xffffffff;

    // mac = (h + pad) % (2^128)
    f = (uint64_t)h0 + state->pad[0];
    mac[0] = f;
    mac[1] = f >> 8;
    mac[2] = f >> 16;
    mac[3] = f >> 24;
    f = (uint64_t)h1 + state->pad[1];
    mac[4] = f;
    mac[5] = f >> 8;
    mac[6] = f >> 16;
    mac[7] = f >> 24;
    f = (uint64_t)h2 + state->pad[2];
    mac[8] = f;
    mac[9] = f >> 8;
    mac[10] = f >> 16;
    mac[11] = f >> 24;
    f = (uint64_t)h3 + state->pad[3];
    mac[12] = f;
    mac[13] = f >> 8;
    mac[14] = f >> 16;
    mac[15] = f >> 24;
}

static void derive_key(const char* password, unsigned char* key) {
    if (!password) {
        memset(key, 0, CHACHA_KEY_SIZE);
        return;
    }
    
    // Simple key derivation using password and salt
    memset(key, 0, CHACHA_KEY_SIZE);
    size_t pass_len = strlen(password);
    
    for (int i = 0; i < KEY_ITERATIONS; i++) {
        for (size_t j = 0; j < pass_len; j++) {
            key[j % CHACHA_KEY_SIZE] ^= password[j] + i + key[(j+1) % CHACHA_KEY_SIZE];
        }
        for (size_t j = 0; j < SALT_LEN; j++) {
            key[j % CHACHA_KEY_SIZE] ^= SALT[j] + i + key[(j+1) % CHACHA_KEY_SIZE];
        }
    }
}

static bool encrypt_data(const unsigned char* in, size_t in_len,
                        unsigned char** out, size_t* out_len,
                        const unsigned char* key) {
    // Generate nonce
    unsigned char nonce[CHACHA_NONCE_SIZE];
    srand(time(NULL));
    for (int i = 0; i < CHACHA_NONCE_SIZE; i++) {
        nonce[i] = rand() & 0xFF;
    }
    
    *out_len = FERNET_PREFIX_LEN + CHACHA_NONCE_SIZE + in_len + POLY1305_TAG_SIZE;
    *out = malloc(*out_len);
    if (!*out) return false;
    
    // Add Fernet prefix and nonce
    memcpy(*out, FERNET_PREFIX, FERNET_PREFIX_LEN);
    memcpy(*out + FERNET_PREFIX_LEN, nonce, CHACHA_NONCE_SIZE);
    
    // Setup ChaCha20 state for encryption
    uint32_t state[16] = {
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574  // "expand 32-byte k"
    };
    memcpy(state + 4, key, CHACHA_KEY_SIZE);
    memcpy(state + 13, nonce, CHACHA_NONCE_SIZE);
    
    // Generate Poly1305 key
    unsigned char poly_key[POLY1305_KEY_SIZE];
    state[12] = 0;  // Counter = 0 for Poly1305 key
    chacha20_block(state, poly_key);
    
    // Encrypt data
    unsigned char* cipher = *out + FERNET_PREFIX_LEN + CHACHA_NONCE_SIZE;
    unsigned char block[64];
    size_t counter = 1;
    
    for (size_t i = 0; i < in_len; i += 64) {
        state[12] = counter++;
        chacha20_block(state, block);
        
        size_t chunk = (in_len - i < 64) ? in_len - i : 64;
        for (size_t j = 0; j < chunk; j++) {
            cipher[i + j] = in[i + j] ^ block[j];
        }
    }
    
    // Calculate Poly1305 MAC
    poly1305_state poly_state;
    poly1305_init(&poly_state, poly_key);
    
    // Include associated data (Fernet prefix)
    poly1305_blocks(&poly_state, *out, FERNET_PREFIX_LEN, 0);
    
    // Include nonce
    poly1305_blocks(&poly_state, nonce, CHACHA_NONCE_SIZE, 0);
    
    // Include ciphertext
    poly1305_blocks(&poly_state, cipher, in_len, 1);
    
    // Finalize and get tag
    poly1305_finish(&poly_state, cipher + in_len);
    
    return true;
}

static bool decrypt_data(const unsigned char* in, size_t in_len,
                        unsigned char** out, size_t* out_len,
                        const unsigned char* key) {
    if (in_len < FERNET_PREFIX_LEN + CHACHA_NONCE_SIZE + POLY1305_TAG_SIZE ||
        memcmp(in, FERNET_PREFIX, FERNET_PREFIX_LEN) != 0) {
        return false;
    }
    
    const unsigned char* nonce = in + FERNET_PREFIX_LEN;
    const unsigned char* cipher = nonce + CHACHA_NONCE_SIZE;
    size_t cipher_len = in_len - FERNET_PREFIX_LEN - CHACHA_NONCE_SIZE - POLY1305_TAG_SIZE;
    const unsigned char* tag = in + in_len - POLY1305_TAG_SIZE;
    
    // Setup ChaCha20 state
    uint32_t state[16] = {
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
    };
    memcpy(state + 4, key, CHACHA_KEY_SIZE);
    memcpy(state + 13, nonce, CHACHA_NONCE_SIZE);
    
    // Generate Poly1305 key
    unsigned char poly_key[POLY1305_KEY_SIZE];
    state[12] = 0;
    chacha20_block(state, poly_key);
    
    // Verify Poly1305 MAC
    poly1305_state poly_state;
    poly1305_init(&poly_state, poly_key);
    
    // Include associated data (Fernet prefix)
    poly1305_blocks(&poly_state, in, FERNET_PREFIX_LEN, 0);
    
    // Include nonce
    poly1305_blocks(&poly_state, nonce, CHACHA_NONCE_SIZE, 0);
    
    // Include ciphertext
    poly1305_blocks(&poly_state, cipher, cipher_len, 1);
    
    // Calculate and verify tag
    unsigned char computed_tag[POLY1305_TAG_SIZE];
    poly1305_finish(&poly_state, computed_tag);
    
    if (memcmp(computed_tag, tag, POLY1305_TAG_SIZE) != 0) {
        return false;
    }
    
    // Decrypt data
    *out_len = cipher_len;
    *out = malloc(cipher_len);
    if (!*out) return false;
    
    size_t counter = 1;
    unsigned char block[64];
    
    for (size_t i = 0; i < cipher_len; i += 64) {
        state[12] = counter++;
        chacha20_block(state, block);
        
        size_t chunk = (cipher_len - i < 64) ? cipher_len - i : 64;
        for (size_t j = 0; j < chunk; j++) {
            (*out)[i + j] = cipher[i + j] ^ block[j];
        }
    }
    
    return true;
}

static void embed_byte(unsigned char* pixels, uint8_t byte) {
    // Use 2 LSBs from each channel, need only 2 pixels for 8 bits
    // First pixel: 6 bits
    pixels[0] = (pixels[0] & 0xFC) | ((byte >> 6) & 0x03);  // bits 7,6
    pixels[1] = (pixels[1] & 0xFC) | ((byte >> 4) & 0x03);  // bits 5,4
    pixels[2] = (pixels[2] & 0xFC) | ((byte >> 2) & 0x03);  // bits 3,2
    
    // Second pixel: 2 bits (first channel only)
    pixels[3] = (pixels[3] & 0xFC) | (byte & 0x03);         // bits 1,0
}

static uint8_t extract_byte(const unsigned char* pixels) {
    uint8_t byte = 0;
    // Extract 2 LSBs from each channel
    byte |= (pixels[0] & 0x03) << 6;  // bits 7,6
    byte |= (pixels[1] & 0x03) << 4;  // bits 5,4
    byte |= (pixels[2] & 0x03) << 2;  // bits 3,2
    byte |= (pixels[3] & 0x03);       // bits 1,0
    return byte;
}

// Embed data in LSBs
static bool embed_data(Image* img, const unsigned char* data, size_t data_len) {
    // Check if image has enough space (2 pixels per byte)
    size_t max_bytes = ((size_t)img->width * img->height * 3) / 4;
    if (data_len + 4 > max_bytes) {
        return false;
    }

    // Write length (4 bytes)
    for (size_t i = 0; i < 4; i++) {
        embed_byte(&img->data[i * 4], (data_len >> (i * 8)) & 0xFF);
    }
    
    // Write data
    size_t pixel_idx = 16; // 4 bytes * 4 pixels per byte
    for (size_t i = 0; i < data_len; i++) {
        embed_byte(&img->data[pixel_idx], data[i]);
        pixel_idx += 4;
    }
    
    return true;
}

// Extract data from LSBs
static bool extract_data(const Image* img, unsigned char** out_data, size_t* out_len) {
    // Read length (4 bytes)
    size_t data_len = 0;
    for (size_t i = 0; i < 4; i++) {
        data_len |= (size_t)extract_byte(&img->data[i * 4]) << (i * 8);
    }
    
    // Validate length
    size_t max_bytes = ((size_t)img->width * img->height * 3) / 4;
    if (data_len > max_bytes - 4) {
        return false;
    }
    
    // Extract data
    *out_data = malloc(data_len);
    if (!*out_data) return false;
    *out_len = data_len;
    
    size_t pixel_idx = 16; // 4 bytes * 4 pixels per byte
    for (size_t i = 0; i < data_len; i++) {
        (*out_data)[i] = extract_byte(&img->data[pixel_idx]);
        pixel_idx += 4;
    }
    
    return true;
}

bool hide(const char* input_file, const char* output_file, const char* password) {
    // Read input file
    FILE* f = fopen(input_file, "rb");
    if (!f) {
        printf("Failed to open input file\n");
        return false;
    }
    
    fseek(f, 0, SEEK_END);
    size_t data_len = ftell(f);
    fseek(f, 0, SEEK_SET);
    printf("Input size: %zu bytes\n", data_len);
    
    unsigned char* data = malloc(data_len);
    if (!data) {
        printf("Failed to allocate input buffer\n");
        fclose(f);
        return false;
    }
    
    if (fread(data, 1, data_len, f) != data_len) {
        printf("Failed to read input file\n");
        free(data);
        fclose(f);
        return false;
    }
    fclose(f);
    
    // Compress data
    uLong comp_bound = compressBound(data_len);
    unsigned char* comp_data = malloc(comp_bound);
    if (!comp_data) {
        printf("Failed to allocate compression buffer\n");
        free(data);
        return false;
    }
    
    uLong comp_len = comp_bound;
    if (compress2(comp_data, &comp_len, data, data_len, Z_BEST_COMPRESSION) != Z_OK) {
        printf("Compression failed\n");
        free(comp_data);
        free(data);
        return false;
    }
    printf("Compressed size: %lu bytes\n", comp_len);
    free(data);
    
    // Encrypt compressed data if password provided
    unsigned char* final_data;
    size_t final_len;
    
    if (password) {
        printf("Encrypting with password\n");
        unsigned char key[CHACHA_KEY_SIZE];
        derive_key(password, key);
        
        if (!encrypt_data(comp_data, comp_len, &final_data, &final_len, key)) {
            printf("Encryption failed\n");
            free(comp_data);
            return false;
        }
        printf("Encrypted size: %zu bytes\n", final_len);
        free(comp_data);
    } else {
        final_data = comp_data;
        final_len = comp_len;
    }
    
    // Calculate required image size (2 pixels per byte)
    size_t total_bytes = final_len + 4;  // Data + length
    size_t required_pixels = (total_bytes * 4 + 2) / 3;  // 4 pixels per byte
    int width = ceil(sqrt(required_pixels));
    int height = (required_pixels + width - 1) / width;
    printf("Creating %dx%d image\n", width, height);
    
    // Try to load existing image or create new one
    Image* img = NULL;
    if (access(output_file, F_OK) == 0) {
        img = image_load(output_file);
        if (img) {
            printf("Loaded existing image %dx%d\n", img->width, img->height);
            // Check if image is big enough
            if ((size_t)img->width * img->height * 3 < required_pixels * 3) {
                printf("Existing image too small, creating new one\n");
                image_free(img);
                img = NULL;
            }
        }
    }
    
    if (!img) {
        img = image_create(width, height);
        if (!img) {
            printf("Failed to create image\n");
            free(final_data);
            return false;
        }
        printf("Created new image\n");
        
        // Fill with pattern
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                int idx = (y * width + x) * 3;
                img->data[idx] = (x + y) & 0xFC;     // R
                img->data[idx+1] = (x * y) & 0xFC;   // G
                img->data[idx+2] = (x - y) & 0xFC;   // B
            }
        }
    }
    
    // Embed data
    bool success = embed_data(img, final_data, final_len);
    free(final_data);
    
    if (!success) {
        printf("Failed to embed data\n");
        image_free(img);
        return false;
    }
    printf("Data embedded successfully\n");
    
    // Save PNG
    success = image_save(img, output_file);
    if (!success) printf("Failed to save image\n");
    image_free(img);
    return success;
}

bool extract(const char* image_file, const char* output_file, const char* password) {
    // Load PNG
    Image* img = image_load(image_file);
    if (!img) return false;
    
    // Extract data
    unsigned char* comp_data;
    size_t comp_len;
    if (!extract_data(img, &comp_data, &comp_len)) {
        image_free(img);
        return false;
    }
    image_free(img);
    
    // Check if data is encrypted (has Fernet prefix)
    bool is_encrypted = (comp_len >= FERNET_PREFIX_LEN && 
                        memcmp(comp_data, FERNET_PREFIX, FERNET_PREFIX_LEN) == 0);
    
    // Fail if data is encrypted but no password provided
    if (is_encrypted && !password) {
        free(comp_data);
        return false;
    }
    
    // Decrypt if password provided
    unsigned char* dec_data = NULL;
    size_t dec_len;
    
    if (password) {
        unsigned char key[CHACHA_KEY_SIZE];
        derive_key(password, key);
        
        if (!decrypt_data(comp_data, comp_len, &dec_data, &dec_len, key)) {
            free(comp_data);
            return false;
        }
        free(comp_data);
        comp_data = dec_data;
        comp_len = dec_len;
    }
    
    // Decompress data
    uLong uncomp_bound = comp_len * 10;  // Conservative initial size
    unsigned char* uncomp_data = NULL;
    int ret;
    
    do {
        uncomp_bound *= 2;
        unsigned char* new_data = realloc(uncomp_data, uncomp_bound);
        if (!new_data) {
            free(uncomp_data);
            free(comp_data);
            return false;
        }
        uncomp_data = new_data;
        
        uLong uncomp_len = uncomp_bound;
        ret = uncompress(uncomp_data, &uncomp_len, comp_data, comp_len);
        
        if (ret == Z_OK) {
            // Write to output file
            FILE* f = fopen(output_file, "wb");
            if (!f) {
                free(uncomp_data);
                free(comp_data);
                return false;
            }
            
            bool success = fwrite(uncomp_data, 1, uncomp_len, f) == uncomp_len;
            fclose(f);
            free(uncomp_data);
            free(comp_data);
            return success;
        }
    } while (ret == Z_BUF_ERROR);
    
    free(uncomp_data);
    free(comp_data);
    return false;
} 