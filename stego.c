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
    // Use 1 LSB from each channel, need 3 pixels for 8 bits
    // First pixel: bits 7,6,5
    pixels[0] = (pixels[0] & 0xFE) | ((byte >> 7) & 0x01);  // bit 7
    pixels[1] = (pixels[1] & 0xFE) | ((byte >> 6) & 0x01);  // bit 6
    pixels[2] = (pixels[2] & 0xFE) | ((byte >> 5) & 0x01);  // bit 5
    
    // Second pixel: bits 4,3,2
    pixels[3] = (pixels[3] & 0xFE) | ((byte >> 4) & 0x01);  // bit 4
    pixels[4] = (pixels[4] & 0xFE) | ((byte >> 3) & 0x01);  // bit 3
    pixels[5] = (pixels[5] & 0xFE) | ((byte >> 2) & 0x01);  // bit 2
    
    // Third pixel: bits 1,0 (last channel unused)
    pixels[6] = (pixels[6] & 0xFE) | ((byte >> 1) & 0x01);  // bit 1
    pixels[7] = (pixels[7] & 0xFE) | (byte & 0x01);         // bit 0
}

static uint8_t extract_byte(const unsigned char* pixels) {
    // Extract 1 LSB from each channel
    uint8_t byte = 0;
    byte |= (pixels[0] & 0x01) << 7;  // bit 7
    byte |= (pixels[1] & 0x01) << 6;  // bit 6
    byte |= (pixels[2] & 0x01) << 5;  // bit 5
    byte |= (pixels[3] & 0x01) << 4;  // bit 4
    byte |= (pixels[4] & 0x01) << 3;  // bit 3
    byte |= (pixels[5] & 0x01) << 2;  // bit 2
    byte |= (pixels[6] & 0x01) << 1;  // bit 1
    byte |= (pixels[7] & 0x01);       // bit 0
    return byte;
}

// Embed data in LSBs
static bool embed_data(Image* img, const unsigned char* data, size_t data_len) {
    // Write length (4 bytes)
    for (size_t i = 0; i < 4; i++) {
        if (i * 8 + 7 >= (size_t)img->width * img->height * 3) {
            return false;
        }
        embed_byte(&img->data[i * 8], (data_len >> (i * 8)) & 0xFF);
    }
    
    // Write data
    size_t pixel_idx = 32; // 4 bytes * 8 bytes per byte
    for (size_t i = 0; i < data_len; i++) {
        if (pixel_idx + 7 >= (size_t)img->width * img->height * 3) {
            return false;
        }
        embed_byte(&img->data[pixel_idx], data[i]);
        pixel_idx += 8;
    }
    
    // Write delimiter
    for (size_t i = 0; i < DELIMITER_LEN; i++) {
        if (pixel_idx + 7 >= (size_t)img->width * img->height * 3) {
            return false;
        }
        embed_byte(&img->data[pixel_idx], DELIMITER[i]);
        pixel_idx += 8;
    }
    
    return true;
}

// Extract data from LSBs
static unsigned char* extract_data(const Image* img, size_t* out_len) {
    // Read length (4 bytes)
    uint32_t size = 0;
    for (size_t i = 0; i < 4; i++) {
        if (i * 8 + 7 >= (size_t)img->width * img->height * 3) {
            return NULL;
        }
        size |= (uint32_t)extract_byte(&img->data[i * 8]) << (i * 8);
    }
    
    // Allocate buffer
    unsigned char* data = malloc(size);
    if (!data) return NULL;
    
    // Extract data
    size_t pixel_idx = 32; // 4 bytes * 8 bytes per byte
    for (uint32_t i = 0; i < size; i++) {
        if (pixel_idx + 7 >= (size_t)img->width * img->height * 3) {
            free(data);
            return NULL;
        }
        data[i] = extract_byte(&img->data[pixel_idx]);
        pixel_idx += 8;
    }
    
    // Verify delimiter
    char delimiter[DELIMITER_LEN + 1] = {0};
    for (size_t i = 0; i < DELIMITER_LEN; i++) {
        if (pixel_idx + 7 >= (size_t)img->width * img->height * 3) {
            free(data);
            return NULL;
        }
        delimiter[i] = extract_byte(&img->data[pixel_idx]);
        pixel_idx += 8;
    }
    
    if (strcmp(delimiter, DELIMITER) != 0) {
        printf("Warning: No delimiter found, data may be incomplete\n");
    }
    
    *out_len = size;
    return data;
}

// Hide data in a new image
bool hide(const char* input_file, const char* output_file, const char* password) {
    printf("Opening input file: %s\n", input_file);
    
    // Read input file
    FILE* f = fopen(input_file, "rb");
    if (!f) {
        perror("Failed to open input file");
        return false;
    }
    
    // Get file size
    fseek(f, 0, SEEK_END);
    size_t data_len = ftell(f);
    fseek(f, 0, SEEK_SET);
    printf("Input file size: %zu bytes\n", data_len);
    
    // Read data
    unsigned char* data = malloc(data_len);
    if (!data) {
        perror("Failed to allocate memory");
        fclose(f);
        return false;
    }
    
    size_t bytes_read = fread(data, 1, data_len, f);
    if (bytes_read != data_len) {
        perror("Failed to read input file");
        fclose(f);
        free(data);
        return false;
    }
    printf("Read %zu bytes from input file\n", bytes_read);
    fclose(f);
    
    // Encrypt data if password provided
    unsigned char* encrypted = NULL;
    size_t encrypted_len = 0;
    if (password) {
        printf("Encrypting data with password\n");
        unsigned char key[CHACHA_KEY_SIZE];
        derive_key(password, key);
        if (!encrypt_data(data, data_len, &encrypted, &encrypted_len, key)) {
            free(data);
            return false;
        }
        free(data);
        data = encrypted;
        data_len = encrypted_len;
        printf("Data encrypted, new size: %zu bytes\n", data_len);
    }
    
    // Calculate required image size
    size_t total_bytes = data_len + 4 + DELIMITER_LEN;  // Data + length + delimiter
    size_t required_pixels = (total_bytes * 8 + 2) / 3;  // 8 bytes per byte of data (using 1 LSB per channel)
    int width = ceil(sqrt(required_pixels));
    int height = (required_pixels + width - 1) / width;
    
    printf("Creating %dx%d image to fit %zu bytes...\n", width, height, data_len);
    
    // Create new image with pattern
    Image* img = image_create(width, height);
    if (!img) {
        perror("Failed to create image");
        free(data);
        return false;
    }
    printf("Image created successfully\n");
    
    // Fill with pattern that has LSBs=0
    for (int y = 0; y < height; y++) {
        for (int x = 0; x < width; x++) {
            int idx = (y * width + x) * 3;
            // Create colors based on position and nearby data bytes
            size_t data_idx = (y * width + x) / 3;
            unsigned char val = (data_idx < data_len) ? data[data_idx] : 0;
            unsigned char prev = (data_idx > 0) ? data[data_idx-1] : 0;
            unsigned char next = (data_idx+1 < data_len) ? data[data_idx+1] : 0;
            
            // Generate pattern keeping LSBs=0
            img->data[idx] = ((val + x + prev) & 0xFE);
            img->data[idx+1] = ((val + y + next) & 0xFE);
            img->data[idx+2] = ((val + x + y) & 0xFE);
        }
    }
    printf("Image pattern filled\n");
    
    // Hide data in LSBs
    if (!embed_data(img, data, data_len)) {
        fprintf(stderr, "Failed to embed data\n");
        free(data);
        image_free(img);
        return false;
    }
    printf("Data embedded successfully\n");
    
    // Save output
    printf("Saving image to: %s\n", output_file);
    if (!image_save(img, output_file)) {
        fprintf(stderr, "Failed to save output image\n");
        free(data);
        image_free(img);
        return false;
    }
    
    printf("Data hidden successfully\n");
    
    free(data);
    image_free(img);
    return true;
}

bool extract(const char* image_file, const char* output_file, const char* password) {
    Image* img = image_load(image_file);
    if (!img) return false;
    
    // Extract data
    size_t data_len;
    unsigned char* data = extract_data(img, &data_len);
    if (!data) {
        image_free(img);
        return false;
    }
    
    // Check if data is encrypted
    bool is_encrypted = (data_len >= FERNET_PREFIX_LEN && 
                        memcmp(data, FERNET_PREFIX, FERNET_PREFIX_LEN) == 0);
    
    // Fail if data is encrypted but no password provided
    if (is_encrypted && !password) {
        free(data);
        image_free(img);
        return false;
    }
    
    // Decrypt if needed
    if (password) {
        unsigned char key[CHACHA_KEY_SIZE];
        derive_key(password, key);
        
        unsigned char* decrypted = NULL;
        size_t decrypted_len = 0;
        if (!decrypt_data(data, data_len, &decrypted, &decrypted_len, key)) {
            free(data);
            image_free(img);
            return false;
        }
        free(data);
        data = decrypted;
        data_len = decrypted_len;
    }
    
    // Save to file
    FILE* f = fopen(output_file, "wb");
    if (!f) {
        free(data);
        image_free(img);
        return false;
    }
    
    if (fwrite(data, 1, data_len, f) != data_len) {
        fclose(f);
        free(data);
        image_free(img);
        return false;
    }
    
    fclose(f);
    free(data);
    image_free(img);
    
    printf("Data extracted successfully\n");
    return true;
} 