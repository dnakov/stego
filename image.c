#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include "image.h"
#include "png.h"

Image* image_create(uint32_t width, uint32_t height) {
    Image* img = malloc(sizeof(Image));
    if (!img) return NULL;

    img->width = width;
    img->height = height;
    img->data = calloc(width * height * 3, 1);
    if (!img->data) {
        free(img);
        return NULL;
    }

    return img;
}

Image* image_load(const char* filename) {
    FILE* f = fopen(filename, "rb");
    if (!f) return NULL;

    // Check PNG signature
    unsigned char signature[8];
    if (fread(signature, 1, 8, f) != 8 ||
        signature[0] != 0x89 || signature[1] != 0x50 || signature[2] != 0x4E || signature[3] != 0x47 ||
        signature[4] != 0x0D || signature[5] != 0x0A || signature[6] != 0x1A || signature[7] != 0x0A) {
        fclose(f);
        return NULL;
    }

    // Read IHDR chunk
    uint32_t length, type;
    if (fread(&length, 4, 1, f) != 1) {
        fclose(f);
        return NULL;
    }
    length = __builtin_bswap32(length);
    if (length != 13) {
        fclose(f);
        return NULL;
    }

    if (fread(&type, 4, 1, f) != 1) {
        fclose(f);
        return NULL;
    }
    type = __builtin_bswap32(type);
    if (type != 0x49484452) { // "IHDR"
        fclose(f);
        return NULL;
    }

    uint32_t width, height;
    uint8_t bit_depth, color_type, compression, filter, interlace;
    if (fread(&width, 4, 1, f) != 1 || fread(&height, 4, 1, f) != 1 ||
        fread(&bit_depth, 1, 1, f) != 1 || fread(&color_type, 1, 1, f) != 1 ||
        fread(&compression, 1, 1, f) != 1 || fread(&filter, 1, 1, f) != 1 ||
        fread(&interlace, 1, 1, f) != 1) {
        fclose(f);
        return NULL;
    }

    width = __builtin_bswap32(width);
    height = __builtin_bswap32(height);

    // Skip IHDR CRC
    fseek(f, 4, SEEK_CUR);

    // Read IDAT chunk
    if (fread(&length, 4, 1, f) != 1) {
        fclose(f);
        return NULL;
    }
    length = __builtin_bswap32(length);

    if (fread(&type, 4, 1, f) != 1) {
        fclose(f);
        return NULL;
    }
    type = __builtin_bswap32(type);
    if (type != 0x49444154) { // "IDAT"
        fclose(f);
        return NULL;
    }

    // Read compressed data
    unsigned char* compressed = malloc(length);
    if (!compressed) {
        fclose(f);
        return NULL;
    }

    if (fread(compressed, 1, length, f) != length) {
        free(compressed);
        fclose(f);
        return NULL;
    }

    // Calculate uncompressed size
    size_t row_size = width * 3;
    size_t image_size = height * (row_size + 1); // +1 for filter byte per row

    // Decompress data using zlib
    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = length;
    strm.next_in = compressed;

    if (inflateInit(&strm) != Z_OK) {
        free(compressed);
        fclose(f);
        return NULL;
    }

    unsigned char* image_data = malloc(image_size);
    if (!image_data) {
        inflateEnd(&strm);
        free(compressed);
        fclose(f);
        return NULL;
    }

    strm.avail_out = image_size;
    strm.next_out = image_data;

    if (inflate(&strm, Z_FINISH) != Z_STREAM_END || strm.total_out != image_size) {
        inflateEnd(&strm);
        free(compressed);
        free(image_data);
        fclose(f);
        return NULL;
    }

    inflateEnd(&strm);
    free(compressed);

    // Create image structure
    Image* img = malloc(sizeof(Image));
    if (!img) {
        free(image_data);
        fclose(f);
        return NULL;
    }

    img->width = width;
    img->height = height;
    img->data = malloc(width * height * 3);
    if (!img->data) {
        free(image_data);
        free(img);
        fclose(f);
        return NULL;
    }

    // Copy pixel data, skipping filter bytes
    for (size_t y = 0; y < height; y++) {
        memcpy(img->data + y * row_size,
               image_data + y * (row_size + 1) + 1,
               row_size);
    }

    free(image_data);
    fclose(f);
    return img;
}

bool image_save(const Image* img, const char* filename) {
    if (!img || !filename) return false;
    return write_png(filename, (const unsigned char*)img->data, img->width, img->height);
}

void image_free(Image* img) {
    if (!img) return;
    free(img->data);
    free(img);
} 