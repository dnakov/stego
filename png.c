#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include "png.h"

bool write_png(const char* filename, const unsigned char* data, int width, int height) {
    FILE* f = fopen(filename, "wb");
    if (!f) return false;

    // PNG signature
    const unsigned char signature[] = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
    fwrite(signature, 1, 8, f);

    // IHDR chunk
    uint32_t ihdr_length = 13;
    uint32_t ihdr_type = 0x49484452; // "IHDR"
    uint32_t ihdr_width = width;
    uint32_t ihdr_height = height;
    uint8_t ihdr_bit_depth = 8;
    uint8_t ihdr_color_type = 2; // RGB
    uint8_t ihdr_compression = 0;
    uint8_t ihdr_filter = 0;
    uint8_t ihdr_interlace = 0;

    // Write IHDR length and type
    uint32_t be_length = __builtin_bswap32(ihdr_length);
    uint32_t be_type = __builtin_bswap32(ihdr_type);
    fwrite(&be_length, 1, 4, f);
    fwrite(&be_type, 1, 4, f);

    // Write IHDR data
    uint32_t be_width = __builtin_bswap32(ihdr_width);
    uint32_t be_height = __builtin_bswap32(ihdr_height);
    fwrite(&be_width, 1, 4, f);
    fwrite(&be_height, 1, 4, f);
    fwrite(&ihdr_bit_depth, 1, 1, f);
    fwrite(&ihdr_color_type, 1, 1, f);
    fwrite(&ihdr_compression, 1, 1, f);
    fwrite(&ihdr_filter, 1, 1, f);
    fwrite(&ihdr_interlace, 1, 1, f);

    // Calculate IHDR CRC (including type)
    unsigned char ihdr_data[17];
    memcpy(ihdr_data, &be_type, 4);
    memcpy(ihdr_data + 4, &be_width, 4);
    memcpy(ihdr_data + 8, &be_height, 4);
    ihdr_data[12] = ihdr_bit_depth;
    ihdr_data[13] = ihdr_color_type;
    ihdr_data[14] = ihdr_compression;
    ihdr_data[15] = ihdr_filter;
    ihdr_data[16] = ihdr_interlace;
    uint32_t ihdr_crc = crc32(0, ihdr_data, sizeof(ihdr_data));
    uint32_t be_ihdr_crc = __builtin_bswap32(ihdr_crc);
    fwrite(&be_ihdr_crc, 1, 4, f);

    // IDAT chunk - compress image data
    size_t row_size = width * 3;
    size_t data_size = height * (row_size + 1); // +1 for filter byte
    unsigned char* filtered = malloc(data_size);
    if (!filtered) {
        fclose(f);
        return false;
    }

    // Add filter byte (0) at start of each row
    for (int y = 0; y < height; y++) {
        filtered[y * (row_size + 1)] = 0;
        memcpy(filtered + y * (row_size + 1) + 1, data + y * row_size, row_size);
    }

    // Compress data
    uLongf compressed_size = compressBound(data_size);
    unsigned char* compressed = malloc(compressed_size);
    if (!compressed) {
        free(filtered);
        fclose(f);
        return false;
    }

    if (compress(compressed, &compressed_size, filtered, data_size) != Z_OK) {
        free(filtered);
        free(compressed);
        fclose(f);
        return false;
    }

    // Write IDAT chunk
    uint32_t idat_type = 0x49444154; // "IDAT"
    uint32_t be_idat_type = __builtin_bswap32(idat_type);
    uint32_t be_compressed_size = __builtin_bswap32(compressed_size);
    fwrite(&be_compressed_size, 1, 4, f);
    fwrite(&be_idat_type, 1, 4, f);
    fwrite(compressed, 1, compressed_size, f);

    // Calculate IDAT CRC
    uint32_t idat_crc = crc32(0, (unsigned char*)&be_idat_type, 4);
    idat_crc = crc32(idat_crc, compressed, compressed_size);
    uint32_t be_idat_crc = __builtin_bswap32(idat_crc);
    fwrite(&be_idat_crc, 1, 4, f);

    // IEND chunk
    uint32_t iend_length = 0;
    uint32_t iend_type = 0x49454E44; // "IEND"
    uint32_t be_iend_type = __builtin_bswap32(iend_type);
    uint32_t iend_crc = crc32(0, (unsigned char*)&be_iend_type, 4);
    uint32_t be_iend_crc = __builtin_bswap32(iend_crc);

    fwrite(&iend_length, 1, 4, f);
    fwrite(&be_iend_type, 1, 4, f);
    fwrite(&be_iend_crc, 1, 4, f);

    free(filtered);
    free(compressed);
    fclose(f);
    return true;
} 