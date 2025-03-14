#ifndef IMAGE_H
#define IMAGE_H

#include <stdint.h>
#include <stdbool.h>

typedef struct {
    uint32_t width;
    uint32_t height;
    unsigned char* data;  // RGB format, 3 bytes per pixel
} Image;

Image* image_load(const char* filename);
bool image_save(const Image* img, const char* filename);
void image_free(Image* img);
Image* image_create(uint32_t width, uint32_t height);

#endif 