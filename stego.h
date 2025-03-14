#ifndef STEGO_H
#define STEGO_H

#include <stdbool.h>

// Hide data in a new image
bool hide(const char* input_file, const char* output_file, const char* password);

// Extract data from image
bool extract(const char* image_file, const char* output_file, const char* password);

#endif 