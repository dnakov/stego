#ifndef PNG_H
#define PNG_H

#include <stdbool.h>
#include <stdint.h>

// Write RGB data to PNG file
bool write_png(const char* filename, const unsigned char* data, int width, int height);

#endif 