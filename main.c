#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "stego.h"

void print_usage() {
    printf("Usage:\n");
    printf("  Hide file:    stego hide <input_file> <output.png> [-p password]\n");
    printf("  Hide text:    stego hide -t <text> <output.png> [-p password]\n");
    printf("  Extract:      stego extract <image.png> <output_file> [-p password]\n");
}

int main(int argc, char** argv) {
    if (argc < 4) {
        print_usage();
        return 1;
    }
    
    const char* command = argv[1];
    const char* password = NULL;
    const char* input = NULL;
    bool is_text = false;
    
    // Check for text flag
    if (strcmp(command, "hide") == 0 && strcmp(argv[2], "-t") == 0) {
        is_text = true;
        input = argv[3];
    } else {
        input = argv[2];
    }
    
    // Check for password
    int start = is_text ? 4 : 4;
    for (int i = start; i < argc - 1; i++) {
        if (strcmp(argv[i], "-p") == 0) {
            password = argv[i + 1];
            break;
        }
    }
    
    if (strcmp(command, "hide") == 0) {
        if (is_text) {
            // Create temporary file for text
            FILE* f = fopen("temp.txt", "w");
            if (!f) {
                perror("Failed to create temp file");
                return 1;
            }
            fprintf(f, "%s", input);
            fclose(f);
            
            // Hide the temp file
            bool success = hide("temp.txt", argv[4], password);
            remove("temp.txt");
            return success ? 0 : 1;
        } else {
            return hide(input, argv[3], password) ? 0 : 1;
        }
    } else if (strcmp(command, "extract") == 0) {
        return extract(argv[2], argv[3], password) ? 0 : 1;
    } else {
        print_usage();
        return 1;
    }
} 