#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <unistd.h>
#include "stego.h"

// Callback function to write downloaded data to a file
size_t write_data(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    return fwrite(ptr, size, nmemb, stream);
}

// Download file from URL
bool download_file(const char* url, const char* output_file) {
    CURL *curl;
    FILE *fp;
    CURLcode res;
    
    curl = curl_easy_init();
    if (!curl) return false;
    
    fp = fopen(output_file, "wb");
    if (!fp) {
        curl_easy_cleanup(curl);
        return false;
    }
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    
    res = curl_easy_perform(curl);
    
    curl_easy_cleanup(curl);
    fclose(fp);
    
    return res == CURLE_OK;
}

void print_usage() {
    printf("Usage:\n");
    printf("  Hide file:    stego hide <input_file> <output.png> [-p password]\n");
    printf("  Hide text:    stego hide -t <text> <output.png> [-p password]\n");
    printf("  Extract:      stego extract <image.png> <output_file> [-p password]\n");
    printf("  URL extract:  stego -u <url_to_png> -o <output_file> [-p password]\n");
}

int main(int argc, char** argv) {
    if (argc < 2) {
        print_usage();
        return 1;
    }
    
    const char* password = NULL;
    const char* output_file = NULL;
    const char* url = NULL;
    
    // Parse args for URL mode
    for (int i = 1; i < argc - 1; i++) {
        if (strcmp(argv[i], "-p") == 0) {
            password = argv[i + 1];
        } else if (strcmp(argv[i], "-o") == 0) {
            output_file = argv[i + 1];
        } else if (strcmp(argv[i], "-u") == 0) {
            url = argv[i + 1];
        }
    }
    
    // Handle URL mode
    if (url) {
        if (!output_file) {
            fprintf(stderr, "Error: -o <output_file> is required\n");
            print_usage();
            return 1;
        }
        
        // Create temp file for PNG
        char temp_png[] = "/tmp/stego_XXXXXX";
        int temp_png_fd = mkstemp(temp_png);
        
        if (temp_png_fd == -1) {
            perror("Failed to create temp file");
            return 1;
        }
        close(temp_png_fd);
        
        // Download the PNG
        if (!download_file(url, temp_png)) {
            fprintf(stderr, "Failed to download URL\n");
            remove(temp_png);
            return 1;
        }
        
        // Extract directly to output file
        bool success = extract(temp_png, output_file, password);
        remove(temp_png);
        
        return success ? 0 : 1;
    }

    // Original functionality
    if (argc < 4) {
        print_usage();
        return 1;
    }
    
    const char* command = argv[1];
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