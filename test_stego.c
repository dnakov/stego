#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include "stego.h"

#define TEST_DATA "This is test data that will be hidden and extracted"
#define TEST_PASSWORD "secret123"
#define TEST_FILE "test_data.txt"
#define OUTPUT_IMAGE "output.png"
#define EXTRACTED_FILE "extracted.txt"

// Helper to write test data to file
static void write_test_data(const char* data) {
    FILE* f = fopen(TEST_FILE, "w");
    assert(f != NULL);
    size_t written = fwrite(data, 1, strlen(data), f);
    printf("Wrote %zu bytes to %s\n", written, TEST_FILE);
    fclose(f);
}

// Helper to read and verify extracted data
static void verify_extracted_data(const char* expected) {
    FILE* f = fopen(EXTRACTED_FILE, "r");
    assert(f != NULL);
    
    char buf[1024] = {0};
    size_t n = fread(buf, 1, sizeof(buf)-1, f);
    fclose(f);
    
    assert(n == strlen(expected));
    assert(memcmp(buf, expected, n) == 0);
}

// Test hiding and extracting without password
static void test_no_password(void) {
    printf("Testing hide/extract without password...\n");
    
    // Write test data
    write_test_data(TEST_DATA);
    
    // Verify file exists and has correct size
    FILE* f = fopen(TEST_FILE, "rb");
    assert(f != NULL);
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fclose(f);
    printf("Test file size: %zu bytes\n", size);
    
    // Hide data
    assert(hide(TEST_FILE, OUTPUT_IMAGE, NULL));
    assert(access(OUTPUT_IMAGE, F_OK) == 0);
    
    // Extract and verify
    assert(extract(OUTPUT_IMAGE, EXTRACTED_FILE, NULL));
    verify_extracted_data(TEST_DATA);
    
    printf("No password test passed!\n");
}

// Test hiding and extracting with password
static void test_with_password(void) {
    printf("Testing hide/extract with password...\n");
    
    // Write test data
    write_test_data(TEST_DATA);
    
    // Hide data with password
    assert(hide(TEST_FILE, OUTPUT_IMAGE, TEST_PASSWORD));
    assert(access(OUTPUT_IMAGE, F_OK) == 0);
    
    // Try extracting without password (should fail)
    assert(!extract(OUTPUT_IMAGE, EXTRACTED_FILE, NULL));
    
    // Extract with correct password and verify
    assert(extract(OUTPUT_IMAGE, EXTRACTED_FILE, TEST_PASSWORD));
    verify_extracted_data(TEST_DATA);
    
    printf("Password test passed!\n");
}

// Test hiding and extracting with wrong password
static void test_wrong_password(void) {
    printf("Testing extraction with wrong password...\n");
    
    // Write test data
    write_test_data(TEST_DATA);
    
    // Hide data with password
    assert(hide(TEST_FILE, OUTPUT_IMAGE, TEST_PASSWORD));
    assert(access(OUTPUT_IMAGE, F_OK) == 0);
    
    // Try extracting with wrong password (should fail)
    assert(!extract(OUTPUT_IMAGE, EXTRACTED_FILE, "wrongpass"));
    
    printf("Wrong password test passed!\n");
}

int main(void) {
    // Run tests
    test_no_password();
    test_with_password();
    test_wrong_password();
    
    // Cleanup
    remove(TEST_FILE);
    remove(OUTPUT_IMAGE);
    remove(EXTRACTED_FILE);
    
    printf("All tests passed!\n");
    return 0;
} 