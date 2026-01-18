/*
 * Sosemanuk Test Vector Generator
 * 
 * Refactored version with improved readability
 * Generates test vectors for Sosemanuk stream cipher
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include "sosemanuk.h"

/* ========================================================================
 * CONSTANTS
 * ======================================================================== */

#define KEY_SIZE_BYTES           32
#define IV_SIZE_BYTES            16
#define PLAINTEXT_SIZE_BYTES     16
#define KEYSTREAM_SIZE_BYTES     80
#define NUM_TEST_VECTORS         20

#define HEX_BUFFER_SIZE_KEY      (KEY_SIZE_BYTES * 2 + 1)
#define HEX_BUFFER_SIZE_IV       (IV_SIZE_BYTES * 2 + 1)
#define HEX_BUFFER_SIZE_PLAIN    (PLAINTEXT_SIZE_BYTES * 2 + 1)
#define HEX_BUFFER_SIZE_KEYSTREAM (KEYSTREAM_SIZE_BYTES * 2 + 1)

#define OUTPUT_FILENAME          "test_vector.txt"

/* ========================================================================
 * UTILITY FUNCTIONS
 * ======================================================================== */

/**
 * Convert hexadecimal string to byte array
 * 
 * @param hex    Input hex string (e.g., "00112233")
 * @param bytes  Output byte array
 * @param len    Number of bytes to convert
 * @return       0 on success
 */
static int 
hex_to_bytes(const char *hex, uint8_t *bytes, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (sscanf(hex + 2 * i, "%2hhx", &bytes[i]) != 1) {
            return -1;
        }
    }
    return 0;
}

/**
 * Convert byte array to hexadecimal string
 * 
 * @param bytes  Input byte array
 * @param len    Number of bytes to convert
 * @param hex    Output hex string buffer (must be at least len*2+1 bytes)
 */
static void 
bytes_to_hex(const uint8_t *bytes, size_t len, char *hex)
{
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + 2 * i, "%02X", bytes[i]);
    }
    hex[2 * len] = '\0';
}

/**
 * Compare two byte arrays
 * 
 * @param a    First byte array
 * @param b    Second byte array
 * @param len  Number of bytes to compare
 * @return     1 if equal, 0 if different
 */
static int 
compare_bytes(const uint8_t *a, const uint8_t *b, size_t len)
{
    return memcmp(a, b, len) == 0;
}

/**
 * XOR two byte arrays
 * 
 * @param dst     Destination array
 * @param src1    First source array
 * @param src2    Second source array
 * @param len     Number of bytes to XOR
 */
static void 
xor_bytes(uint8_t *dst, const uint8_t *src1, const uint8_t *src2, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        dst[i] = src1[i] ^ src2[i];
    }
}

/* ========================================================================
 * TEST VECTOR GENERATION
 * ======================================================================== */

/**
 * Initialize test key
 * 
 * @param key  Output key buffer (must be KEY_SIZE_BYTES)
 */
static void 
initialize_test_key(uint8_t *key)
{
    const uint8_t key_pattern[KEY_SIZE_BYTES] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    memcpy(key, key_pattern, KEY_SIZE_BYTES);
}

/**
 * Initialize test IV with optional offset
 * 
 * @param iv      Output IV buffer (must be IV_SIZE_BYTES)
 * @param offset  Value to add to last byte for variation
 */
static void 
initialize_test_iv(uint8_t *iv, uint8_t offset)
{
    const uint8_t iv_pattern[IV_SIZE_BYTES] = {
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77
    };
    memcpy(iv, iv_pattern, IV_SIZE_BYTES);
    iv[IV_SIZE_BYTES - 1] += offset;
}

/**
 * Initialize test plaintext
 * 
 * @param plaintext  Output plaintext buffer (must be PLAINTEXT_SIZE_BYTES)
 */
static void 
initialize_test_plaintext(uint8_t *plaintext)
{
    const char *message = "Hello World!";
    size_t msg_len = strlen(message);
    
    memset(plaintext, 0, PLAINTEXT_SIZE_BYTES);
    memcpy(plaintext, message, msg_len);
}

/**
 * Generate a single test vector
 * 
 * @param vector_num  Test vector number (for display)
 * @param key         Encryption key
 * @param iv          Initialization vector
 * @param plaintext   Plaintext to encrypt
 * @param fp          Output file pointer
 * @return            0 on success, -1 on error
 */
static int 
generate_test_vector(int vector_num, 
                     const uint8_t *key, 
                     const uint8_t *iv,
                     const uint8_t *plaintext,
                     FILE *fp)
{
    struct sosemanuk_context ctx;
    uint32_t keystream[KEYSTREAM_SIZE_BYTES / sizeof(uint32_t)];
    uint8_t keystream_bytes[KEYSTREAM_SIZE_BYTES];
    uint8_t ciphertext[PLAINTEXT_SIZE_BYTES];
    uint8_t recovered[PLAINTEXT_SIZE_BYTES];
    
    char key_hex[HEX_BUFFER_SIZE_KEY];
    char iv_hex[HEX_BUFFER_SIZE_IV];
    char keystream_hex[HEX_BUFFER_SIZE_KEYSTREAM];
    char ciphertext_hex[HEX_BUFFER_SIZE_PLAIN];
    
    /* Setup Sosemanuk context */
    if (sosemanuk_set_key_and_iv(&ctx, key, KEY_SIZE_BYTES, iv, IV_SIZE_BYTES) != 0) {
        fprintf(stderr, "Error: Failed to setup context for vector %d\n", vector_num);
        return -1;
    }
    
    /* Generate keystream */
    sosemanuk_generate_keystream(&ctx, keystream);
    memcpy(keystream_bytes, keystream, KEYSTREAM_SIZE_BYTES);
    
    /* Encrypt: plaintext XOR keystream = ciphertext */
    xor_bytes(ciphertext, plaintext, keystream_bytes, PLAINTEXT_SIZE_BYTES);
    
    /* Decrypt: ciphertext XOR keystream = recovered plaintext */
    xor_bytes(recovered, ciphertext, keystream_bytes, PLAINTEXT_SIZE_BYTES);
    
    /* Verify decryption */
    if (!compare_bytes(plaintext, recovered, PLAINTEXT_SIZE_BYTES)) {
        fprintf(stderr, "Warning: Decryption verification failed for vector %d\n", vector_num);
    }
    
    /* Convert to hexadecimal */
    bytes_to_hex(key, KEY_SIZE_BYTES, key_hex);
    bytes_to_hex(iv, IV_SIZE_BYTES, iv_hex);
    bytes_to_hex(keystream_bytes, KEYSTREAM_SIZE_BYTES, keystream_hex);
    bytes_to_hex(ciphertext, PLAINTEXT_SIZE_BYTES, ciphertext_hex);
    
    /* Write to file */
    fprintf(fp, "Test Vector %d:\n", vector_num);
    fprintf(fp, "Key: %s\n", key_hex);
    fprintf(fp, "IV: %s\n", iv_hex);
    fprintf(fp, "Keystream: %s\n", keystream_hex);
    fprintf(fp, "Plaintext: %.*s\n", PLAINTEXT_SIZE_BYTES, plaintext);
    fprintf(fp, "Ciphertext: %s\n", ciphertext_hex);
    fprintf(fp, "Recovered Plaintext: %.*s\n\n", PLAINTEXT_SIZE_BYTES, recovered);
    
    return 0;
}

/* ========================================================================
 * MAIN FUNCTION
 * ======================================================================== */

int 
main(void)
{
    uint8_t key[KEY_SIZE_BYTES];
    uint8_t iv[IV_SIZE_BYTES];
    uint8_t plaintext[PLAINTEXT_SIZE_BYTES];
    FILE *fp;
    int success_count = 0;
    
    /* Initialize test data */
    initialize_test_key(key);
    initialize_test_plaintext(plaintext);
    
    /* Open output file */
    remove(OUTPUT_FILENAME);
    fp = fopen(OUTPUT_FILENAME, "w");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open file '%s' for writing\n", OUTPUT_FILENAME);
        return EXIT_FAILURE;
    }
    
    /* Write file header */
    fprintf(fp, "========================================\n");
    fprintf(fp, "Sosemanuk Test Vectors\n");
    fprintf(fp, "========================================\n\n");
    
    /* Generate test vectors */
    printf("Generating %d test vectors...\n", NUM_TEST_VECTORS);
    
    for (int i = 0; i < NUM_TEST_VECTORS; i++) {
        /* Initialize IV with variation */
        initialize_test_iv(iv, i);
        
        /* Generate and write test vector */
        if (generate_test_vector(i + 1, key, iv, plaintext, fp) == 0) {
            success_count++;
            printf("  Vector %2d/%d generated successfully\n", i + 1, NUM_TEST_VECTORS);
        } else {
            printf("  Vector %2d/%d FAILED\n", i + 1, NUM_TEST_VECTORS);
        }
    }
    
    /* Cleanup */
    fclose(fp);
    
    /* Print summary */
    printf("\n========================================\n");
    printf("Generation complete!\n");
    printf("  Total vectors: %d\n", NUM_TEST_VECTORS);
    printf("  Successful: %d\n", success_count);
    printf("  Failed: %d\n", NUM_TEST_VECTORS - success_count);
    printf("  Output file: %s\n", OUTPUT_FILENAME);
    printf("========================================\n");
    
    return (success_count == NUM_TEST_VECTORS) ? EXIT_SUCCESS : EXIT_FAILURE;
}
