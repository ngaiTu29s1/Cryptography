#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "sosemanuk.h"

// Function to convert hex string to bytes
int hex_to_bytes(const char *hex, uint8_t *bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        sscanf(hex + 2 * i, "%2hhx", &bytes[i]);
    }
    return 0;
}

// Function to convert bytes to hex string
void bytes_to_hex(const uint8_t *bytes, size_t len, char *hex) {
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + 2 * i, "%02X", bytes[i]);
    }
    hex[2 * len] = '\0';
}

// Function to compare two byte arrays
int compare_bytes(const uint8_t *a, const uint8_t *b, size_t len) {
    return memcmp(a, b, len) == 0;
}

int
main(void)
{
    uint8_t key[32] = { 0x00, 0x11, 0x22, 0x33,
                        0x44, 0x55, 0x66, 0x77,
                        0x88, 0x99, 0xAA, 0xBB,
                        0xCC, 0xDD, 0xEE, 0xFF,
                        0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00 };

    uint8_t plaintext[16] = "Hello World!";  // 12 bytes + padding
    plaintext[12] = 0x00; plaintext[13] = 0x00; plaintext[14] = 0x00; plaintext[15] = 0x00;

    FILE *fp_txt;
    char key_hex[65], plaintext_hex[33];
    int i;

    // Convert key and plaintext to hex
    bytes_to_hex(key, 32, key_hex);
    bytes_to_hex(plaintext, 16, plaintext_hex);

    // Open files
    remove("test_vector.txt");
    fp_txt = fopen("test_vector.txt", "w");

    // Generate 20 test vectors with incrementing IV
    for (i = 0; i < 20; i++) {
        uint8_t iv[16] = { 0x88, 0x99, 0xAA, 0xBB,
                           0xCC, 0xDD, 0xEE, 0xFF,
                           0x00, 0x11, 0x22, 0x33,
                           0x44, 0x55, 0x66, 0x77 };
        iv[15] += i;  // Increment IV slightly for variation

        struct sosemanuk_context ctx;
        uint32_t keystream[20];  // 80 bytes
        char iv_hex[33], keystream_hex[161], ciphertext_hex[33], recovered_hex[33];
        uint8_t ciphertext[16], recovered[16];

        // Setup context
        if (sosemanuk_set_key_and_iv(&ctx, key, 32, iv, 16)) {
            printf("Context setup error for vector %d!\n", i + 1);
            continue;
        }

        // Generate keystream
        sosemanuk_generate_keystream(&ctx, keystream);
        uint8_t keystream_bytes[80];
        memcpy(keystream_bytes, keystream, 80);

        // Compute ciphertext and recovered
        for (int j = 0; j < 16; j++) {
            ciphertext[j] = plaintext[j] ^ keystream_bytes[j];
            recovered[j] = ciphertext[j] ^ keystream_bytes[j];
        }

        // Convert to hex
        bytes_to_hex(iv, 16, iv_hex);
        bytes_to_hex(keystream_bytes, 80, keystream_hex);
        bytes_to_hex(ciphertext, 16, ciphertext_hex);
        bytes_to_hex(recovered, 16, recovered_hex);

        // Write to TXT
        if (fp_txt) {
            fprintf(fp_txt, "Test Vector %d:\n", i + 1);
            fprintf(fp_txt, "Key: %s\n", key_hex);
            fprintf(fp_txt, "IV: %s\n", iv_hex);
            fprintf(fp_txt, "Keystream: %s\n", keystream_hex);
            fprintf(fp_txt, "Plaintext: %s\n", plaintext_hex);
            fprintf(fp_txt, "Ciphertext: %s\n", ciphertext_hex);
            fprintf(fp_txt, "Recovered Plaintext: %s\n\n", recovered_hex);
        }
    }

    if (fp_txt) fclose(fp_txt);

    printf("Generated 20 test vectors to test_vector.txt\n");

    return 0;
}

