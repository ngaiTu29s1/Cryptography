/*
 * Simple Sosemanuk Encrypt/Decrypt Tool
 * Single case processing with key, iv, plaintext from input file
 * Usage:
 *   encrypt: ./simple_sosemanuk -e input.txt output.bin
 *   decrypt: ./simple_sosemanuk -d input.txt output.txt
 *
 * Input file format for encrypt:
 *   key=<hex_key>
 *   iv=<hex_iv>
 *   plaintext=<text_or_hex>
 *
 * Input file format for decrypt:
 *   key=<hex_key>
 *   iv=<hex_iv>
 *   ciphertext_file=<encrypted_file_path>
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>

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

// Function to read input file and parse parameters
int parse_input_file(const char *filename, uint8_t *key, uint8_t *iv, char *plaintext, size_t *plaintext_len, char *ciphertext_file, int is_encrypt) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("Cannot open input file");
        return -1;
    }

    char line[1024];
    char key_hex[65] = {0};
    char iv_hex[33] = {0};
    char plaintext_hex[1025] = {0};
    char ciphertext_path[256] = {0};

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "key=")) {
            sscanf(line, "key=%64s", key_hex);
            hex_to_bytes(key_hex, key, 32);
        } else if (strstr(line, "iv=")) {
            sscanf(line, "iv=%32s", iv_hex);
            hex_to_bytes(iv_hex, iv, 16);
        } else if (is_encrypt && strstr(line, "plaintext=")) {
            char *ptr = strstr(line, "plaintext=") + 10;
            // Remove newline
            ptr[strcspn(ptr, "\n")] = 0;
            strcpy(plaintext_hex, ptr);

            // Try to parse as hex first
            size_t hex_len = strlen(plaintext_hex);
            if (hex_len % 2 == 0 && hex_len > 0) {
                // Check if it's valid hex
                int is_hex = 1;
                for (size_t i = 0; i < hex_len; i++) {
                    if (!isxdigit(plaintext_hex[i])) {
                        is_hex = 0;
                        break;
                    }
                }
                if (is_hex) {
                    *plaintext_len = hex_len / 2;
                    hex_to_bytes(plaintext_hex, (uint8_t*)plaintext, *plaintext_len);
                    plaintext[*plaintext_len] = '\0';
                } else {
                    // Treat as plain text
                    strcpy(plaintext, plaintext_hex);
                    *plaintext_len = strlen(plaintext);
                }
            } else {
                // Plain text
                strcpy(plaintext, plaintext_hex);
                *plaintext_len = strlen(plaintext);
            }
        } else if (!is_encrypt && strstr(line, "ciphertext_file=")) {
            sscanf(line, "ciphertext_file=%255s", ciphertext_path);
            strcpy(ciphertext_file, ciphertext_path);
        }
    }

    fclose(fp);
    return 0;
}

void print_usage(const char *program_name) {
    printf("Simple Sosemanuk Encrypt/Decrypt Tool\n\n");
    printf("Usage:\n");
    printf("  %s -e <input_file> <output_file>    # Encrypt\n", program_name);
    printf("  %s -d <input_file> <output_file>    # Decrypt\n\n", program_name);
    printf("Input file format for encryption:\n");
    printf("  key=<32_byte_hex_key>\n");
    printf("  iv=<16_byte_hex_iv>\n");
    printf("  plaintext=<text_or_hex_data>\n\n");
    printf("Input file format for decryption:\n");
    printf("  key=<32_byte_hex_key>\n");
    printf("  iv=<16_byte_hex_iv>\n");
    printf("  ciphertext_file=<encrypted_file_path>\n\n");
    printf("Examples:\n");
    printf("  %s -e encrypt_input.txt message.enc\n", program_name);
    printf("  %s -d decrypt_input.txt message.txt\n", program_name);
}

int main(int argc, char *argv[]) {
    int encrypt_mode = 1; // 1 = encrypt, 0 = decrypt
    char *input_file = NULL;
    char *output_file = NULL;

    // Parse command line arguments
    if (argc < 4) {
        print_usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "-e") == 0) {
        encrypt_mode = 1;
    } else if (strcmp(argv[1], "-d") == 0) {
        encrypt_mode = 0;
    } else {
        print_usage(argv[0]);
        return 1;
    }

    input_file = argv[2];
    output_file = argv[3];

    // Parse input file
    uint8_t key[32];
    uint8_t iv[16];
    char plaintext[1024];
    size_t plaintext_len = 0;
    char ciphertext_file[256];

    if (parse_input_file(input_file, key, iv, plaintext, &plaintext_len, ciphertext_file, encrypt_mode) != 0) {
        return 1;
    }

    // Initialize cipher context
    struct sosemanuk_context ctx;
    if (sosemanuk_set_key_and_iv(&ctx, key, 32, iv, 16)) {
        printf("Error: Failed to initialize cipher context\n");
        return 1;
    }

    if (encrypt_mode) {
        // Encrypt mode
        printf("Encrypting %zu bytes of plaintext...\n", plaintext_len);

        // Allocate output buffer
        uint8_t *ciphertext = malloc(plaintext_len);
        if (!ciphertext) {
            printf("Error: Memory allocation failed\n");
            return 1;
        }

        // Encrypt
        sosemanuk_crypt(&ctx, (uint8_t*)plaintext, plaintext_len, ciphertext);

        // Write to output file
        FILE *fp = fopen(output_file, "wb");
        if (!fp) {
            perror("Cannot open output file");
            free(ciphertext);
            return 1;
        }

        fwrite(ciphertext, 1, plaintext_len, fp);
        fclose(fp);
        free(ciphertext);

        printf("Encryption complete. Output written to: %s\n", output_file);

        // Print hex for verification
        char hex_output[2049];
        bytes_to_hex(ciphertext, plaintext_len, hex_output);
        printf("Ciphertext (hex): %s\n", hex_output);

    } else {
        // Decrypt mode
        printf("Decrypting from file: %s\n", ciphertext_file);

        // Read ciphertext from file
        FILE *fp_in = fopen(ciphertext_file, "rb");
        if (!fp_in) {
            perror("Cannot open ciphertext file");
            return 1;
        }

        // Get file size
        fseek(fp_in, 0, SEEK_END);
        size_t file_size = ftell(fp_in);
        fseek(fp_in, 0, SEEK_SET);

        uint8_t *ciphertext = malloc(file_size);
        if (!ciphertext) {
            printf("Error: Memory allocation failed\n");
            fclose(fp_in);
            return 1;
        }

        fread(ciphertext, 1, file_size, fp_in);
        fclose(fp_in);

        // Allocate output buffer
        uint8_t *decrypted = malloc(file_size);
        if (!decrypted) {
            printf("Error: Memory allocation failed\n");
            free(ciphertext);
            return 1;
        }

        // Decrypt (same operation as encrypt for stream cipher)
        sosemanuk_crypt(&ctx, ciphertext, file_size, decrypted);

        // Write to output file
        FILE *fp_out = fopen(output_file, "wb");
        if (!fp_out) {
            perror("Cannot open output file");
            free(ciphertext);
            free(decrypted);
            return 1;
        }

        fwrite(decrypted, 1, file_size, fp_out);
        fclose(fp_out);

        free(ciphertext);
        free(decrypted);

        printf("Decryption complete. Output written to: %s\n", output_file);

        // Try to print as text if it's printable
        int is_printable = 1;
        for (size_t i = 0; i < file_size && i < 100; i++) {
            if (decrypted[i] < 32 && decrypted[i] != '\n' && decrypted[i] != '\r' && decrypted[i] != '\t') {
                is_printable = 0;
                break;
            }
        }

        if (is_printable && file_size < 200) {
            printf("Decrypted text: %.*s\n", (int)file_size, decrypted);
        }
    }

    return 0;
}

