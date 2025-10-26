/*
 * Simple Sosemanuk Encrypt/Decrypt Tool
 * Single case processing with key, iv, plaintext from input file
 * Usage:
 *   encrypt: ./simple_sosemanuk -e input.txt output.bin
 *   decrypt from hex: ./simple_sosemanuk -d input.txt
 *   decrypt from hex: ./simple_sosemanuk -h input.txt
 *
 * Input file format for encryption:
 *   key=<32_byte_hex_key>
 *   iv=<16_byte_hex_iv>
 *   plaintext=<text_or_hex_data>
 *
 * Input file format for decryption from hex:
 *   key=<32_byte_hex_key>
 *   iv=<16_byte_hex_iv>
 *   ciphertext=<hex_data>
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>

#include "sosemanuk.h"

// Function to convert hex string to bytes
int hex_to_bytes(const char *hex, uint8_t *bytes, size_t max_len, size_t *out_len) {
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) return -1;

    *out_len = hex_len / 2;
    if (*out_len > max_len) return -1;

    for (size_t i = 0; i < *out_len; i++) {
        if (sscanf(hex + 2 * i, "%2hhx", &bytes[i]) != 1) {
            return -1;
        }
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
int parse_input_file(const char *filename, uint8_t *key, uint8_t *iv, char *plaintext, size_t *plaintext_len, char *ciphertext_file, char *ciphertext_hex, int mode) {
    // mode: 0=encrypt, 1=decrypt_file, 2=decrypt_hex
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("Cannot open input file");
        return -1;
    }

    char line[1024];

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "key=")) {
            char key_hex[65] = {0};
            sscanf(line, "key=%64s", key_hex);
            size_t key_len;
            if (hex_to_bytes(key_hex, key, 32, &key_len) != 0 || key_len != 32) {
                printf("Error: Invalid key format\n");
                fclose(fp);
                return -1;
            }
        } else if (strstr(line, "iv=")) {
            char iv_hex[33] = {0};
            sscanf(line, "iv=%32s", iv_hex);
            size_t iv_len;
            if (hex_to_bytes(iv_hex, iv, 16, &iv_len) != 0 || iv_len != 16) {
                printf("Error: Invalid IV format\n");
                fclose(fp);
                return -1;
            }
        } else if (mode == 0 && strstr(line, "plaintext=")) { // encrypt mode
            char *ptr = strstr(line, "plaintext=") + 10;
            // Remove newline
            ptr[strcspn(ptr, "\n")] = 0;

            // Try to parse as hex first
            size_t hex_len = strlen(ptr);
            if (hex_len % 2 == 0 && hex_len > 0) {
                // Check if it's valid hex
                int is_hex = 1;
                for (size_t i = 0; i < hex_len; i++) {
                    if (!isxdigit((unsigned char)ptr[i])) {
                        is_hex = 0;
                        break;
                    }
                }
                if (is_hex) {
                    if (hex_to_bytes(ptr, (uint8_t*)plaintext, sizeof(plaintext), plaintext_len) != 0) {
                        printf("Error: Invalid plaintext hex format\n");
                        fclose(fp);
                        return -1;
                    }
                    plaintext[*plaintext_len] = '\0';
                } else {
                    // Treat as plain text
                    strcpy(plaintext, ptr);
                    *plaintext_len = strlen(plaintext);
                }
            } else {
                // Plain text
                strcpy(plaintext, ptr);
                *plaintext_len = strlen(plaintext);
            }
        } else if ((mode == 1 || mode == 2) && strstr(line, "ciphertext=")) { // decrypt from hex mode
            char *ptr = strstr(line, "ciphertext=") + 11;
            // Remove newline
            ptr[strcspn(ptr, "\n")] = 0;
            strcpy(ciphertext_hex, ptr);
        }
    }

    fclose(fp);
    return 0;
}

void print_usage(const char *program_name) {
    printf("Simple Sosemanuk Encrypt/Decrypt Tool\n\n");
    printf("Usage:\n");
    printf("  %s -e <input_file> <output_file>    # Encrypt\n", program_name);
    printf("  %s -d <input_file>                  # Decrypt from hex\n", program_name);
    printf("  %s -h <input_file>                  # Decrypt from hex\n\n", program_name);
    printf("Input file format for encryption:\n");
    printf("  key=<32_byte_hex_key>\n");
    printf("  iv=<16_byte_hex_iv>\n");
    printf("  plaintext=<text_or_hex_data>\n\n");
    printf("Input file format for decryption from file:\n");
    printf("  key=<32_byte_hex_key>\n");
    printf("  iv=<16_byte_hex_iv>\n");
    printf("  ciphertext_file=<encrypted_file_path>\n\n");
    printf("Input file format for decryption from hex:\n");
    printf("  key=<32_byte_hex_key>\n");
    printf("  iv=<16_byte_hex_iv>\n");
    printf("  ciphertext=<hex_data>\n\n");
    printf("Examples:\n");
    printf("  %s -e encrypt_input.txt message.enc\n", program_name);
    printf("  %s -d decrypt_input.txt message.txt\n", program_name);
    printf("  %s -h hex_decrypt_input.txt\n", program_name);
}

int main(int argc, char *argv[]) {
    int mode = 0; // 0=encrypt, 1=decrypt_file, 2=decrypt_hex
    char *input_file = NULL;
    char *output_file = NULL;

    // Parse command line arguments
    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "-e") == 0) {
        mode = 0;
        if (argc != 4) {
            print_usage(argv[0]);
            return 1;
        }
        input_file = argv[2];
        output_file = argv[3];
    } else if (strcmp(argv[1], "-d") == 0) {
        mode = 1;
        if (argc != 3) {
            print_usage(argv[0]);
            return 1;
        }
        input_file = argv[2];
    } else if (strcmp(argv[1], "-h") == 0) {
        mode = 2;
        if (argc != 3) {
            print_usage(argv[0]);
            return 1;
        }
        input_file = argv[2];
    } else {
        print_usage(argv[0]);
        return 1;
    }

    // Parse input file
    uint8_t key[32];
    uint8_t iv[16];
    char plaintext[1024];
    size_t plaintext_len = 0;
    char ciphertext_file[256];
    char ciphertext_hex[2048];

    if (parse_input_file(input_file, key, iv, plaintext, &plaintext_len, ciphertext_file, ciphertext_hex, mode) != 0) {
        return 1;
    }

    // Initialize cipher context
    struct sosemanuk_context ctx;
    if (sosemanuk_set_key_and_iv(&ctx, key, 32, iv, 16)) {
        printf("Error: Failed to initialize cipher context\n");
        return 1;
    }

    if (mode == 0) {
        // Encrypt mode
        printf("Encrypting %zu bytes of plaintext...\n", plaintext_len);

        // Allocate output buffer
        uint8_t *ciphertext = (uint8_t*)malloc(plaintext_len);
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

        // Print hex for verification
        char hex_output[2049];
        bytes_to_hex(ciphertext, plaintext_len, hex_output);
        printf("Ciphertext (hex): %s\n", hex_output);

        free(ciphertext);

        printf("Encryption complete. Output written to: %s\n", output_file);

    } else if (mode == 1 || mode == 2) {
        // Decrypt from hex mode
        printf("Decrypting from hex ciphertext...\n");

        // Parse hex ciphertext
        uint8_t *ciphertext = (uint8_t*)malloc(strlen(ciphertext_hex) / 2);
        if (!ciphertext) {
            printf("Error: Memory allocation failed\n");
            return 1;
        }

        size_t ciphertext_len;
        if (hex_to_bytes(ciphertext_hex, ciphertext, strlen(ciphertext_hex) / 2, &ciphertext_len) != 0) {
            printf("Error: Invalid ciphertext hex format\n");
            free(ciphertext);
            return 1;
        }

        // Allocate output buffer
        uint8_t *decrypted = (uint8_t*)malloc(ciphertext_len);
        if (!decrypted) {
            printf("Error: Memory allocation failed\n");
            free(ciphertext);
            return 1;
        }

        // Decrypt
        sosemanuk_crypt(&ctx, ciphertext, ciphertext_len, decrypted);

        // Print recovered text
        printf("Recovered plaintext: ");
        for (size_t i = 0; i < ciphertext_len; i++) {
            if (isprint(decrypted[i])) {
                printf("%c", decrypted[i]);
            } else {
                printf("\\x%02X", decrypted[i]);
            }
        }
        printf("\n");

        free(ciphertext);
        free(decrypted);
    }

    return 0;
}

