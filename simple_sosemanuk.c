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

#define KEY_SIZE 32
#define IV_SIZE 16
#define MAX_LINE_SIZE 1024
#define MAX_PLAINTEXT_SIZE 1024
#define MAX_CIPHERTEXT_HEX_SIZE 2048
#define MAX_FILENAME_SIZE 256

typedef enum {
    MODE_ENCRYPT = 0,
    MODE_DECRYPT_FILE = 1,
    MODE_DECRYPT_HEX = 2
} operation_mode_t;

typedef struct {
    uint8_t key[KEY_SIZE];
    uint8_t iv[IV_SIZE];
    char plaintext[MAX_PLAINTEXT_SIZE];
    size_t plaintext_len;
    char ciphertext_file[MAX_FILENAME_SIZE];
    char ciphertext_hex[MAX_CIPHERTEXT_HEX_SIZE];
} crypto_params_t;

// Function to convert hex string to bytes
int hex_to_bytes(const char *hex, uint8_t *bytes, size_t max_len, size_t *out_len) {
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) {
        return -1;
    }

    *out_len = hex_len / 2;
    if (*out_len > max_len) {
        return -1;
    }

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

// Check if string is valid hexadecimal
int is_valid_hex(const char *str, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (!isxdigit((unsigned char)str[i])) {
            return 0;
        }
    }
    return 1;
}

// Parse key from line
int parse_key(const char *line, uint8_t *key) {
    char key_hex[65] = {0};
    if (sscanf(line, "key=%64s", key_hex) != 1) {
        return -1;
    }
    
    size_t key_len;
    if (hex_to_bytes(key_hex, key, KEY_SIZE, &key_len) != 0 || key_len != KEY_SIZE) {
        fprintf(stderr, "Error: Invalid key format (must be 32 bytes hex)\n");
        return -1;
    }
    return 0;
}

// Parse IV from line
int parse_iv(const char *line, uint8_t *iv) {
    char iv_hex[33] = {0};
    if (sscanf(line, "iv=%32s", iv_hex) != 1) {
        return -1;
    }
    
    size_t iv_len;
    if (hex_to_bytes(iv_hex, iv, IV_SIZE, &iv_len) != 0 || iv_len != IV_SIZE) {
        fprintf(stderr, "Error: Invalid IV format (must be 16 bytes hex)\n");
        return -1;
    }
    return 0;
}

// Parse plaintext from line (for encryption)
int parse_plaintext(const char *line, char *plaintext, size_t *plaintext_len) {
    char *ptr = strstr(line, "plaintext=");
    if (!ptr) {
        return -1;
    }
    ptr += 10; // Skip "plaintext="
    
    // Remove newline
    ptr[strcspn(ptr, "\n")] = '\0';
    
    size_t hex_len = strlen(ptr);
    
    // Try to parse as hex first
    if (hex_len % 2 == 0 && hex_len > 0 && is_valid_hex(ptr, hex_len)) {
        if (hex_to_bytes(ptr, (uint8_t*)plaintext, MAX_PLAINTEXT_SIZE, plaintext_len) != 0) {
            fprintf(stderr, "Error: Invalid plaintext hex format\n");
            return -1;
        }
        plaintext[*plaintext_len] = '\0';
    } else {
        // Treat as plain text
        strncpy(plaintext, ptr, MAX_PLAINTEXT_SIZE - 1);
        plaintext[MAX_PLAINTEXT_SIZE - 1] = '\0';
        *plaintext_len = strlen(plaintext);
    }
    
    return 0;
}

// Parse ciphertext from line (for decryption)
int parse_ciphertext(const char *line, char *ciphertext_hex) {
    char *ptr = strstr(line, "ciphertext=");
    if (!ptr) {
        return -1;
    }
    ptr += 11; // Skip "ciphertext="
    
    // Remove newline
    ptr[strcspn(ptr, "\n")] = '\0';
    
    strncpy(ciphertext_hex, ptr, MAX_CIPHERTEXT_HEX_SIZE - 1);
    ciphertext_hex[MAX_CIPHERTEXT_HEX_SIZE - 1] = '\0';
    
    return 0;
}

// Function to read input file and parse parameters
int parse_input_file(const char *filename, crypto_params_t *params, operation_mode_t mode) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("Cannot open input file");
        return -1;
    }

    char line[MAX_LINE_SIZE];
    int has_key = 0, has_iv = 0, has_data = 0;

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "key=")) {
            if (parse_key(line, params->key) == 0) {
                has_key = 1;
            } else {
                fclose(fp);
                return -1;
            }
        } else if (strstr(line, "iv=")) {
            if (parse_iv(line, params->iv) == 0) {
                has_iv = 1;
            } else {
                fclose(fp);
                return -1;
            }
        } else if (mode == MODE_ENCRYPT && strstr(line, "plaintext=")) {
            if (parse_plaintext(line, params->plaintext, &params->plaintext_len) == 0) {
                has_data = 1;
            } else {
                fclose(fp);
                return -1;
            }
        } else if ((mode == MODE_DECRYPT_FILE || mode == MODE_DECRYPT_HEX) && strstr(line, "ciphertext=")) {
            if (parse_ciphertext(line, params->ciphertext_hex) == 0) {
                has_data = 1;
            } else {
                fclose(fp);
                return -1;
            }
        }
    }

    fclose(fp);
    
    // Validate required fields
    if (!has_key || !has_iv || !has_data) {
        fprintf(stderr, "Error: Missing required fields in input file\n");
        return -1;
    }

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
    printf("Input file format for decryption from hex:\n");
    printf("  key=<32_byte_hex_key>\n");
    printf("  iv=<16_byte_hex_iv>\n");
    printf("  ciphertext=<hex_data>\n\n");
    printf("Examples:\n");
    printf("  %s -e encrypt_input.txt message.enc\n", program_name);
    printf("  %s -d decrypt_input.txt\n", program_name);
    printf("  %s -h hex_decrypt_input.txt\n", program_name);
}

// Perform encryption
int perform_encryption(crypto_params_t *params, const char *output_file) {
    struct sosemanuk_context ctx;
    
    if (sosemanuk_set_key_and_iv(&ctx, params->key, KEY_SIZE, params->iv, IV_SIZE)) {
        fprintf(stderr, "Error: Failed to initialize cipher context\n");
        return -1;
    }

    printf("Encrypting %zu bytes of plaintext...\n", params->plaintext_len);

    uint8_t *ciphertext = (uint8_t*)malloc(params->plaintext_len);
    if (!ciphertext) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        return -1;
    }

    sosemanuk_crypt(&ctx, (uint8_t*)params->plaintext, params->plaintext_len, ciphertext);

    FILE *fp = fopen(output_file, "wb");
    if (!fp) {
        perror("Cannot open output file");
        free(ciphertext);
        return -1;
    }

    fwrite(ciphertext, 1, params->plaintext_len, fp);
    fclose(fp);

    // Print hex for verification
    char *hex_output = (char*)malloc(params->plaintext_len * 2 + 1);
    if (hex_output) {
        bytes_to_hex(ciphertext, params->plaintext_len, hex_output);
        printf("Ciphertext (hex): %s\n", hex_output);
        free(hex_output);
    }

    free(ciphertext);
    printf("Encryption complete. Output written to: %s\n", output_file);

    return 0;
}

// Perform decryption
int perform_decryption(crypto_params_t *params) {
    struct sosemanuk_context ctx;
    
    if (sosemanuk_set_key_and_iv(&ctx, params->key, KEY_SIZE, params->iv, IV_SIZE)) {
        fprintf(stderr, "Error: Failed to initialize cipher context\n");
        return -1;
    }

    printf("Decrypting from hex ciphertext...\n");

    size_t max_ciphertext_len = strlen(params->ciphertext_hex) / 2;
    uint8_t *ciphertext = (uint8_t*)malloc(max_ciphertext_len);
    if (!ciphertext) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        return -1;
    }

    size_t ciphertext_len;
    if (hex_to_bytes(params->ciphertext_hex, ciphertext, max_ciphertext_len, &ciphertext_len) != 0) {
        fprintf(stderr, "Error: Invalid ciphertext hex format\n");
        free(ciphertext);
        return -1;
    }

    uint8_t *decrypted = (uint8_t*)malloc(ciphertext_len);
    if (!decrypted) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        free(ciphertext);
        return -1;
    }

    sosemanuk_crypt(&ctx, ciphertext, ciphertext_len, decrypted);

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

    return 0;
}

int main(int argc, char *argv[]) {
    operation_mode_t mode;
    char *input_file = NULL;
    char *output_file = NULL;

    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }

    // Parse command line arguments
    if (strcmp(argv[1], "-e") == 0) {
        if (argc != 4) {
            print_usage(argv[0]);
            return 1;
        }
        mode = MODE_ENCRYPT;
        input_file = argv[2];
        output_file = argv[3];
    } else if (strcmp(argv[1], "-d") == 0 || strcmp(argv[1], "-h") == 0) {
        if (argc != 3) {
            print_usage(argv[0]);
            return 1;
        }
        mode = (strcmp(argv[1], "-d") == 0) ? MODE_DECRYPT_FILE : MODE_DECRYPT_HEX;
        input_file = argv[2];
    } else {
        print_usage(argv[0]);
        return 1;
    }

    // Parse input file
    crypto_params_t params = {0};
    if (parse_input_file(input_file, &params, mode) != 0) {
        return 1;
    }

    // Perform operation
    int result;
    if (mode == MODE_ENCRYPT) {
        result = perform_encryption(&params, output_file);
    } else {
        result = perform_decryption(&params);
    }

    return result;
}
