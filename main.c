// This program tests the library sosemanuk.h

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>

#include "sosemanuk.h"

// Struct for time value
struct timeval t1, t2;

uint8_t key[32];
uint8_t iv[16];

static void
time_start(void)
{
	gettimeofday(&t1, NULL);
}

static uint32_t
time_stop(void)
{
	gettimeofday(&t2, NULL);

	t2.tv_sec -= t1.tv_sec;
	t2.tv_usec -= t1.tv_usec;

	if(t2.tv_usec < 0) {
		t2.tv_sec--;
		t2.tv_usec += 1000000;
	}

	return (t2.tv_sec * 1000 + t2.tv_usec/1000);
}

void hex_to_bytes(const char *hex, uint8_t *bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        sscanf(hex + 2 * i, "%2hhx", &bytes[i]);
    }
}

void bytes_to_hex(const uint8_t *bytes, size_t len, char *hex) {
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + 2 * i, "%02X", bytes[i]);
    }
    hex[2 * len] = '\0';
}

int
main()
{
	struct sosemanuk_context ctx;
	FILE *fp = fopen("test_vector.txt", "r");
	if (!fp) {
		perror("Cannot open test_vector.txt");
		exit(1);
	}

	char line[1024];
	int vector_count = 0;
	int pass_count = 0;
	uint32_t total_time = 0;

	while (fgets(line, sizeof(line), fp)) {
		if (strstr(line, "Test Vector")) {
			vector_count++;
			printf("\n=== Test Vector %d ===\n", vector_count);

			// Read Key
			fgets(line, sizeof(line), fp);
			char key_hex[65];
			sscanf(line, "Key: %64s", key_hex);
			hex_to_bytes(key_hex, key, 32);
			bytes_to_hex(key, 32, key_hex);
			printf("Key: %s\n", key_hex);

			// Read IV
			fgets(line, sizeof(line), fp);
			char iv_hex[33];
			sscanf(line, "IV: %32s", iv_hex);
			hex_to_bytes(iv_hex, iv, 16);
			bytes_to_hex(iv, 16, iv_hex);
			printf("IV: %s\n", iv_hex);

			// Skip Keystream
			fgets(line, sizeof(line), fp);

			// Read Plaintext
			fgets(line, sizeof(line), fp);
			char pt_hex[33];
			sscanf(line, "Plaintext: %32s", pt_hex);
			uint8_t plaintext[16];
			hex_to_bytes(pt_hex, plaintext, 16);
			printf("Plaintext (hex): %s\n", pt_hex);
			printf("Plaintext (text): %.*s\n", 16, plaintext);

			// Read Ciphertext expected
			fgets(line, sizeof(line), fp);
			char ct_hex[33];
			sscanf(line, "Ciphertext: %32s", ct_hex);
			uint8_t ct_expected[16];
			hex_to_bytes(ct_hex, ct_expected, 16);
			printf("Ciphertext Expected (hex): %s\n", ct_hex);
			printf("Ciphertext Expected (text): %.*s\n", 16, ct_expected);

			// Skip Recovered
			fgets(line, sizeof(line), fp);
			// Skip blank
			fgets(line, sizeof(line), fp);

			// Set key and IV for verification
			if (sosemanuk_set_key_and_iv(&ctx, key, 32, iv, 16)) {
				printf("Error setting key/iv for vector %d\n", vector_count);
				continue;
			}

			// Generate keystream and XOR for verification
			uint32_t keystream[20]; // 80 bytes
			sosemanuk_generate_keystream(&ctx, keystream);
			uint8_t keystream_bytes[80];
			memcpy(keystream_bytes, keystream, 80);
			char keystream_hex[161];
			bytes_to_hex(keystream_bytes, 80, keystream_hex);
			printf("Keystream: %s\n", keystream_hex);
			uint8_t ciphertext[16];
			for (int j = 0; j < 16; j++) {
				ciphertext[j] = plaintext[j] ^ keystream_bytes[j];
			}

			char computed_hex[33];
			bytes_to_hex(ciphertext, 16, computed_hex);
			printf("Ciphertext Computed (hex): %s\n", computed_hex);
			printf("Ciphertext Computed (text): %.*s\n", 16, ciphertext);

			// Compare ciphertext
			int cipher_passed = (memcmp(ciphertext, ct_expected, 16) == 0);
			if (cipher_passed) {
				pass_count++;
				printf("Ciphertext Result: PASS\n");
			} else {
				printf("Ciphertext Result: FAIL\n");
			}

			// Compute recovered plaintext
			uint8_t recovered[16];
			for (int j = 0; j < 16; j++) {
				recovered[j] = ciphertext[j] ^ keystream_bytes[j];
			}
			char recovered_hex[33];
			bytes_to_hex(recovered, 16, recovered_hex);
			printf("Recovered Plaintext Expected (hex): %s\n", pt_hex);
			printf("Recovered Plaintext Expected (text): %.*s\n", 16, plaintext);
			printf("Recovered Plaintext Computed (hex): %s\n", recovered_hex);
			printf("Recovered Plaintext Computed (text): %.*s\n", 16, recovered);

			// Compare recovered
			int recovered_passed = (memcmp(recovered, plaintext, 16) == 0);
			if (recovered_passed) {
				printf("Recovered Plaintext Result: PASS\n");
			} else {
				printf("Recovered Plaintext Result: FAIL\n");
			}

			// Overall result for vector
			if (cipher_passed && recovered_passed) {
				printf("Overall Result: PASS\n");
			} else {
				printf("Overall Result: FAIL\n");
			}

			// Measure time for multiple encryptions (reset context each time for fair timing)
			const int loops = 10000;
			time_start();
			for (int i = 0; i < loops; i++) {
				sosemanuk_set_key_and_iv(&ctx, key, 32, iv, 16);
				sosemanuk_generate_keystream(&ctx, keystream);
				memcpy(keystream_bytes, keystream, 80);
				for (int j = 0; j < 16; j++) {
					ciphertext[j] = plaintext[j] ^ keystream_bytes[j];
				}
			}
			uint32_t time_ms = time_stop();
			total_time += time_ms;

			// Performance
			size_t total_bytes = (size_t)loops * 16;
			double time_sec = time_ms / 1000.0;
			double mbps = (total_bytes / (1024.0 * 1024.0)) / time_sec;
			printf("Time for %d encryptions: %u ms\n", loops, time_ms);
			printf("Throughput: %.2f MB/s\n", mbps);
		}
	}

	fclose(fp);

	printf("\n=== Summary ===\n");
	printf("Total vectors: %d\n", vector_count);
	printf("Passed: %d\n", pass_count);
	printf("Failed: %d\n", vector_count - pass_count);
	printf("Total time: %u ms\n", total_time);
	if (total_time > 0) {
		size_t total_bytes = (size_t)vector_count * 10000 * 16;
		double time_sec = total_time / 1000.0;
		double mbps = (total_bytes / (1024.0 * 1024.0)) / time_sec;
		printf("Overall Throughput: %.2f MB/s\n", mbps);
	}

	return 0;
}
