#ifndef IO_HANDLER_H
#define IO_HANDLER_H

#include <string>
#include <vector>
#include <cstdint>

#include <tuple>
#include <fstream>

// Function to handle input for key and IV
void handle_input(const std::string& prompt, uint8_t* output, size_t size);

// Structure to hold test vector data
struct TestVector {
    std::string plaintext;      // Fixed input
    std::string key;            // Fixed input
    std::string iv;             // Fixed input
    std::string expected_ciphertext;  // Expected output for validation
    std::string expected_recovered;   // Expected output for validation
};

// Function to read test vectors from a TXT file
std::vector<TestVector> read_test_vectors(const std::string& file_path);

// Function to convert hex string to byte array
void hex_to_bytes(const std::string& hex_str, uint8_t* output, size_t size);

// Function to convert byte array to hex string
std::string bytes_to_hex(const uint8_t* bytes, size_t size);

#endif // IO_HANDLER_H