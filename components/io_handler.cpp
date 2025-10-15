#include "io_handler.h"
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <iomanip>

void handle_input(const std::string& prompt, uint8_t* output, size_t size) {
    std::cout << prompt;
    std::string input;
    std::getline(std::cin, input); // Read the entire line
    std::istringstream stream(input);
    for (size_t i = 0; i < size; i++) {
        unsigned int byte;
        stream >> std::hex >> byte; // Parse each hex value
        output[i] = static_cast<uint8_t>(byte);
    }
}

std::vector<TestVector> read_test_vectors(const std::string& file_path) {
    std::vector<TestVector> test_vectors;
    std::ifstream file(file_path);

    if (!file.is_open()) {
        throw std::runtime_error("Could not open file: " + file_path);
    }

    std::string line;
    TestVector current_vector;
    
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') {
            continue; // Skip empty lines or comments
        }

        if (line == "---") {
            // End of current test vector
            if (!current_vector.plaintext.empty()) {
                test_vectors.push_back(current_vector);
                current_vector = TestVector{}; // Reset for next vector
            }
            continue;
        }

        size_t pos = line.find('=');
        if (pos != std::string::npos) {
            std::string field = line.substr(0, pos);
            std::string value = line.substr(pos + 1);

            if (field == "plaintext") {
                current_vector.plaintext = value;
            } else if (field == "key") {
                current_vector.key = value;
            } else if (field == "iv") {
                current_vector.iv = value;
            } else if (field == "expected_ciphertext") {
                current_vector.expected_ciphertext = value;
            } else if (field == "expected_recovered") {
                current_vector.expected_recovered = value;
            }
        }
    }

    // Add the last vector if it exists
    if (!current_vector.plaintext.empty()) {
        test_vectors.push_back(current_vector);
    }

    file.close();
    return test_vectors;
}

void hex_to_bytes(const std::string& hex_str, uint8_t* output, size_t size) {
    std::istringstream stream(hex_str);
    for (size_t i = 0; i < size; i++) {
        unsigned int byte;
        stream >> std::hex >> byte;
        output[i] = static_cast<uint8_t>(byte);
    }
}

std::string bytes_to_hex(const uint8_t* bytes, size_t size) {
    std::ostringstream stream;
    for (size_t i = 0; i < size; i++) {
        if (i > 0) stream << " ";
        stream << std::hex << std::uppercase << std::setfill('0') << std::setw(2) 
               << static_cast<unsigned int>(bytes[i]);
    }
    return stream.str();
}