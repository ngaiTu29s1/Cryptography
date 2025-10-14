#include "io_handler.h"
#include <iostream>
#include <sstream>

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