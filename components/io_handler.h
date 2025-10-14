#ifndef IO_HANDLER_H
#define IO_HANDLER_H

#include <string>
#include <vector>
#include <cstdint>

// Function to handle input for key and IV
void handle_input(const std::string& prompt, uint8_t* output, size_t size);

#endif // IO_HANDLER_H