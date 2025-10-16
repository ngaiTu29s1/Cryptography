#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include "../components/components.h"
#include "../components/io_handler.h"

using namespace sose_sim;

struct TestInput {
    std::string plaintext;
    std::string key;
    std::string iv;
};

// Parse input file format: plaintext|key|iv per line
std::vector<TestInput> parse_input_file(const std::string& filename) {
    std::vector<TestInput> inputs;
    std::ifstream file(filename);
    
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open input file: " + filename);
    }
    
    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;
        
        std::stringstream ss(line);
        std::string plaintext, key, iv;
        
        if (std::getline(ss, plaintext, '|') && 
            std::getline(ss, key, '|') && 
            std::getline(ss, iv)) {
            inputs.push_back({plaintext, key, iv});
        }
    }
    
    file.close();
    return inputs;
}

// Generate test vector from input
void generate_test_vector(const TestInput& input, std::ofstream& output) {
    try {
        // Parse key and IV from hex strings
        uint8_t key_bytes[16] = {0};
        uint8_t iv_bytes[16] = {0};
        
        hex_to_bytes(input.key, key_bytes, 16);
        hex_to_bytes(input.iv, iv_bytes, 16);
        
        // Initialize cipher state
        State st;
        init_state_from_key_iv(st, key_bytes, 16, iv_bytes, 16);
        
        // Generate keystream
        std::vector<uint8_t> keystream(input.plaintext.size());
        generate_keystream(st, keystream.data(), keystream.size());
        
        // Encrypt plaintext
        std::vector<uint8_t> plaintext_bytes(input.plaintext.begin(), input.plaintext.end());
        std::vector<uint8_t> ciphertext = plaintext_bytes;
        xor_in_place(ciphertext.data(), keystream.data(), ciphertext.size());
        
        // Output in test_data.txt format
        output << "plaintext=" << input.plaintext << "\n";
        output << "key=" << input.key << "\n";
        output << "iv=" << input.iv << "\n";
        output << "keystream=" << bytes_to_hex(keystream.data(), keystream.size()) << "\n";
        output << "expected_ciphertext=" << bytes_to_hex(ciphertext.data(), ciphertext.size()) << "\n";
        output << "expected_recovered=" << input.plaintext << "\n";
        output << "---\n";
        
        std::cout << "Generated test vector for: \"" << input.plaintext << "\"\n";
        
    } catch (const std::exception& e) {
        std::cerr << "Error generating test vector: " << e.what() << "\n";
    }
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cout << "Usage: " << argv[0] << " <input_file> <output_file>\n\n";
        std::cout << "Input file format (pipe-separated):\n";
        std::cout << "plaintext|key|iv\n";
        std::cout << "Example:\n";
        std::cout << "Hello World|00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF|FF EE DD CC BB AA 99 88 77 66 55 44 33 22 11 00\n";
        std::cout << "\nOutput: test_data.txt compatible format\n";
        return 1;
    }
    
    std::string input_file = argv[1];
    std::string output_file = argv[2];
    
    try {
        // Parse input
        auto inputs = parse_input_file(input_file);
        std::cout << "Found " << inputs.size() << " test inputs\n\n";
        
        // Generate output
        std::ofstream output(output_file);
        if (!output.is_open()) {
            throw std::runtime_error("Cannot create output file: " + output_file);
        }
        
        output << "# Test vectors for Sosemanuk implementation\n";
        output << "# Format: field=value, separated by --- for each test case\n";
        output << "# Auto-generated from input file: " << input_file << "\n\n";
        
        for (const auto& input : inputs) {
            generate_test_vector(input, output);
        }
        
        output.close();
        std::cout << "\n✅ Test vectors generated successfully in: " << output_file << "\n";
        
    } catch (const std::exception& e) {
        std::cerr << "❌ Error: " << e.what() << "\n";
        return 1;
    }
    
    return 0;
}