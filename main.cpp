#include "components.h"
#include "components/io_handler.h"
#include <iostream>
#include <vector>
#include <sstream> // For std::istringstream
#include <algorithm> // For std::remove

int main(){
    using namespace sose_sim;

    std::cout << "=== Batch Test Vectors Processing ===\n";
    
    try {
        auto test_vectors = read_test_vectors("test_vectors/test_data.txt");
        
        for (size_t i = 0; i < test_vectors.size(); i++) {
            const auto& tv = test_vectors[i];
            std::cout << "\n--- Test Vector " << (i + 1) << " ---\n";
            
            uint8_t key[16] = {0};
            uint8_t iv[16] = {0};
            
            hex_to_bytes(tv.key, key, 16);
            hex_to_bytes(tv.iv, iv, 16);
            
            // Encryption
            State st_enc{};
            init_state_from_key_iv(st_enc, key, sizeof(key), iv, sizeof(iv));
            
            std::vector<uint8_t> ks(tv.plaintext.size());
            generate_keystream(st_enc, ks.data(), ks.size());
            
            std::vector<uint8_t> cipher(tv.plaintext.begin(), tv.plaintext.end());
            xor_in_place(cipher.data(), ks.data(), cipher.size());
            
            // Decryption
            State st_dec{};
            init_state_from_key_iv(st_dec, key, sizeof(key), iv, sizeof(iv));
            std::vector<uint8_t> ks2(cipher.size());
            generate_keystream(st_dec, ks2.data(), ks2.size());
            
            std::vector<uint8_t> recover = cipher;
            xor_in_place(recover.data(), ks2.data(), recover.size());
            std::string recovered(recover.begin(), recover.end());
            
            std::cout << "PLAINTEXT : " << tv.plaintext << "\n";
            std::cout << "KEY       : " << tv.key << "\n";
            std::cout << "IV        : " << tv.iv << "\n";
            std::cout << "KEYSTREAM : " << to_hex(ks.data(), ks.size()) << "\n";
            std::cout << "CIPHERTEXT: " << to_hex(cipher.data(), cipher.size()) << "\n";
            std::cout << "RECOVERED : " << recovered << "\n";
            
            // Check expected values if available and not empty
            if (!tv.expected_ciphertext.empty()) {
                std::string actual_cipher = to_hex(cipher.data(), cipher.size());
                // Remove spaces for comparison
                std::string expected_clean = tv.expected_ciphertext;
                std::string actual_clean = actual_cipher;
                expected_clean.erase(std::remove(expected_clean.begin(), expected_clean.end(), ' '), expected_clean.end());
                actual_clean.erase(std::remove(actual_clean.begin(), actual_clean.end(), ' '), actual_clean.end());
                
                bool cipher_match = (actual_clean == expected_clean);
                std::cout << "CIPHER CHK: " << (cipher_match ? "[OK]" : "[FAIL]") << 
                             " (expected: " << tv.expected_ciphertext << ")\n";
            } else {
                std::cout << "CIPHER CHK: [SKIP] (no expected value)\n";
            }
            
            if (!tv.expected_recovered.empty()) {
                bool recover_match = (recovered == tv.expected_recovered);
                std::cout << "RECOVER CHK: " << (recover_match ? "[OK]" : "[FAIL]") << 
                             " (expected: " << tv.expected_recovered << ")\n";
            } else {
                std::cout << "RECOVER CHK: [SKIP] (no expected value)\n";
            }
        }
        
    } catch (const std::exception& e) {
        std::cout << "Error reading test vectors: " << e.what() << "\n";
    }
    return 0;
}
