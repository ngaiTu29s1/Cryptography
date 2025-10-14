#include "components.h"
#include "components/io_handler.h"
#include <iostream>
#include <vector>
#include <sstream> // For std::istringstream

int main(){
    using namespace sose_sim;

    std::string plain;
    std::cout << "Enter plaintext: ";
    std::getline(std::cin, plain);
    char raw_key[16] = {0}, raw_iv[16] = {0};
    uint8_t key[16] = {0};
    uint8_t iv[16] = {0};

    std::cout << "=== Encryption ===\n";

    // Dev only
    handle_input("Enter key (16 bytes hex): \n Sample: 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n> ", key, 16);
    handle_input("Enter IV (16 bytes hex): \n Sample: 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n> ", iv, 16);

    std::cout << "Key: " << to_hex(key, sizeof(key)) << "\n";

    State st_enc{};
    init_state_from_key_iv(st_enc, key, sizeof(key), iv, sizeof(iv));

    std::vector<uint8_t> ks(plain.size());
    generate_keystream(st_enc, ks.data(), ks.size());

    std::vector<uint8_t> cipher(plain.begin(), plain.end());
    xor_in_place(cipher.data(), ks.data(), cipher.size());

    std::cout << "PLAINTEXT : " << plain << "\n";
    std::cout << "KEY       : " << to_hex(key, sizeof(key)) << "\n";
    std::cout << "IV        : " << to_hex(iv, sizeof(iv)) << "\n";
    std::cout << "KEYSTREAM : " << to_hex(ks.data(), ks.size()) << "\n";
    std::cout << "CIPHERTEXT: " << to_hex(cipher.data(), cipher.size()) << "\n";

    // decrypt (resync)
    State st_dec{};
    init_state_from_key_iv(st_dec, key, sizeof(key), iv, sizeof(iv));
    std::vector<uint8_t> ks2(cipher.size());
    generate_keystream(st_dec, ks2.data(), ks2.size());

    std::vector<uint8_t> recover = cipher;
    xor_in_place(recover.data(), ks2.data(), recover.size());
    std::string recovered(recover.begin(), recover.end());

    std::cout << "RECOVERED : " << recovered << "\n";
    std::cout << ((recovered == plain) ? "[OK] decrypt matched\n" : "[FAIL] mismatch\n");
    return 0;
}
