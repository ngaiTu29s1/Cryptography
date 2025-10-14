#include "components.h"
#include <iostream>
#include <vector>

int main(){
    using namespace sose_sim;

    const std::string plain = "Hello from Sose-like simulator (EDU)!";
    const uint8_t key[16] = {
        0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B, 0x0C,0x0D,0x0E,0x0F
    };
    const uint8_t iv[16] = {
        0xA0,0xA1,0xA2,0xA3, 0xA4,0xA5,0xA6,0xA7,
        0xA8,0xA9,0xAA,0xAB, 0xAC,0xAD,0xAE,0xAF
    };

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
