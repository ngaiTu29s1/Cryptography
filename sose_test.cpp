#include <cryptopp/cryptlib.h>
#include <cryptopp/secblock.h>
#include <cryptopp/sosemanuk.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>

#include <iostream>
#include <string>

int main()
{
    using namespace CryptoPP;

    AutoSeededRandomPool prng;
    HexEncoder encoder(new FileSink(std::cout));
    std::string plain("Sosemanuk stream cipher test"), cipher, recover;

    SecByteBlock key(16), iv(16);
    prng.GenerateBlock(key, key.size());
    prng.GenerateBlock(iv, iv.size());

    std::cout << "Key: ";
    encoder.Put((const byte*)key.data(), key.size());
    encoder.MessageEnd();
    std::cout << std::endl;

    std::cout << "IV: ";
    encoder.Put((const byte*)iv.data(), iv.size());
    encoder.MessageEnd();
    std::cout << std::endl;

    // Encryption object
    Sosemanuk::Encryption enc;    
    enc.SetKeyWithIV(key, key.size(), iv, iv.size());

    // Perform the encryption
    cipher.resize(plain.size());
    enc.ProcessData((byte*)&cipher[0], (const byte*)plain.data(), plain.size());

    std::cout << "Plain: " << plain << std::endl;

    std::cout << "Cipher: ";
    encoder.Put((const byte*)cipher.data(), cipher.size());
    encoder.MessageEnd();
    std::cout << std::endl;

    // Sosemanuk::Decryption dec;
    // dec.SetKeyWithIV(key, key.size(), iv, iv.size());

    std::cout << "Self inverting: " << enc.IsSelfInverting() << std::endl;
    std::cout << "Resynchronizable: " << enc.IsResynchronizable() << std::endl;

    enc.Resynchronize(iv, iv.size());

    // Perform the decryption
    // recover.resize(cipher.size());
    // dec.ProcessData((byte*)&recover[0], (const byte*)cipher.data(), cipher.size());

    // Perform the decryption with the encryptor
    recover.resize(cipher.size());
    enc.ProcessData((byte*)&recover[0], (const byte*)cipher.data(), cipher.size());

    std::cout << "Recovered: " << recover << std::endl;

    return 0;
}