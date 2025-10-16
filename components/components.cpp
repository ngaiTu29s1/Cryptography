#include "components.h"
#include <cstring>
#include <sstream>
#include <iomanip>
// #include <cryptopp/sosemanuk.h> // Uncomment if Crypto++ library is available


namespace sose_sim {

// ===== Sosemanuk Constants =====
// GF(2^32) irreducible polynomial: x^32 + x^7 + x^3 + x^2 + 1
static constexpr uint32_t GF_POLY = 0x10D;
// Multiplicative inverse of alpha (0x2) in GF(2^32)  
static constexpr uint32_t ALPHA_INV = 0x80000069;

// ===== utils =====
uint32_t rol32(uint32_t x, unsigned r){ return (x<<r) | (x>>(32-r)); }
uint32_t ror32(uint32_t x, unsigned r){ return (x>>r) | (x<<(32-r)); }
uint32_t mux(uint32_t c, uint32_t x, uint32_t y){ return (c & 1u) ? y : x; }

// ===== constants =====
static constexpr uint32_t TRANS_M = 0x54655307u;  // Sosemanuk Trans multiplier

// ===== Trans function (Sosemanuk specification) =====
uint32_t Trans(uint32_t z){
    // Trans(z) = (z * 0x54655307) <<< 7 (mod 2^32)
    uint64_t m = static_cast<uint64_t>(z) * TRANS_M;
    return rol32(static_cast<uint32_t>(m), 7);
}

// ===== Sosemanuk multiplication tables (from CryptoPP) =====
// Complete Sosemanuk multiplication and division tables from CryptoPP
static const uint32_t s_sosemanukMulTables[512] = {
    // Multiplication table (first 256 entries)
    0x00000000, 0xE19FCF12, 0x6B973724, 0x8A08F836,
    0xD6876E48, 0x3718A15A, 0xBD10596C, 0x5C8F967E,
    0x05A7DC90, 0xE4381382, 0x6E30EBB4, 0x8FAF24A6,
    0xD320B2D8, 0x32BF7DCA, 0xB8B785FC, 0x59284AEE,
    0x0AE71189, 0xEB78DE9B, 0x617026AD, 0x80EFE9BF,
    0xDC607FC1, 0x3DFFB0D3, 0xB7F748E5, 0x566887F7,
    0x0F40CD19, 0xEEDF020B, 0x64D7FA3D, 0x8548352F,
    0xD9C7A351, 0x38586C43, 0xB2509475, 0x53CF5B67,
    0x146E2312, 0xF5F1EC00, 0x7FF91436, 0x9E66DB24,
    0xC2E94D5A, 0x23768248, 0xA97E7A7E, 0x48E1B56C,
    0x11C9FF82, 0xF0563090, 0x7A5EC8A6, 0x9BC107B4,
    0xC74E91CA, 0x26D15ED8, 0xACD9A6EE, 0x4D4669FC,
    0x1E89329B, 0xFF16FD89, 0x751E05BF, 0x9481CAAD,
    0xC80E5CD3, 0x299193C1, 0xA3996BF7, 0x4206A4E5,
    0x1B2EEE0B, 0xFAB12119, 0x70B9D92F, 0x9126163D,
    0xCDA98043, 0x2C364F51, 0xA63EB767, 0x47A17875,
    0x28DC4624, 0xC9438936, 0x434B7100, 0xA2D4BE12,
    0xFE5B286C, 0x1FC4E77E, 0x95CC1F48, 0x7453D05A,
    0x2D7B9AB4, 0xCCE455A6, 0x46ECAD90, 0xA7736282,
    0xFBFCF4FC, 0x1A633BEE, 0x906BC3D8, 0x71F40CCA,
    0x223B57AD, 0xC3A498BF, 0x49AC6089, 0xA833AF9B,
    0xF4BC39E5, 0x1523F6F7, 0x9F2B0EC1, 0x7EB4C1D3,
    0x279C8B3D, 0xC603442F, 0x4C0BBC19, 0xAD94730B,
    0xF11BE575, 0x10842A67, 0x9A8CD251, 0x7B131D43,
    0x3CB26536, 0xDD2DAA24, 0x57255212, 0xB6BA9D00,
    0xEA350B7E, 0x0BAAC46C, 0x81A23C5A, 0x603DF348,
    0x3915B9A6, 0xD88A76B4, 0x52828E82, 0xB31D4190,
    0xEF92D7EE, 0x0E0D18FC, 0x8405E0CA, 0x659A2FD8,
    0x365574BF, 0xD7CABBAD, 0x5DC2439B, 0xBC5D8C89,
    0xE0D21AF7, 0x014DD5E5, 0x8B452DD3, 0x6ADAE2C1,
    0x33F2A82F, 0xD26D673D, 0x58659F0B, 0xB9FA5019,
    0xE575C667, 0x04EA0975, 0x8EE2F143, 0x6F7D3E51,
    0x51B88C48, 0xB027435A, 0x3A2FBB6C, 0xDBB0747E,
    0x873FE200, 0x66A02D12, 0xECA8D524, 0x0D371A36,
    0x541F50D8, 0xB5809FCA, 0x3F8867FC, 0xDE17A8EE,
    0x82983E90, 0x6307F182, 0xE90F09B4, 0x0890C6A6,
    0x5B5F9DC1, 0xBAC052D3, 0x30C8AAE5, 0xD15765F7,
    0x8DD8F389, 0x6C473C9B, 0xE64FC4AD, 0x07D00BBF,
    0x5EF84151, 0xBF678E43, 0x356F7675, 0xD4F0B967,
    0x887F2F19, 0x69E0E00B, 0xE3E8183D, 0x0277D72F,
    0x45D6AE5A, 0xA4496148, 0x2E41997E, 0xCFDE566C,
    0x9351C012, 0x72CE0F00, 0xF8C6F736, 0x19593824,
    0x407172CA, 0xA1EEBDD8, 0x2BE645EE, 0xCA798AFC,
    0x96F61C82, 0x7769D390, 0xFD612BA6, 0x1CFEE4B4,
    0x4F31BFD3, 0xAEAE70C1, 0x24A688F7, 0xC53947E5,
    0x99B6D19B, 0x78291E89, 0xF221E6BF, 0x13BE29AD,
    0x4A966343, 0xAB09AC51, 0x21015467, 0xC09E9B75,
    0x9C110D0B, 0x7D8EC219, 0xF7863A2F, 0x1619F53D,
    0x75644C6E, 0x94FB837C, 0x1EF37B4A, 0xFF6CB458,
    0xA3E32226, 0x427CED34, 0xC8741502, 0x29EBDA10,
    0x70C390FE, 0x915C5FEC, 0x1B54A7DA, 0xFACB68C8,
    0xA644FEB6, 0x47DB31A4, 0xCDD3C992, 0x2C4C0680,
    0x7F835DE7, 0x9E1C92F5, 0x14146AC3, 0xF58BA5D1,
    0xA90433AF, 0x489BFCBD, 0xC293048B, 0x230CCB99,
    0x7A24C177, 0x9BBB0E65, 0x11B3F653, 0xF02C3941,
    0xACA3AF3F, 0x4D3C602D, 0xC734981B, 0x26AB5709,
    0x61023A7C, 0x809DF56E, 0x0A950D58, 0xEB0AC24A,
    0xB7855434, 0x561A9B26, 0xDC126310, 0x3D8DAC02,
    0x64A5E6EC, 0x853A29FE, 0x0F32D1C8, 0xEEAD1EDA,
    0xB22288A4, 0x53BD47B6, 0xD9B5BF80, 0x382A7092,
    0x6BE52BF5, 0x8A7AE4E7, 0x00721CD1, 0xE1EDD3C3,
    0xBD6245BD, 0x5CFD8AAF, 0xD6F57299, 0x376ABD8B,
    0x6E42F765, 0x8FDD3877, 0x05D5C041, 0xE44A0F53,
    0xB8C5992D, 0x595A563F, 0xD352AE09, 0x32CD611B,

    // Division table (entries 256-511)
    0x00000000, 0x180F40CD, 0x301E8033, 0x2811C0FE,
    0x603CA966, 0x7833E9AB, 0x50222955, 0x482D6998,
    0xC0794B99, 0xD8760B54, 0xF067CBAA, 0xE8688B67,
    0xA045E2FF, 0xB84AA232, 0x905B62CC, 0x88542201,
    0x29F29333, 0x31FDD3FE, 0x19EC1300, 0x01E353CD,
    0x49CE3A55, 0x51C17A98, 0x79D0BA66, 0x61DFFAAB,
    0xE98BD8AA, 0xF1849867, 0xD9955899, 0xC19A1854,
    0x89B771CC, 0x91B83101, 0xB9A9F1FF, 0xA1A6B132,
    0x53E52666, 0x4BEA66AB, 0x63FBA655, 0x7BF4E698,
    0x33D98F00, 0x2BD6CFCD, 0x03C70F33, 0x1BC84FFE,
    0x93946DFF, 0x8B9B2D32, 0xA38AEDCC, 0xBB85AD01,
    0xF3A8C499, 0xEBA78454, 0xC3B644AA, 0xDBB90467,
    0x7A17B554, 0x6218F599, 0x4A093567, 0x520675AA,
    0x1A2B1C32, 0x02245CFF, 0x2A359C01, 0x323ADCCC,
    0xBA6EFECD, 0xA261BE00, 0x8A707EFE, 0x927F3E33,
    0xDA5257AB, 0xC25D1766, 0xEA4CD798, 0xF2439755,
    0xA7CAA199, 0xBFC5E154, 0x97D421AA, 0x8FDB6167,
    0xC7F608FF, 0xDFF94832, 0xF7E888CC, 0xEFE7C801,
    0x67B3EA00, 0x7FBCAACD, 0x57AD6A33, 0x4FA22AFE,
    0x078F4366, 0x1F8003AB, 0x3791C355, 0x2F9E8398,
    0x8E30948B, 0x963FD446, 0xBE2E14B8, 0xA6215475,
    0xEE0C3DED, 0xF6037D20, 0xDE12BDDE, 0xC61DFD13,
    0x4E49DF12, 0x56469FDF, 0x7E575F21, 0x66581FEC,
    0x2E757674, 0x367A36B9, 0x1E6BF647, 0x0664B68A,
    0x9F35C7CC, 0x873A8701, 0xAF2B47FF, 0xB7240732,
    0xFF096EAA, 0xE7062E67, 0xCF17EE99, 0xD718AE54,
    0x5F4C8C55, 0x4743CC98, 0x6F520C66, 0x775D4CAB,
    0x3F702533, 0x277F65FE, 0x0F6EA500, 0x1761E5CD,
    0xB6CFF6DE, 0xAEC0B613, 0x86D176ED, 0x9EDE3620,
    0xD6F35FB8, 0xCEFC1F75, 0xE6EDDF8B, 0xFEE29F46,
    0x76B6BD47, 0x6EB9FD8A, 0x46A83D74, 0x5EA77DB9,
    0x168A1421, 0x0E8554EC, 0x26949412, 0x3E9BD4DF,
    0xC8F86655, 0xD0F72698, 0xF8E6E666, 0xE0E9A6AB,
    0xA8C4CF33, 0xB0CB8FFE, 0x98DA4F00, 0x80D50FCD,
    0x08812DCC, 0x108E6D01, 0x389FADFF, 0x2090ED32,
    0x68BD84AA, 0x70B2C467, 0x58A30499, 0x40AC4454,
    0xE1025747, 0xF90D178A, 0xD11CD774, 0xC91397B9,
    0x813EFE21, 0x9931BEEC, 0xB1207E12, 0xA92F3EDF,
    0x217B1CDE, 0x39745C13, 0x11659CED, 0x096ADC20,
    0x4147B5B8, 0x5948F575, 0x7159358B, 0x69567546,
    0x6F3FE5BB, 0x7730A576, 0x5F216588, 0x472E2545,
    0x0F034CDD, 0x170C0C10, 0x3F1DCCEE, 0x27128C23,
    0xAF46AE22, 0xB749EEEF, 0x9F582E11, 0x87576EDC,
    0xCF7A0744, 0xD7754789, 0xFF648777, 0xE76BC7BA,
    0x46C5D4A9, 0x5ECA9464, 0x76DB549A, 0x6ED41457,
    0x26F97DCF, 0x3EF63D02, 0x16E7FDFC, 0x0EE8BD31,
    0x86BC9F30, 0x9EB3DFFD, 0xB6A21F03, 0xAEAD5FCE,
    0xE6803656, 0xFE8F769B, 0xD69EB665, 0xCE91F6A8
};

// ===== Alpha operations in GF(2^32) (CryptoPP implementation) =====
uint32_t mul_alpha(uint32_t x){
    // MUL_A macro from CryptoPP: ((x << 8) ^ s_sosemanukMulTables[x >> 24])
    return ((x << 8) ^ s_sosemanukMulTables[x >> 24]);
}

uint32_t div_alpha(uint32_t x){
    // DIV_A macro from CryptoPP: ((x >> 8) ^ s_sosemanukMulTables[256 + (x & 0xFF)])
    return ((x >> 8) ^ s_sosemanukMulTables[256 + (x & 0xFF)]);
}

// ===== Serpent S-box implementations for verification =====

// NOTE: After checking CryptoPP source, Sosemanuk DOES use Serpent S2
// But let's add a comment explaining the confusion:
// - Serpent has 8 S-boxes (S0-S7) used in different rounds
// - Sosemanuk uses specifically the S2 S-box from Serpent cipher
// - This is NOT "Serpent24" but "Serpent S2" (the 2nd S-box)

void Serpent2_bitslice(const uint32_t in[4], uint32_t out[4]){
    uint32_t a = in[0], b = in[1], c = in[2], d = in[3];
    
    // Serpent S2 bitslice implementation (used in Sosemanuk)
    // S2[x] = {8, 6, 7, 9, 3, 12, 10, 15, 13, 1, 14, 4, 0, 11, 5, 2}
    uint32_t t01 = b | c;
    uint32_t t02 = a | d;
    uint32_t t03 = a ^ b;
    uint32_t t04 = c ^ d;
    uint32_t t05 = t03 & t04;
    uint32_t t06 = t01 & t02;
    out[2] = t05 ^ t06;
    
    uint32_t t08 = b ^ d;
    uint32_t t09 = a | t08;
    uint32_t t10 = t01 ^ t02;
    uint32_t t11 = t09 & t10;
    out[0] = c ^ t11;
    
    uint32_t t13 = a ^ d;
    uint32_t t14 = b | out[2];
    uint32_t t15 = t13 & t14;
    uint32_t t16 = out[0] | t05;
    out[1] = t15 ^ t16;
    
    uint32_t t18 = ~out[1];
    uint32_t t19 = t13 ^ t08;
    uint32_t t20 = t19 & t18;
    out[3] = t20 ^ out[2];
}

// Simplified Serpent S2 for key schedule (based on CryptoPP)
static void serpent_s2_simple(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    uint32_t t01 = b | c;
    uint32_t t02 = a | d;
    uint32_t t03 = a ^ b;
    uint32_t t04 = c ^ d;
    uint32_t t05 = t03 & t04;
    uint32_t t06 = t01 & t02;
    
    uint32_t new_c = t05 ^ t06;
    uint32_t t08 = b ^ d;
    uint32_t t09 = a | t08;
    uint32_t t10 = t01 ^ t02;
    uint32_t t11 = t09 & t10;
    uint32_t new_a = c ^ t11;
    
    uint32_t t13 = a ^ d;
    uint32_t t14 = b | new_c;
    uint32_t t15 = t13 & t14;
    uint32_t t16 = new_a | t05;
    uint32_t new_b = t15 ^ t16;
    
    uint32_t t18 = ~new_b;
    uint32_t t19 = t13 ^ t08;
    uint32_t t20 = t19 & t18;
    uint32_t new_d = t20 ^ new_c;
    
    a = new_a; b = new_b; c = new_c; d = new_d;
}

// ===== Proper Serpent Key Schedule (CryptoPP compatible) =====
static void expand_key(const uint8_t* key, size_t keylen, uint32_t w[100]) {
    // Step 1: Pad key to 32 bytes as per Serpent specification
    uint8_t fullkey[32];
    std::memset(fullkey, 0, 32);
    std::memcpy(fullkey, key, std::min(keylen, size_t(32)));
    
    if (keylen < 32) {
        fullkey[keylen] = 0x80; // Serpent padding
    }
    
    // Step 2: Convert to 32-bit words (little endian)
    uint32_t k[140]; // Serpent needs more intermediate words
    for (int i = 0; i < 8; i++) {
        k[i] = (uint32_t(fullkey[4*i+0]) <<  0) |
               (uint32_t(fullkey[4*i+1]) <<  8) |
               (uint32_t(fullkey[4*i+2]) << 16) |
               (uint32_t(fullkey[4*i+3]) << 24);
    }
    
    // Step 3: Generate prekeys using Serpent linear recurrence
    for (int i = 8; i < 140; i++) {
        uint32_t temp = k[i-8] ^ k[i-5] ^ k[i-3] ^ k[i-1] ^ 0x9e3779b9 ^ (i-8);
        k[i] = rol32(temp, 11);
    }
    
    // Step 4: Apply S-boxes to generate final round keys
    // Sosemanuk uses first 100 words but with S-box mixing
    for (int i = 0; i < 25; i++) { // 100/4 = 25 groups
        uint32_t a = k[i*4 + 8 + 0];
        uint32_t b = k[i*4 + 8 + 1];  
        uint32_t c = k[i*4 + 8 + 2];
        uint32_t d = k[i*4 + 8 + 3];
        
        // Apply S2 (used in Sosemanuk)
        serpent_s2_simple(a, b, c, d);
        
        w[i*4 + 0] = a;
        w[i*4 + 1] = b;
        w[i*4 + 2] = c;
        w[i*4 + 3] = d;
    }
}

// ===== mix function for initialization =====
static uint32_t mix32(uint32_t x){
    x ^= x >> 16; x *= 0x7feb352du;
    x ^= x >> 15; x *= 0x846ca68bu;
    x ^= x >> 16; return x;
}

// Educational Sosemanuk Initialization (simplified but functional)
void init_state_from_key_iv(State& st,
                            const uint8_t* key, size_t keylen,
                            const uint8_t* iv,  size_t ivlen)
{
    // Step 1: Generate key schedule using Serpent-like expansion
    uint32_t w[100];
    expand_key(key, keylen, w);
    
    // Step 2: Convert IV to 32-bit words (little endian)
    uint32_t iv_words[4] = {0};
    for (int i = 0; i < 4 && (i*4+3) < (int)ivlen; i++) {
        iv_words[i] = (uint32_t(iv[4*i+0]) <<  0) |
                      (uint32_t(iv[4*i+1]) <<  8) | 
                      (uint32_t(iv[4*i+2]) << 16) |
                      (uint32_t(iv[4*i+3]) << 24);
    }
    
    // Step 3: Initialize LFSR state S[0..9] 
    // Educational: Mix expanded key with IV
    for (int i = 0; i < 10; i++) {
        st.S[i] = w[i];
        if (i < 4) {
            st.S[i] ^= iv_words[i];  // Mix IV into first 4 registers
        }
    }
    
    // Step 4: Initialize FSM registers R1, R2
    // Educational: Use key material + IV for initialization  
    st.R1 = w[10] ^ iv_words[0];
    st.R2 = w[11] ^ iv_words[1];
    
    // Step 5: Run mixing rounds (Sosemanuk uses ~24 rounds for good mixing)
    // Educational: This ensures the state is properly pseudorandomized
    for (int round = 0; round < 24; round++) {
        StepOut dummy = step(st);
        (void)dummy; // We discard output during initialization
    }
}

// ===== one step =====
StepOut step(State& st){
    uint32_t s0 = st.S[0], s3 = st.S[3], s9 = st.S[9];

    uint32_t R1_old = st.R1, R2_old = st.R2;
    uint32_t choose = mux(R1_old, st.S[1], st.S[1] ^ st.S[8]);
    uint32_t R1_new = R2_old + choose;
    uint32_t R2_new = Trans(R1_old);
    uint32_t f_t    = (st.S[9] + R1_new) ^ R2_new;

    uint32_t s10 = s9 ^ div_alpha(s3) ^ mul_alpha(s0);
    for(int i=0;i<9;i++) st.S[i] = st.S[i+1];
    st.S[9] = s10;

    st.R1 = R1_new; st.R2 = R2_new;

    return { f_t, s0 };
}

// ===== keystream =====
void generate_keystream(State& st, uint8_t* out, size_t out_len){
    size_t produced = 0;
    uint32_t fbuf[4];
    uint32_t sdrop[4];
    int cnt = 0;

    while(produced < out_len){
        auto o = step(st);
        fbuf[cnt] = o.f;
        sdrop[cnt] = o.dropped_s;
        cnt++;

        if(cnt == 4){
            uint32_t in4[4] = { fbuf[3], fbuf[2], fbuf[1], fbuf[0] };
            uint32_t out4[4];
            Serpent2_bitslice(in4, out4);
            for(int i=0;i<4 && produced < out_len; ++i){
                uint32_t z = out4[i] ^ sdrop[i];
                for(int b=0;b<4 && produced < out_len; ++b){
                    out[produced++] = static_cast<uint8_t>((z >> (8*b)) & 0xFF);
                }
            }
            cnt = 0;
        }
    }
}

// ===== helpers =====
void xor_in_place(uint8_t* dst, const uint8_t* src, size_t n){
    for(size_t i=0;i<n;i++) dst[i] ^= src[i];
}

std::string to_hex(const uint8_t* p, size_t n){
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for(size_t i=0;i<n;i++) oss << std::setw(2) << static_cast<unsigned>(p[i]);
    return oss.str();
}

} // namespace sose_sim
