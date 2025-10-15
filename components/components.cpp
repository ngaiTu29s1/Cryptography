#include "components.h"
#include <cstring>
#include <sstream>
#include <iomanip>

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

// ===== Alpha operations in GF(2^32) (Sosemanuk specification) =====
uint32_t mul_alpha(uint32_t x){
    // Multiplication by alpha in GF(2^32)
    // alpha = 0x00000002, polynomial: x^32 + x^7 + x^3 + x^2 + 1
    uint32_t msb = x >> 31;  // Extract MSB
    uint32_t result = (x << 1) & 0xFFFFFFFE;  // Shift left, clear LSB
    if (msb) {
        result ^= GF_POLY;  // Reduce modulo polynomial if MSB was 1
    }
    return result;
}

uint32_t div_alpha(uint32_t x){
    // Division by alpha in GF(2^32) = multiplication by alpha^(-1)
    uint32_t lsb = x & 1;  // Extract LSB
    uint32_t result = x >> 1;  // Shift right
    if (lsb) {
        result ^= ALPHA_INV;  // Add alpha^(-1) if LSB was 1
    }
    return result;
}

// ===== Serpent S2 bitslice (Sosemanuk specification) =====
void Serpent2_bitslice(const uint32_t in[4], uint32_t out[4]){
    uint32_t a = in[0], b = in[1], c = in[2], d = in[3];
    
    // Serpent S2: S2[x] = {8, 6, 7, 9, 3, 12, 10, 15, 13, 1, 14, 4, 0, 11, 5, 2}
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

// ===== Key Schedule (Sosemanuk specification) =====
static void expand_key(const uint8_t* key, size_t keylen, uint32_t w[100]) {
    // Expand key to 100 32-bit words using Serpent key schedule
    uint8_t fullkey[32];
    std::memset(fullkey, 0, 32);
    std::memcpy(fullkey, key, std::min(keylen, size_t(32)));
    
    // If key is less than 32 bytes, pad with single 1 bit followed by zeros
    if (keylen < 32) {
        fullkey[keylen] = 0x80;
    }
    
    // Convert to 32-bit words (little endian)
    uint32_t k[8];
    for (int i = 0; i < 8; i++) {
        k[i] = (uint32_t(fullkey[4*i]) |
               (uint32_t(fullkey[4*i+1]) << 8) |
               (uint32_t(fullkey[4*i+2]) << 16) |
               (uint32_t(fullkey[4*i+3]) << 24));
    }
    
    // Serpent key expansion
    for (int i = 0; i < 8; i++) {
        w[i] = k[i];
    }
    
    // Generate remaining 92 words
    for (int i = 8; i < 100; i++) {
        uint32_t temp = w[i-8] ^ w[i-5] ^ w[i-3] ^ w[i-1] ^ 0x9e3779b9 ^ (i-8);
        w[i] = rol32(temp, 11);
    }
}

// ===== mix function for initialization =====
static uint32_t mix32(uint32_t x){
    x ^= x >> 16; x *= 0x7feb352du;
    x ^= x >> 15; x *= 0x846ca68bu;
    x ^= x >> 16; return x;
}

void init_state_from_key_iv(State& st,
                            const uint8_t* key, size_t keylen,
                            const uint8_t* iv,  size_t ivlen)
{
    // Generate expanded key
    uint32_t w[100];
    expand_key(key, keylen, w);
    
    // Initialize LFSR state S[0] to S[9] using key and IV
    // Use first 10 expanded key words
    for (int i = 0; i < 10; i++) {
        st.S[i] = w[i];
    }
    
    // Mix in IV (assuming 16-byte IV)
    if (ivlen >= 16) {
        // Convert IV to 4 32-bit words
        uint32_t iv_words[4];
        for (int i = 0; i < 4; i++) {
            iv_words[i] = (uint32_t(iv[4*i]) |
                          (uint32_t(iv[4*i+1]) << 8) |
                          (uint32_t(iv[4*i+2]) << 16) |
                          (uint32_t(iv[4*i+3]) << 24));
        }
        
        // XOR IV into first 4 LFSR registers
        for (int i = 0; i < 4; i++) {
            st.S[i] ^= iv_words[i];
        }
    }
    
    // Initialize FSM registers R1, R2 using expanded key
    st.R1 = w[10] ^ w[11];
    st.R2 = w[12] ^ w[13];
    
    // Run several initialization rounds to mix state
    for (int i = 0; i < 24; i++) {
        StepOut dummy = step(st);
        (void)dummy; // Suppress unused variable warning
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
