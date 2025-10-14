#include "components.h"
#include <cstring>
#include <sstream>
#include <iomanip>

namespace sose_sim {

// ===== utils =====
uint32_t rol32(uint32_t x, unsigned r){ return (x<<r) | (x>>(32-r)); }
uint32_t ror32(uint32_t x, unsigned r){ return (x>>r) | (x<<(32-r)); }
uint32_t mux(uint32_t c, uint32_t x, uint32_t y){ return (c & 1u) ? y : x; }

// ===== constants =====
static constexpr uint32_t TRANS_M = 0x54655307u;

// ===== Trans =====
uint32_t Trans(uint32_t z){
    uint64_t m = static_cast<uint64_t>(z) * TRANS_M; // mod 2^32 by cast
    return rol32(static_cast<uint32_t>(m), 7);
}

// ===== placeholder alpha mul/div (TODO: spec-accurate masks) =====
uint32_t mul_alpha(uint32_t x){
    uint32_t msb = (x >> 24) & 0xFFu;
    uint32_t shifted = (x << 8);
    uint32_t mask = rol32(0x1B000001u * (msb | 1u), (msb % 13));
    return shifted ^ mask;
}
uint32_t div_alpha(uint32_t x){
    uint32_t lsb = x & 0xFFu;
    uint32_t shifted = (x >> 8);
    uint32_t mask = ror32(0xA3000001u * (lsb | 1u), (lsb % 11));
    return shifted ^ mask;
}

// ===== placeholder Serpent1 bitslice (TODO: replace with real S2 bitslice) =====
void Serpent1_bitslice(const uint32_t in[4], uint32_t out[4]){
    uint32_t a = in[0], b = in[1], c = in[2], d = in[3];
    uint32_t t1 = (a ^ (b & c)) ^ rol32(d, 13);
    uint32_t t2 = (b ^ (c | d)) ^ rol32(a, 7);
    uint32_t t3 = (c ^ (d & a)) ^ rol32(b, 3);
    uint32_t t4 = (d ^ (a | b)) ^ rol32(c, 17);
    out[0] = (t1 ^ rol32(t3, 5)) ^ (t2 & t4);
    out[1] = (t2 ^ rol32(t4, 9)) ^ (t1 & t3);
    out[2] = (t3 ^ rol32(t1, 13)) ^ (t2 | t4);
    out[3] = (t4 ^ rol32(t2, 1))  ^ (t1 | t3);
}

// ===== init (EDU): mix key/iv to state (not spec-accurate) =====
static uint32_t mix32(uint32_t x){
    x ^= x >> 16; x *= 0x7feb352du;
    x ^= x >> 15; x *= 0x846ca68bu;
    x ^= x >> 16; return x;
}

void init_state_from_key_iv(State& st,
                            const uint8_t* key, size_t keylen,
                            const uint8_t* iv,  size_t ivlen)
{
    uint32_t accK = 0x243F6A88u, accV = 0x85A308D3u;
    for(size_t i=0;i<keylen;i++){
        accK ^= key[i];
        accK = rol32(accK, 5) + 0x9E3779B9u;
        accK = mix32(accK);
    }
    for(size_t i=0;i<ivlen;i++){
        accV ^= iv[i];
        accV = rol32(accV, 7) + 0x7F4A7C15u;
        accV = mix32(accV);
    }
    uint32_t x = accK, y = accV;
    for(int i=0;i<10;i++){
        x = mix32(x + 0xDEADBEEF + i);
        y = mix32(y + 0xBADC0FFE + i*3);
        st.S[i] = x ^ rol32(y, i+1);
    }
    st.R1 = mix32(accK ^ 0xA5A5A5A5u);
    st.R2 = mix32(accV ^ 0x5A5A5A5Au);
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
            Serpent1_bitslice(in4, out4);
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
