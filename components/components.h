#pragma once
#include <array>
#include <cstdint>
#include <vector>
#include <string>

namespace sose_sim {

// ===== Types =====
struct State {
    std::array<uint32_t,10> S{};
    uint32_t R1{0}, R2{0};
};
struct StepOut { uint32_t f; uint32_t dropped_s; };

// ===== Prototypes =====
// utils
uint32_t rol32(uint32_t x, unsigned r);
uint32_t ror32(uint32_t x, unsigned r);
uint32_t mux(uint32_t c, uint32_t x, uint32_t y);

// core transforms
uint32_t Trans(uint32_t z);
uint32_t mul_alpha(uint32_t x);    // placeholder (TODO: replace with spec-accurate)
uint32_t div_alpha(uint32_t x);    // placeholder (TODO: replace with spec-accurate)
void Serpent1_bitslice(const uint32_t in[4], uint32_t out[4]); // placeholder

// init/step/keystream
void init_state_from_key_iv(State& st,
                            const uint8_t* key, size_t keylen,
                            const uint8_t* iv,  size_t ivlen);

StepOut step(State& st);
void generate_keystream(State& st, uint8_t* out, size_t out_len);

// helpers
void xor_in_place(uint8_t* dst, const uint8_t* src, size_t n);
std::string to_hex(const uint8_t* p, size_t n);

} // namespace sose_sim
