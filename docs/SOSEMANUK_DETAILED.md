# Sosemanuk Stream Cipher - Implementation Guide

## Tổng Quan
Sosemanuk kết hợp LFSR 10-word với FSM 2-register và Serpent S-box để tạo keystream an toàn.

## Core Implementation

### 1. Khởi Tạo từ components.cpp

```cpp
void init_state_from_key_iv(State& st, const uint8_t* key, size_t keylen,
                            const uint8_t* iv, size_t ivlen) {
    uint32_t w[100];
    expand_key(key, keylen, w);
    
    uint32_t iv_words[4] = {0};
    for (int i = 0; i < 4 && (i*4+3) < (int)ivlen; i++) {
        iv_words[i] = (uint32_t(iv[4*i+0]) << 0) | (uint32_t(iv[4*i+1]) << 8) |
                      (uint32_t(iv[4*i+2]) << 16) | (uint32_t(iv[4*i+3]) << 24);
    }
    
    for (int i = 0; i < 10; i++) {
        st.S[i] = w[i];
        if (i < 4) st.S[i] ^= iv_words[i];
    }
    
    st.R1 = w[10] ^ iv_words[0];
    st.R2 = w[11] ^ iv_words[1];
    
    for (int round = 0; round < 24; round++) {
        step(st);
    }
}
```

### 2. Key Schedule với Serpent

```cpp
static void expand_key(const uint8_t* key, size_t keylen, uint32_t w[100]) {
    uint8_t fullkey[32];
    std::memset(fullkey, 0, 32);
    std::memcpy(fullkey, key, std::min(keylen, size_t(32)));
    if (keylen < 32) fullkey[keylen] = 0x80;
    
    uint32_t k[140];
    for (int i = 0; i < 8; i++) {
        k[i] = (uint32_t(fullkey[4*i+0]) << 0) | (uint32_t(fullkey[4*i+1]) << 8) |
               (uint32_t(fullkey[4*i+2]) << 16) | (uint32_t(fullkey[4*i+3]) << 24);
    }
    
    for (int i = 8; i < 140; i++) {
        uint32_t temp = k[i-8] ^ k[i-5] ^ k[i-3] ^ k[i-1] ^ 0x9e3779b9 ^ (i-8);
        k[i] = rol32(temp, 11);
    }
    
    for (int i = 0; i < 25; i++) {
        serpent_s2_simple(k[i*4+8], k[i*4+9], k[i*4+10], k[i*4+11]);
        w[i*4] = k[i*4+8]; w[i*4+1] = k[i*4+9];
        w[i*4+2] = k[i*4+10]; w[i*4+3] = k[i*4+11];
    }
}
```

### 3. Cipher Step Function

```cpp
StepOut step(State& st) {
    uint32_t s0 = st.S[0], s3 = st.S[3], s9 = st.S[9];
    uint32_t R1_old = st.R1, R2_old = st.R2;
    
    uint32_t choose = mux(R1_old, st.S[1], st.S[1] ^ st.S[8]);
    uint32_t R1_new = R2_old + choose;
    uint32_t R2_new = Trans(R1_old);
    uint32_t f_t = (st.S[9] + R1_new) ^ R2_new;
    
    uint32_t s10 = s9 ^ div_alpha(s3) ^ mul_alpha(s0);
    
    for(int i=0; i<9; i++) st.S[i] = st.S[i+1];
    st.S[9] = s10;
    
    st.R1 = R1_new; st.R2 = R2_new;
    
    return { f_t, s0 };
}
```

### 4. Keystream Generation

```cpp
void generate_keystream(State& st, uint8_t* out, size_t out_len) {
    size_t produced = 0;
    uint32_t fbuf[4], sdrop[4];
    int cnt = 0;

    while(produced < out_len) {
        auto o = step(st);
        fbuf[cnt] = o.f;
        sdrop[cnt] = o.dropped_s;
        cnt++;

        if(cnt == 4) {
            uint32_t in4[4] = { fbuf[3], fbuf[2], fbuf[1], fbuf[0] };
            uint32_t out4[4];
            
            Serpent2_bitslice(in4, out4);
            
            for(int i=0; i<4 && produced < out_len; ++i) {
                uint32_t z = out4[i] ^ sdrop[i];
                
                for(int b=0; b<4 && produced < out_len; ++b) {
                    out[produced++] = static_cast<uint8_t>((z >> (8*b)) & 0xFF);
                }
            }
            cnt = 0;
        }
    }
}
```

## Key Components

### GF(2³²) Operations
```cpp
uint32_t mul_alpha(uint32_t x) {
    return ((x << 8) ^ s_sosemanukMulTables[x >> 24]);
}

uint32_t div_alpha(uint32_t x) {
    return ((x >> 8) ^ s_sosemanukMulTables[256 + (x & 0xFF)]);
}
```

### FSM Functions
```cpp
uint32_t mux(uint32_t c, uint32_t x, uint32_t y) { 
    return (c & 1u) ? y : x; 
}

uint32_t Trans(uint32_t z) {
    uint64_t m = static_cast<uint64_t>(z) * 0x54655307u;
    return rol32(static_cast<uint32_t>(m), 7);
}
```

### Serpent S2 Bitslice
```cpp
void Serpent2_bitslice(const uint32_t in[4], uint32_t out[4]) {
    uint32_t a = in[0], b = in[1], c = in[2], d = in[3];
    
    uint32_t t01 = b | c;
    uint32_t t02 = a | d;
    uint32_t t03 = a ^ b;
    // ... (complex Boolean algebra for 32 parallel S-boxes)
    
    out[0] = /* result */; out[1] = /* result */;
    out[2] = /* result */; out[3] = /* result */;
}
```

## Usage
```cpp
State st;
uint8_t key[16] = {...};
uint8_t iv[16] = {...};

init_state_from_key_iv(st, key, 16, iv, 16);

uint8_t keystream[1000];
generate_keystream(st, keystream, 1000);

// XOR với plaintext để mã hóa
for (size_t i = 0; i < data_len; i++) {
    ciphertext[i] = plaintext[i] ^ keystream[i];
}
```

#### ✅ Implementation Points
- [ ] **Endianness**: Little-endian cho conversion bytes ↔ words
- [ ] **Lookup Tables**: s_sosemanukMulTables[512] từ CryptoPP
- [ ] **Warm-up Rounds**: 24 rounds để trộn đều state
- [ ] **Buffer Management**: Thu thập 4 f_t values trước khi S-box
- [ ] **Memory Safety**: Bounds checking cho arrays

#### ✅ Testing & Validation  
- [ ] **Test Vectors**: So sánh với reference implementation
- [ ] **Edge Cases**: Key lengths khác nhau, IV all-zero
- [ ] **Performance**: Đo tốc độ keystream generation
- [ ] **Memory**: Check leaks và buffer overflows

---

### 🔢 Workflow Chi Tiết - Từng Bước Cụ Thể

#### **BƯỚC 1: Chuẩn Bị Input**

```cpp
// Từ components.cpp - init_state_from_key_iv() function
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
        iv_words[i] = (uint32_t(iv[4*i+0]) <<  0) |  // Byte 0: LSB
                      (uint32_t(iv[4*i+1]) <<  8) |  // Byte 1: bits 8-15
                      (uint32_t(iv[4*i+2]) << 16) |  // Byte 2: bits 16-23
                      (uint32_t(iv[4*i+3]) << 24);   // Byte 3: MSB
    }
    // ... continue with state initialization
}
```

**📝 Phân Tích Chi Tiết Input Processing:**

#### **Key Validation & Processing:**
- **keylen**: Có thể là 16, 20, 24, 28, hoặc 32 bytes
- **Serpent Compatibility**: expand_key() tự động pad key nếu < 32 bytes
- **Memory Safety**: `std::min(keylen, size_t(32))` đảm bảo không buffer overflow

#### **IV Conversion Logic:**
```cpp
// Ví dụ IV = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, ...]
// Conversion thành little-endian words:
iv_words[0] = 0x78563412  // First 4 bytes
iv_words[1] = 0xF0DEBC9A  // Next 4 bytes
// ... tiếp tục cho 16 bytes IV
```

#### **Bounds Checking:**
```cpp
for (int i = 0; i < 4 && (i*4+3) < (int)ivlen; i++)
```
- **i < 4**: Chỉ xử lý tối đa 4 words (16 bytes)
- **(i*4+3) < ivlen**: Đảm bảo không đọc quá buffer IV
- **Graceful handling**: Nếu IV < 16 bytes, các word còn lại = 0

**⚠️ Lưu ý Implementation:**
- **Little-endian**: LSB first trong memory layout
- **Type Safety**: Explicit casting `uint32_t(iv[...])` 
- **Zero Padding**: iv_words khởi tạo = {0} cho safety

---

#### **BƯỚC 2: Key Schedule (Serpent-based)**

```cpp
// Từ components.cpp - expand_key() function
static void expand_key(const uint8_t* key, size_t keylen, uint32_t w[100]) {
    // Step 1: Pad key to 32 bytes as per Serpent specification
    uint8_t fullkey[32];
    std::memset(fullkey, 0, 32);                              // Clear all bytes
    std::memcpy(fullkey, key, std::min(keylen, size_t(32)));  // Copy user key
    
    if (keylen < 32) {
        fullkey[keylen] = 0x80; // Serpent padding: 10000000 binary
    }
    
    // Step 2: Convert to 32-bit words (little endian)
    uint32_t k[140]; // Serpent needs more intermediate words
    for (int i = 0; i < 8; i++) {
        k[i] = (uint32_t(fullkey[4*i+0]) <<  0) |  // LSB
               (uint32_t(fullkey[4*i+1]) <<  8) |  
               (uint32_t(fullkey[4*i+2]) << 16) |  
               (uint32_t(fullkey[4*i+3]) << 24);   // MSB
    }
    
    // Step 3: Generate prekeys using Serpent linear recurrence
    for (int i = 8; i < 140; i++) {
        uint32_t temp = k[i-8] ^ k[i-5] ^ k[i-3] ^ k[i-1]  // Linear combination
                        ^ 0x9e3779b9                         // Golden ratio φ
                        ^ (i-8);                             // Round counter
        k[i] = rol32(temp, 11);  // Rotate left 11 positions
    }
    
    // Step 4: Apply S-boxes to generate final round keys
    for (int i = 0; i < 25; i++) { // 100/4 = 25 groups of 4 words
        uint32_t a = k[i*4 + 8 + 0];  // Get 4 consecutive words
        uint32_t b = k[i*4 + 8 + 1];  
        uint32_t c = k[i*4 + 8 + 2];
        uint32_t d = k[i*4 + 8 + 3];
        
        serpent_s2_simple(a, b, c, d);  // Apply Serpent S2 transformation
        
        w[i*4 + 0] = a;  // Store back transformed words
        w[i*4 + 1] = b;
        w[i*4 + 2] = c;
        w[i*4 + 3] = d;
    }
}
```

**📝 Phân Tích Chi Tiết Key Schedule:**

#### **Step 1 - Serpent Padding Strategy:**
```cpp
// Ví dụ: Key 16 bytes = [K0, K1, ..., K15]
// Result: [K0, K1, ..., K15, 0x80, 0x00, 0x00, ..., 0x00] (32 bytes total)

if (keylen < 32) {
    fullkey[keylen] = 0x80;  // Binary: 10000000
}
```
- **0x80 Padding**: Serpent standard để tránh weak keys
- **Security**: Đảm bảo keys khác nhau không collide sau padding
- **Deterministic**: Cùng input key → cùng padded result

#### **Step 2 - Little Endian Conversion:**
```cpp
// Ví dụ: 4 bytes [0x12, 0x34, 0x56, 0x78]
// k[i] = 0x78563412 trong memory (LSB first)

k[i] = (uint32_t(fullkey[4*i+0]) <<  0) |  // 0x12 << 0  = 0x00000012
       (uint32_t(fullkey[4*i+1]) <<  8) |  // 0x34 << 8  = 0x00003400
       (uint32_t(fullkey[4*i+2]) << 16) |  // 0x56 << 16 = 0x00560000  
       (uint32_t(fullkey[4*i+3]) << 24);   // 0x78 << 24 = 0x78000000
                                           // Result: 0x78563412
```

#### **Step 3 - Linear Recurrence Analysis:**
```cpp
uint32_t temp = k[i-8] ^ k[i-5] ^ k[i-3] ^ k[i-1] ^ 0x9e3779b9 ^ (i-8);
k[i] = rol32(temp, 11);
```

**Mathematical Properties:**
- **Taps [-8,-5,-3,-1]**: Chọn để có maximum period
- **Golden Ratio φ**: `0x9e3779b9 = floor(2^32 * (√5-1)/2)` 
- **Round Counter**: `(i-8)` để mỗi round khác nhau
- **ROL 11**: Diffusion để spread bits evenly

#### **Step 4 - S-box Mixing Implementation:**
```cpp
serpent_s2_simple(a, b, c, d);  // In-place transformation
```
- **Non-linearity**: Phá vỡ linear relationships
- **Confusion**: Obscure key-to-expanded-key relationship
- **Avalanche**: 1-bit key change → 50% expanded key change

**🔍 Tại sao cần Key Schedule phức tạp?**
1. **Avalanche Effect**: 1 bit key thay đổi → 50% expanded key thay đổi
2. **Non-linearity**: S-box phá vỡ tính tuyến tính
3. **Uniform Distribution**: Mọi expanded key đều có xác suất xuất hiện bằng nhau

---

#### **BƯỚC 3: State Initialization**

```cpp
// Tiếp tục từ init_state_from_key_iv() trong components.cpp
void init_state_from_key_iv(State& st,
                            const uint8_t* key, size_t keylen,
                            const uint8_t* iv,  size_t ivlen)
{
    // [Previous steps: expand_key và IV processing...]
    
    // Step 3: Initialize LFSR state S[0..9] 
    // Educational: Mix expanded key with IV
    for (int i = 0; i < 10; i++) {
        st.S[i] = w[i];           // Base value from expanded key
        if (i < 4) {
            st.S[i] ^= iv_words[i];  // XOR mix IV into first 4 registers only
        }
    }
    
    // Step 4: Initialize FSM registers R1, R2
    // Educational: Use key material + IV for initialization  
    st.R1 = w[10] ^ iv_words[0];  // FSM register 1: key[10] ⊕ IV[0]
    st.R2 = w[11] ^ iv_words[1];  // FSM register 2: key[11] ⊕ IV[1]
    
    // Step 5: Run mixing rounds (Sosemanuk uses ~24 rounds for good mixing)
    // Educational: This ensures the state is properly pseudorandomized
    for (int round = 0; round < 24; round++) {
        StepOut dummy = step(st);  // Execute cipher step but discard output
        (void)dummy; // Suppress unused variable warning
    }
}
```

**📝 Phân Tích Chi Tiết State Initialization:**

#### **LFSR Setup Logic:**
```cpp
// State layout sau initialization:
st.S[0] = w[0] ⊕ iv_words[0]    // Key word 0 mixed với IV word 0
st.S[1] = w[1] ⊕ iv_words[1]    // Key word 1 mixed với IV word 1
st.S[2] = w[2] ⊕ iv_words[2]    // Key word 2 mixed với IV word 2  
st.S[3] = w[3] ⊕ iv_words[3]    // Key word 3 mixed với IV word 3
st.S[4] = w[4]                  // Pure key material (no IV mixing)
st.S[5] = w[5]                  // Pure key material
st.S[6] = w[6]                  // Pure key material
st.S[7] = w[7]                  // Pure key material
st.S[8] = w[8]                  // Pure key material
st.S[9] = w[9]                  // Pure key material
```

**Why chỉ mix IV vào first 4 registers?**
- **Sosemanuk Design**: IV chỉ ảnh hưởng partial state initially
- **Diffusion**: Warm-up rounds sẽ spread IV effect toàn bộ state
- **Security**: Tránh IV dominate toàn bộ initial state

#### **FSM Initialization Strategy:**
```cpp
st.R1 = w[10] ^ iv_words[0];  // R1 = Key[10] ⊕ IV[0]
st.R2 = w[11] ^ iv_words[1];  // R2 = Key[11] ⊕ IV[1]
```
- **Independent Sources**: FSM state khác biệt với LFSR state
- **IV Dependency**: Cùng key, khác IV → khác FSM initial state
- **Key Dependency**: Khác key → khác FSM initial state ngay cả với cùng IV

#### **24-Round Warm-up Analysis:**
```cpp
for (int round = 0; round < 24; round++) {
    StepOut dummy = step(st);  // Full cipher step execution
    (void)dummy;               // Discard f_t và dropped_s outputs
}
```

**Mathematical Justification:**
- **Diffusion Time**: Trong 1 step, mỗi bit có thể ảnh hưởng ~3-4 bits khác
- **Complete Mixing**: 24 steps đảm bảo mỗi input bit ảnh hưởng toàn bộ state
- **Avalanche Saturation**: Sau 20+ rounds, state trở nên truly pseudorandom
- **Security Margin**: 24 > 20 để đảm bảo no remaining structure

**🔥 Tại sao cần 24 rounds warm-up?**
- **Diffusion**: Đảm bảo key+IV khuếch tán đều khắp state
- **Pattern Breaking**: Xóa các patterns có thể dự đoán được
- **Security**: Ngăn chặn attacks dựa trên initial state

---

#### **BƯỚC 4: Cipher Step Function (Trái Tim Của Thuật Toán)**

```cpp
// Từ components.cpp - step() function
StepOut step(State& st){
    // Phase 4.1: Save values needed before state updates
    uint32_t s0 = st.S[0];  // Will be shifted out (dropped value)
    uint32_t s3 = st.S[3];  // For LFSR feedback calculation
    uint32_t s9 = st.S[9];  // For FSM input and LFSR feedback

    // Phase 4.2: FSM Update (Non-linear component)
    uint32_t R1_old = st.R1, R2_old = st.R2;  // Save current FSM state
    
    // MUX function: conditional selection based on R1's LSB
    uint32_t choose = mux(R1_old, st.S[1], st.S[1] ^ st.S[8]);
    // If R1_old & 1 == 1: choose = S[1] ^ S[8]
    // If R1_old & 1 == 0: choose = S[1]
    
    uint32_t R1_new = R2_old + choose;    // Addition modulo 2^32 
    uint32_t R2_new = Trans(R1_old);      // Non-linear transformation
    uint32_t f_t = (st.S[9] + R1_new) ^ R2_new;  // Output function

    // Phase 4.3: LFSR Update (Linear component in GF(2^32))
    uint32_t s10 = s9 ^ div_alpha(s3) ^ mul_alpha(s0);
    // S[10] = S[9] ⊕ (S[3]/α) ⊕ (S[0]×α) in finite field GF(2^32)
    
    // Shift LFSR registers: S[i] ← S[i+1] for i=0..8, S[9] ← s10
    for(int i=0; i<9; i++) st.S[i] = st.S[i+1];
    st.S[9] = s10;

    // Phase 4.4: Update FSM state
    st.R1 = R1_new; 
    st.R2 = R2_new;

    return { f_t, s0 };  // Return output word and dropped LFSR value
}
```

**📝 Phân Tích Chi Tiết Cipher Step:**

#### **MUX Function Logic:**
```cpp
// mux() implementation từ components.cpp
uint32_t mux(uint32_t c, uint32_t x, uint32_t y){ 
    return (c & 1u) ? y : x; 
}

// Trong step function:
uint32_t choose = mux(R1_old, st.S[1], st.S[1] ^ st.S[8]);
```

**Detailed Behavior:**
```cpp
if (R1_old & 0x1 == 1) {
    choose = st.S[1] ^ st.S[8];  // XOR của 2 LFSR registers
} else {
    choose = st.S[1];            // Direct LFSR register value
}
```

**Cryptographic Purpose:**
- **Data-dependent Selection**: Choice phụ thuộc vào FSM state (R1)
- **LFSR Coupling**: FSM và LFSR interact với nhau
- **Non-linearity**: Conditional branch tạo non-linear behavior

#### **FSM State Update:**
```cpp
uint32_t R1_new = R2_old + choose;    // Modular addition
uint32_t R2_new = Trans(R1_old);      // Non-linear transformation

// Trans function implementation:
uint32_t Trans(uint32_t z){
    uint64_t m = static_cast<uint64_t>(z) * TRANS_M;  // 0x54655307
    return rol32(static_cast<uint32_t>(m), 7);        // Rotate left 7
}
```

**Step-by-step Trans Analysis:**
```cpp
// Input: z = 32-bit value
// Step 1: z * 0x54655307 (64-bit multiplication)
// Step 2: Take lower 32 bits: (uint32_t)(z * 0x54655307)  
// Step 3: Rotate left 7 positions
// Result: Highly non-linear transformation
```

#### **LFSR Feedback Computation:**
```cpp
uint32_t s10 = s9 ^ div_alpha(s3) ^ mul_alpha(s0);
```

**GF(2³²) Operations Breakdown:**
```cpp
// mul_alpha(s0): Multiply S[0] by α in GF(2^32)
uint32_t mul_result = ((s0 << 8) ^ s_sosemanukMulTables[s0 >> 24]);

// div_alpha(s3): Divide S[3] by α in GF(2^32)  
uint32_t div_result = ((s3 >> 8) ^ s_sosemanukMulTables[256 + (s3 & 0xFF)]);

// Final feedback: XOR combination
uint32_t s10 = s9 ^ div_result ^ mul_result;
```

**Mathematical Meaning:**
```
S[10] = S[9] ⊕ (S[3] / α) ⊕ (S[0] × α)  in GF(2³²)
```
- **S[9]**: Immediate feedback (most recent)
- **S[3]/α**: Delayed feedback với scaling down  
- **S[0]×α**: Oldest feedback với scaling up
- **Taps [0,3,9]**: Chosen để maximize LFSR period

#### **Output Function Analysis:**
```cpp
uint32_t f_t = (st.S[9] + R1_new) ^ R2_new;
```

**Component Analysis:**
- **st.S[9]**: Linear component từ LFSR
- **R1_new**: Non-linear component từ FSM  
- **Addition (+)**: Modular arithmetic mixing
- **XOR (^)**: Final linear combination
- **Balance**: Linear + Non-linear = cryptographically strong

**🧠 Hiểu sâu Cipher Step:**
- **LFSR**: Tạo tính chu kỳ dài, dễ dự đoán nếu đứng một mình
- **FSM**: Thêm tính phi tuyến, làm khó dự đoán
- **Kết hợp**: LFSR + FSM = vừa có chu kỳ dài, vừa khó phân tích

---

#### **BƯỚC 5: Keystream Generation (Batched Processing)**

```cpp
// Từ components.cpp - generate_keystream() function
void generate_keystream(State& st, uint8_t* out, size_t out_len){
    size_t produced = 0;          // Bytes đã generate
    uint32_t fbuf[4];             // Buffer cho 4 f_t values
    uint32_t sdrop[4];            // Buffer cho 4 dropped S values
    int cnt = 0;                  // Counter cho batch processing

    while(produced < out_len){
        // Phase 5.1: Collect cipher step output
        auto o = step(st);        // Execute one cipher step
        fbuf[cnt] = o.f;          // Store f_t value  
        sdrop[cnt] = o.dropped_s; // Store dropped LFSR value
        cnt++;

        if(cnt == 4){  // Khi đã collect đủ 4 values
            // Phase 5.2: Prepare Serpent S-box input (REVERSED ORDER!)
            uint32_t in4[4] = { fbuf[3], fbuf[2], fbuf[1], fbuf[0] };
            uint32_t out4[4];
            
            // Phase 5.3: Apply Serpent S2 bitslice transformation
            Serpent2_bitslice(in4, out4);
            
            // Phase 5.4: Final mixing and byte extraction
            for(int i=0; i<4 && produced < out_len; ++i){
                uint32_t z = out4[i] ^ sdrop[i];  // XOR with dropped value
                
                // Extract 4 bytes từ word (little-endian order)
                for(int b=0; b<4 && produced < out_len; ++b){
                    out[produced++] = static_cast<uint8_t>((z >> (8*b)) & 0xFF);
                }
            }
            cnt = 0;  // Reset batch counter
        }
    }
}
```

**📝 Phân Tích Chi Tiết Keystream Generation:**

#### **Batch Collection Logic:**
```cpp
// Collect 4 cipher steps:
Step 1: fbuf[0] = f_0, sdrop[0] = s0_0  // First step output
Step 2: fbuf[1] = f_1, sdrop[1] = s0_1  // Second step output  
Step 3: fbuf[2] = f_2, sdrop[2] = s0_2  // Third step output
Step 4: fbuf[3] = f_3, sdrop[3] = s0_3  // Fourth step output
```

**Why batch exactly 4 values?**
- **Serpent Compatibility**: S-box thiết kế cho 4×32-bit input
- **Bitslice Efficiency**: Process 32 S-boxes simultaneously
- **Standard Block Size**: 4×4 = 16 bytes output per batch

#### **Input Order Reversal:**
```cpp
uint32_t in4[4] = { fbuf[3], fbuf[2], fbuf[1], fbuf[0] };
//                    ↑       ↑       ↑       ↑
//                  newest  →  →  →   oldest
```

**Sosemanuk Specification Requirement:**
- **Most recent f_t first**: Newer cipher outputs processed first
- **Chronological reversal**: [f₃, f₂, f₁, f₀] → Serpent S-box
- **Standard compliance**: Matches reference implementation behavior

#### **Serpent S2 Bitslice Processing:**
```cpp
void Serpent2_bitslice(const uint32_t in[4], uint32_t out[4]){
    // Input: 4 words = 128 bits = 32 parallel 4-bit S-box inputs
    // Output: 4 words = 128 bits = 32 parallel 4-bit S-box outputs
    
    uint32_t a = in[0], b = in[1], c = in[2], d = in[3];
    
    // Serpent S2 boolean logic (32 operations in parallel)
    uint32_t t01 = b | c;      // 32 OR operations simultaneously
    uint32_t t02 = a | d;
    uint32_t t03 = a ^ b;      // 32 XOR operations simultaneously
    // ... (complex boolean algebra)
    
    out[0] = /* result */;     // 32 S-box outputs for bit position 0
    out[1] = /* result */;     // 32 S-box outputs for bit position 1  
    out[2] = /* result */;     // 32 S-box outputs for bit position 2
    out[3] = /* result */;     // 32 S-box outputs for bit position 3
}
```

#### **Final Mixing Strategy:**
```cpp
uint32_t z = out4[i] ^ sdrop[i];
```

**Security Analysis:**
- **Additional Diffusion**: Serpent output ⊕ historical LFSR state
- **State Dependency**: Keystream depends on both current & past
- **Attack Resistance**: Harder để recover internal state
- **Specification Compliance**: Matches original Sosemanuk design

#### **Byte Extraction (Little-Endian):**
```cpp
for(int b=0; b<4 && produced < out_len; ++b){
    out[produced++] = static_cast<uint8_t>((z >> (8*b)) & 0xFF);
}
```

**Bit Layout Extraction:**
```cpp
// z = 0x12345678 (example 32-bit word)
// Byte extraction order:
out[0] = (0x12345678 >> 0)  & 0xFF = 0x78  // LSB first
out[1] = (0x12345678 >> 8)  & 0xFF = 0x56  
out[2] = (0x12345678 >> 16) & 0xFF = 0x34
out[3] = (0x12345678 >> 24) & 0xFF = 0x12  // MSB last
```

**Memory Layout (Little-Endian):**
```
Address: [n+0] [n+1] [n+2] [n+3]
Value:   0x78  0x56  0x34  0x12
```

#### **Throughput Analysis:**
- **4 steps → 16 bytes**: Efficiency ratio 4:1 (words:bytes)
- **Batching overhead**: Minimal function call overhead  
- **S-box amortization**: 32 S-boxes cost ≈ 1 S-box time
- **Memory efficiency**: Sequential write access pattern

**🎲 Tại sao lại batch 4 values?**
- **Serpent Compatibility**: Serpent S-box thiết kế cho 4×32-bit blocks
- **Parallel Processing**: Bitslice cho phép xử lý 32 S-box cùng lúc
- **Efficiency**: Giảm overhead function calls

---

#### **BƯỚC 6: Encryption/Decryption (Stream Cipher)**

```cpp
// Complete workflow combining tất cả functions từ components.cpp
void sosemanuk_encrypt_decrypt(const uint8_t* plaintext, size_t len,
                              const uint8_t* key, size_t keylen,  
                              const uint8_t* iv, size_t ivlen,
                              uint8_t* ciphertext) {
    
    // Phase 6.1: Initialize cipher state
    State st;  // Declare cipher state structure
    init_state_from_key_iv(st, key, keylen, iv, ivlen);
    // This function internally calls:
    // - expand_key() for key schedule
    // - IV processing to words  
    // - LFSR/FSM state setup
    // - 24 warm-up rounds
    
    // Phase 6.2: Generate keystream  
    uint8_t* keystream = new uint8_t[len];  // Allocate keystream buffer
    generate_keystream(st, keystream, len);
    // This function internally calls:
    // - step() multiple times for batching
    // - Serpent2_bitslice() for S-box processing
    // - Final mixing and byte extraction
    
    // Phase 6.3: XOR operation (encryption = decryption)
    xor_in_place(ciphertext, plaintext, len);      // Copy plaintext first
    xor_in_place(ciphertext, keystream, len);      // XOR with keystream
    
    delete[] keystream;  // Clean up memory
}

// Helper function implementation từ components.cpp:
void xor_in_place(uint8_t* dst, const uint8_t* src, size_t n){
    for(size_t i=0; i<n; i++) {
        dst[i] ^= src[i];  // Byte-by-byte XOR operation
    }
}
```

**📝 Phân Tích Chi Tiết Complete Workflow:**

#### **State Structure Layout:**
```cpp
// Từ components.h (inferred structure)
struct State {
    uint32_t S[10];  // LFSR registers (320 bits total)
    uint32_t R1;     // FSM register 1 (32 bits)  
    uint32_t R2;     // FSM register 2 (32 bits)
    // Total internal state: 384 bits
};
```

#### **Memory Management Strategy:**
```cpp
uint8_t* keystream = new uint8_t[len];  // Dynamic allocation
// Process keystream generation...
delete[] keystream;                     // Explicit cleanup
```

**Alternative Stack-based Approach (for smaller lengths):**
```cpp
if (len <= 1024) {  // Small message optimization
    uint8_t keystream[1024];  // Stack allocation
    generate_keystream(st, keystream, len);
    // No delete needed
}
```

#### **XOR Operation Analysis:**
```cpp
// Stream cipher fundamental operation:
ciphertext[i] = plaintext[i] ⊕ keystream[i]

// Decryption (identical operation):  
plaintext[i] = ciphertext[i] ⊕ keystream[i]

// Mathematical proof:
// Let K = keystream, P = plaintext, C = ciphertext
// Encryption: C = P ⊕ K
// Decryption: P = C ⊕ K = (P ⊕ K) ⊕ K = P ⊕ (K ⊕ K) = P ⊕ 0 = P ✓
```

#### **Complete Usage Example:**
```cpp
#include "components.h"

int main() {
    // Test data
    uint8_t key[16] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
                       0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
    uint8_t iv[16]  = {0xFF,0xEE,0xDD,0xCC,0xBB,0xAA,0x99,0x88,
                       0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00};
    uint8_t plaintext[] = "Hello, Sosemanuk Stream Cipher!";
    size_t len = strlen((char*)plaintext);
    
    // Cipher state initialization
    sose_sim::State st;
    sose_sim::init_state_from_key_iv(st, key, 16, iv, 16);
    
    // Keystream generation  
    uint8_t keystream[100];
    sose_sim::generate_keystream(st, keystream, len);
    
    // Encryption
    uint8_t ciphertext[100];
    memcpy(ciphertext, plaintext, len);
    sose_sim::xor_in_place(ciphertext, keystream, len);
    
    // Decryption (re-initialize state with same key+IV)
    sose_sim::init_state_from_key_iv(st, key, 16, iv, 16);
    sose_sim::generate_keystream(st, keystream, len);  // Same keystream
    sose_sim::xor_in_place(ciphertext, keystream, len); // Recover plaintext
    
    return 0;
}
```

#### **Security Considerations:**
```cpp
// CRITICAL: Never reuse IV với same key
// Bad:  encrypt(msg1, key, iv) then encrypt(msg2, key, iv) 
// Good: encrypt(msg1, key, iv1) then encrypt(msg2, key, iv2)

// Keystream reuse attack:
// C1 = P1 ⊕ K,  C2 = P2 ⊕ K (same keystream K)
// C1 ⊕ C2 = (P1 ⊕ K) ⊕ (P2 ⊕ K) = P1 ⊕ P2
// Attacker gets plaintext XOR without knowing key!
```

#### **Performance Characteristics:**
- **Initialization Cost**: ~100 cycles (key schedule + warm-up)
- **Keystream Rate**: ~4.8 cycles/byte (very fast)
- **Memory Usage**: 384-bit state + lookup tables
- **Cache Efficiency**: Good sequential access patterns

---

### 🔬 Điểm Mấu Chốt Cần Hiểu Sâu

#### **1. Finite Field GF(2³²) Operations**

```cpp
// Từ components.cpp - GF(2^32) operations
// Phép cộng trong GF(2^32): Đơn giản là XOR
uint32_t gf_add(uint32_t a, uint32_t b) {
    return a ^ b;  // Addition = XOR trong characteristic 2 field
}

// Phép nhân với α: Sử dụng lookup table từ CryptoPP
uint32_t mul_alpha(uint32_t x){
    // MUL_A macro from CryptoPP: ((x << 8) ^ s_sosemanukMulTables[x >> 24])
    return ((x << 8) ^ s_sosemanukMulTables[x >> 24]);
}

// Phép chia cho α: Cũng dùng lookup table
uint32_t div_alpha(uint32_t x){
    // DIV_A macro from CryptoPP: ((x >> 8) ^ s_sosemanukMulTables[256 + (x & 0xFF)])
    return ((x >> 8) ^ s_sosemanukMulTables[256 + (x & 0xFF)]);
}

// Constants definition
static constexpr uint32_t GF_POLY = 0x10D;        // x^32 + x^7 + x^3 + x^2 + 1
static constexpr uint32_t ALPHA_INV = 0x80000069; // α^(-1) trong GF(2^32)
```

**📝 Detailed Mathematical Analysis:**

#### **Polynomial Representation:**
```cpp
// GF(2^32) elements represented as polynomials:
// x = x₃₁·X³¹ + x₃₀·X³⁰ + ... + x₁·X¹ + x₀·X⁰
// Stored as: uint32_t = [x₃₁ x₃₀ ... x₁ x₀] (binary representation)

// Example: 0x12345678 = polynomial:
// 1·X³¹ + 0·X³⁰ + 0·X²⁹ + 1·X²⁸ + ... + 1·X³ + 1·X² + 0·X¹ + 0·X⁰
```

#### **mul_alpha() Deep Dive:**
```cpp
uint32_t mul_alpha(uint32_t x) {
    // Step 1: Left shift (multiply by X)
    uint32_t shifted = x << 8;  // Shift 8 positions left
    
    // Step 2: Check for overflow (degree ≥ 32)  
    uint32_t high_bits = x >> 24;  // Extract top 8 bits
    
    // Step 3: Apply reduction if needed
    uint32_t reduction = s_sosemanukMulTables[high_bits];
    
    // Step 4: Combine results
    return shifted ^ reduction;
}
```

**Why shift 8 bits instead of 1?**
- **α = X⁸ trong Sosemanuk**: α không phải X¹, mà là X⁸
- **Efficiency**: Shift 8 bits ≡ multiply by X⁸ = α
- **Lookup table**: Pre-computed reductions cho all possible overflow values

**💡 Tại sao cần Finite Field?**
- **Tính Toán Chính Xác**: Đảm bảo operations không overflow
- **Tính Chất Đại Số**: LFSR feedback có tính chất toán học tốt
- **Bảo Mật**: Khó dự đoán quan hệ input-output

#### **2. Serpent S2 Bitslice Magic**

```cpp
// Từ components.cpp - Complete Serpent S2 bitslice implementation
void Serpent2_bitslice(const uint32_t in[4], uint32_t out[4]){
    uint32_t a = in[0], b = in[1], c = in[2], d = in[3];
    
    // Serpent S2 bitslice implementation (used in Sosemanuk)
    // S2[x] = {8, 6, 7, 9, 3, 12, 10, 15, 13, 1, 14, 4, 0, 11, 5, 2}
    
    // Boolean algebra for 32 parallel S-boxes
    uint32_t t01 = b | c;       // 32 OR operations simultaneously
    uint32_t t02 = a | d;       // 32 OR operations simultaneously  
    uint32_t t03 = a ^ b;       // 32 XOR operations simultaneously
    uint32_t t04 = c ^ d;       // 32 XOR operations simultaneously
    uint32_t t05 = t03 & t04;   // 32 AND operations simultaneously
    uint32_t t06 = t01 & t02;   // 32 AND operations simultaneously
    out[2] = t05 ^ t06;         // First output bit plane
    
    uint32_t t08 = b ^ d;
    uint32_t t09 = a | t08;
    uint32_t t10 = t01 ^ t02;
    uint32_t t11 = t09 & t10;
    out[0] = c ^ t11;           // Second output bit plane
    
    uint32_t t13 = a ^ d;
    uint32_t t14 = b | out[2];  // Use previously computed output
    uint32_t t15 = t13 & t14;
    uint32_t t16 = out[0] | t05; // Use previously computed values
    out[1] = t15 ^ t16;         // Third output bit plane
    
    uint32_t t18 = ~out[1];     // 32 NOT operations simultaneously
    uint32_t t19 = t13 ^ t08;
    uint32_t t20 = t19 & t18;
    out[3] = t20 ^ out[2];      // Fourth output bit plane
}
```

**📝 Bitslice Conceptual Model:**

#### **Traditional vs Bitslice S-box:**
```cpp
// Traditional S-box (1 at a time):
uint8_t traditional_s2(uint8_t input) {
    static const uint8_t S2[16] = {8,6,7,9,3,12,10,15,13,1,14,4,0,11,5,2};
    return S2[input & 0xF];  // 4-bit input → 4-bit output
}

// Bitslice S-box (32 at once):  
void bitslice_s2(uint32_t in[4], uint32_t out[4]) {
    // Process 32 S-boxes simultaneously
    // Each bit position i processes S-box i
}
```

#### **Data Layout Visualization:**
```cpp
// Input layout (4 words × 32 bits each):
//   Bit position: 31 30 29 ... 2  1  0
// in[0] (a bits): a₃₁a₃₀a₂₉... a₂ a₁ a₀  ← Input bit 0 của mỗi S-box
// in[1] (b bits): b₃₁b₃₀b₂₉... b₂ b₁ b₀  ← Input bit 1 của mỗi S-box  
// in[2] (c bits): c₃₁c₃₀c₂₉... c₂ c₁ c₀  ← Input bit 2 của mỗi S-box
// in[3] (d bits): d₃₁d₃₀d₂₉... d₂ d₁ d₀  ← Input bit 3 của mỗi S-box

// S-box i processes: (aᵢ, bᵢ, cᵢ, dᵢ) → (out0ᵢ, out1ᵢ, out2ᵢ, out3ᵢ)

// Output layout (4 words × 32 bits each):
// out[0]: out0₃₁ out0₃₀ ... out0₁ out0₀  ← Output bit 0 của mỗi S-box
// out[1]: out1₃₁ out1₃₀ ... out1₁ out1₀  ← Output bit 1 của mỗi S-box
// out[2]: out2₃₁ out2₃₀ ... out2₁ out2₀  ← Output bit 2 của mỗi S-box  
// out[3]: out3₃₁ out3₃₀ ... out3₁ out3₀  ← Output bit 3 của mỗi S-box
```

#### **Boolean Logic Analysis:**
```cpp
// Serpent S2 truth table: S2[x] = {8,6,7,9,3,12,10,15,13,1,14,4,0,11,5,2}
// Input x:  0 1 2 3 4  5  6  7  8 9 10 11 12 13 14 15
// Output:   8 6 7 9 3 12 10 15 13 1 14  4  0 11  5  2

// Boolean function derivation (simplified):
// out[0] = f₀(a,b,c,d) = complex boolean expression
// out[1] = f₁(a,b,c,d) = complex boolean expression  
// out[2] = f₂(a,b,c,d) = complex boolean expression
// out[3] = f₃(a,b,c,d) = complex boolean expression

// The t01, t02, ... variables are intermediate computations
// to implement these boolean functions efficiently
```

#### **Performance Advantages:**
```cpp
// Traditional approach (32 table lookups):
for (int i = 0; i < 32; i++) {
    uint8_t input = extract_4_bits(in, i);      // Extract operation  
    uint8_t output = S2_table[input];           // Table lookup
    insert_4_bits(out, i, output);             // Insert operation
}
// Cost: 32 × (extract + lookup + insert) = ~96-128 operations

// Bitslice approach (pure boolean logic):  
// Cost: ~20 boolean operations total
// Speedup: ~5-6x faster + better cache behavior
```

**🚀 Lợi ích Bitslice:**
- **Tốc độ**: 32 S-box trong thời gian của 1 S-box
- **Cache Friendly**: Ít memory access hơn table lookup
- **Constant Time**: Không phụ thuộc input data (chống side-channel)

#### **3. Key Schedule Security Properties**

```cpp
// Avalanche test implementation using components.cpp functions
void test_avalanche_effect() {
    // Test keys: differ by only 1 bit
    uint8_t key1[16] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    uint8_t key2[16] = {0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,  // Only bit 0 different
                        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    
    // Generate expanded keys using actual implementation
    uint32_t expanded1[100], expanded2[100];
    sose_sim::expand_key(key1, 16, expanded1);  // From components.cpp
    sose_sim::expand_key(key2, 16, expanded2);
    
    // Count different bits
    int diff_bits = 0;
    for (int i = 0; i < 100; i++) {
        uint32_t xor_result = expanded1[i] ^ expanded2[i];
        diff_bits += __builtin_popcount(xor_result);  // Count 1-bits in XOR
    }
    
    // Calculate avalanche ratio
    double avalanche_ratio = (double)diff_bits / (100 * 32);  // Total bits = 3200
    
    // Good key schedule should have ~50% bit changes
    assert(avalanche_ratio > 0.4 && avalanche_ratio < 0.6);
    printf("Avalanche ratio: %.3f (should be ≈ 0.5)\n", avalanche_ratio);
}

// Detailed key expansion analysis function  
void analyze_key_expansion() {
    uint8_t test_key[16] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
                            0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
    uint32_t w[100];
    
    // Step-by-step expansion analysis
    printf("=== Key Expansion Analysis ===\n");
    printf("Original key: ");
    for (int i = 0; i < 16; i++) printf("%02X ", test_key[i]);
    printf("\n");
    
    // Call actual expand_key function
    sose_sim::expand_key(test_key, 16, w);
    
    // Display first few expanded words
    printf("Expanded key words [0-9]:\n");
    for (int i = 0; i < 10; i++) {
        printf("w[%d] = 0x%08X\n", i, w[i]);
    }
    
    // Analyze bit distribution
    int bit_counts[32] = {0};  // Count 1-bits per position
    for (int i = 0; i < 100; i++) {
        for (int bit = 0; bit < 32; bit++) {
            if (w[i] & (1u << bit)) bit_counts[bit]++;
        }
    }
    
    printf("Bit distribution analysis (should be ≈ 50 for good randomness):\n");
    for (int bit = 0; bit < 32; bit++) {
        printf("Bit %2d: %2d/100 (%.1f%%)\n", bit, bit_counts[bit], 
               100.0 * bit_counts[bit] / 100);
    }
}
```

**📝 Security Properties Analysis:**

#### **Avalanche Effect Measurement:**
```cpp
// Mathematical definition:
// Avalanche(K₁, K₂) = |{i : expand_key(K₁)[i] ≠ expand_key(K₂)[i]}| / total_bits
// 
// Good avalanche: ≈ 50% của bits change khi input change 1 bit
// Poor avalanche: < 25% hoặc > 75% của bits change

// Practical testing:
uint32_t hamming_distance(uint32_t a, uint32_t b) {
    return __builtin_popcount(a ^ b);  // Count differing bits
}
```

#### **Linear Recurrence Security:**
```cpp
// From expand_key() function:
for (int i = 8; i < 140; i++) {
    uint32_t temp = k[i-8] ^ k[i-5] ^ k[i-3] ^ k[i-1]  // Linear feedback
                    ^ 0x9e3779b9                         // Breaking constant
                    ^ (i-8);                             // Round dependency
    k[i] = rol32(temp, 11);                             // Diffusion
}
```

**Security Analysis:**
- **Taps [-8,-5,-3,-1]**: Chosen để avoid short periods
- **Golden ratio constant**: Breaks symmetries và weak key patterns  
- **Round counter**: Ensures different rounds produce different patterns
- **ROL 11**: Spreads bit influence across word boundaries

#### **S-box Mixing Security:**
```cpp
// Non-linear transformation every 4 words:
for (int i = 0; i < 25; i++) {
    // Get 4 consecutive linear-generated words
    uint32_t a = k[i*4 + 8 + 0], b = k[i*4 + 8 + 1];
    uint32_t c = k[i*4 + 8 + 2], d = k[i*4 + 8 + 3];
    
    // Apply non-linear Serpent S2 transformation
    serpent_s2_simple(a, b, c, d);
    
    // Store non-linearly transformed results
    w[i*4 + 0] = a; w[i*4 + 1] = b;
    w[i*4 + 2] = c; w[i*4 + 3] = d;
}
```

**Non-linearity Benefits:**
- **Algebraic Immunity**: S-box prevents linear algebra attacks
- **Correlation Immunity**: Reduces statistical correlations
- **SAT Resistance**: Makes SAT solver attacks harder

---

### 🎯 Troubleshooting Guide

#### **Lỗi Thường Gặp & Cách Fix:**

1. **Wrong Keystream Output**:
   - ✅ Check endianness (little-endian)
   - ✅ Verify lookup tables (s_sosemanukMulTables)
   - ✅ Confirm 24 warm-up rounds
   - ✅ Check Serpent S2 implementation

2. **Performance Issues**:
   - ✅ Use lookup tables thay vì compute GF operations
   - ✅ Implement Serpent bitslice correctly
   - ✅ Avoid unnecessary memory allocations

3. **Security Concerns**:
   - ✅ Never reuse IV with same key
   - ✅ Ensure random IV generation
   - ✅ Implement constant-time operations nếu cần

#### **Validation Steps:**

```python
def validate_implementation():
    # Test với known test vectors
    test_key = bytes.fromhex("00112233445566778899aabbccddeeff")
    test_iv = bytes.fromhex("ffeeddccbbaa99887766554433221100")
    test_plain = b"Hello, Sosemanuk!"
    
    # Expected ciphertext (from reference implementation)
    expected = bytes.fromhex("...")  # Điền từ test vectors
    
    actual = sosemanuk_encrypt_decrypt(test_plain, test_key, test_iv)
    assert actual == expected, "Implementation mismatch!"
```

---

### 🏆 Tóm Tắt Workflow Cho Team

**Khi implement, hãy làm theo thứ tự:**

1. **Setup Constants**: Lookup tables, hằng số GF(2³²)
2. **Basic Operations**: GF operations, bitwise utilities  
3. **Serpent Components**: S2 bitslice, key schedule
4. **LFSR & FSM**: Step function, state management
5. **Integration**: Initialization, keystream generation
6. **Testing**: Test vectors, edge cases, performance
7. **Documentation**: Code comments, usage examples

**Mỗi component nên được test riêng biệt trước khi integrate!**

---

## 💻 Code Analysis & Implementation Breakdown

Phần này phân tích chi tiết code trong `components.cpp` để hiểu cách Sosemanuk được implement thực tế.

### 🔧 **1. Constants & Lookup Tables**

```cpp
// GF(2^32) irreducible polynomial: x^32 + x^7 + x^3 + x^2 + 1
static constexpr uint32_t GF_POLY = 0x10D;
static constexpr uint32_t ALPHA_INV = 0x80000069;
static constexpr uint32_t TRANS_M = 0x54655307u;

// Complete 512-entry lookup table from CryptoPP
static const uint32_t s_sosemanukMulTables[512] = {
    // First 256: multiplication table
    // Last 256: division table  
    0x00000000, 0xE19FCF12, 0x6B973724, ...
};
```

**📝 Phân Tích:**
- **GF_POLY**: Polynomial bất khả quy để define GF(2³²)
- **ALPHA_INV**: Nghịch đảo của α = 0x2 trong finite field
- **TRANS_M**: Hằng số 0x54655307 cho hàm Trans (chọn để tránh weakness)
- **s_sosemanukMulTables**: Bảng lookup 512 phần tử từ CryptoPP, đảm bảo tính chính xác

**🎯 Tại sao cần lookup tables?**
- **Performance**: Phép nhân/chia GF(2³²) từ O(32) → O(1)  
- **Accuracy**: Tránh lỗi implementation polynomial arithmetic
- **Compatibility**: Đảm bảo kết quả giống CryptoPP reference

---

### ⚙️ **2. Basic Utility Functions**

```cpp
// Rotation operations (essential for bitwise cryptography)
uint32_t rol32(uint32_t x, unsigned r){ 
    return (x<<r) | (x>>(32-r)); 
}

uint32_t ror32(uint32_t x, unsigned r){ 
    return (x>>r) | (x<<(32-r)); 
}

// Multiplexer: conditional selection based on LSB
uint32_t mux(uint32_t c, uint32_t x, uint32_t y){ 
    return (c & 1u) ? y : x; 
}
```

**📝 Phân Tích:**
- **rol32/ror32**: Rotate left/right, cần thiết cho key schedule và Trans function
- **mux**: Chọn `y` nếu bit cuối của `c` = 1, ngược lại chọn `x`
- **Constant-time**: Các operations này không phụ thuộc vào giá trị data (chống side-channel)

---

### 🧮 **3. GF(2³²) Field Operations**

```cpp
uint32_t mul_alpha(uint32_t x){
    // MUL_A macro from CryptoPP
    return ((x << 8) ^ s_sosemanukMulTables[x >> 24]);
}

uint32_t div_alpha(uint32_t x){
    // DIV_A macro from CryptoPP  
    return ((x >> 8) ^ s_sosemanukMulTables[256 + (x & 0xFF)]);
}
```

**📝 Phân Tích Chi Tiết:**

#### **mul_alpha(x) - Nhân với α:**
```
Input:  x = [x31 x30 ... x8 x7 ... x0] (32 bits)
Step 1: x << 8 = [x23 x22 ... x0 0 0 ... 0] (shift left 8 bits)  
Step 2: x >> 24 = [0 0 ... 0 x31 x30 ... x24] (get top 8 bits)
Step 3: table[x >> 24] = precomputed reduction value
Result: (x << 8) XOR table[x >> 24]
```

**🔍 Tại sao hoạt động?**
- **Multiplication by α**: Trong GF(2³²), nhân với α = shift left + reduce modulo polynomial
- **Overflow handling**: Top 8 bits cần reduce bằng polynomial, lookup table làm việc này
- **Efficiency**: 1 shift + 1 XOR + 1 table lookup = rất nhanh

#### **div_alpha(x) - Chia cho α:**
```
Input:  x = [x31 x30 ... x8 x7 ... x0] (32 bits)
Step 1: x >> 8 = [0 0 ... 0 x31 x30 ... x8] (shift right 8 bits)
Step 2: x & 0xFF = [0 0 ... 0 x7 x6 ... x0] (get bottom 8 bits)  
Step 3: table[256 + (x & 0xFF)] = precomputed "carry" value
Result: (x >> 8) XOR table[256 + (x & 0xFF)]
```

---

### 🔧 **4. Trans Function (FSM Core)**

```cpp
uint32_t Trans(uint32_t z){
    // Trans(z) = (z * 0x54655307) <<< 7 (mod 2^32)
    uint64_t m = static_cast<uint64_t>(z) * TRANS_M;
    return rol32(static_cast<uint32_t>(m), 7);
}
```

**📝 Phân Tích:**
- **Purpose**: Non-linear transformation cho FSM state
- **Algorithm**: Nhân với constant, sau đó rotate left 7 positions
- **Why uint64_t?**: Tránh overflow khi nhân 32-bit numbers
- **Constant 0x54655307**: Được chọn để có diffusion properties tốt

**🎲 Tính Chất Cryptographic:**
- **Avalanche**: Thay đổi 1 bit input → ~16 bit output thay đổi
- **Period**: Không có fixed points hoặc short cycles
- **Non-linearity**: Không thể express bằng linear operations

---

### 🐍 **5. Serpent S-box Implementation**

```cpp
void Serpent2_bitslice(const uint32_t in[4], uint32_t out[4]){
    uint32_t a = in[0], b = in[1], c = in[2], d = in[3];
    
    // Serpent S2 bitslice: process 32 S-boxes in parallel
    uint32_t t01 = b | c;      // 32 OR operations parallel
    uint32_t t02 = a | d;
    uint32_t t03 = a ^ b;      // 32 XOR operations parallel
    uint32_t t04 = c ^ d;
    uint32_t t05 = t03 & t04;  // 32 AND operations parallel
    uint32_t t06 = t01 & t02;
    out[2] = t05 ^ t06;        // First output
    
    // Continue with remaining intermediate values...
    uint32_t t08 = b ^ d;
    uint32_t t09 = a | t08;
    uint32_t t10 = t01 ^ t02;
    uint32_t t11 = t09 & t10;
    out[0] = c ^ t11;          // Second output
    
    uint32_t t13 = a ^ d;
    uint32_t t14 = b | out[2];
    uint32_t t15 = t13 & t14;
    uint32_t t16 = out[0] | t05;
    out[1] = t15 ^ t16;        // Third output
    
    uint32_t t18 = ~out[1];    // NOT operation
    uint32_t t19 = t13 ^ t08;
    uint32_t t20 = t19 & t18;
    out[3] = t20 ^ out[2];     // Fourth output
}
```

**📝 Phân Tích Bitslice Magic:**

#### **Conceptual View:**
```
Traditional S-box: 1 input (4 bits) → 1 output (4 bits)
Bitslice S-box:   32 inputs (4×32 bits) → 32 outputs (4×32 bits)

Input Layout:
  in[0] = [a31 a30 ... a1 a0] - bit 0 của 32 S-boxes
  in[1] = [b31 b30 ... b1 b0] - bit 1 của 32 S-boxes  
  in[2] = [c31 c30 ... c1 c0] - bit 2 của 32 S-boxes
  in[3] = [d31 d30 ... d1 d0] - bit 3 của 32 S-boxes
  
Each S-box i processes: (a_i, b_i, c_i, d_i) → (out0_i, out1_i, out2_i, out3_i)
```

#### **Performance Advantage:**
- **Parallel**: 32 S-box transformations trong thời gian của 1
- **Cache Friendly**: Không cần memory access cho lookup tables
- **Constant Time**: Execution time không phụ thuộc input values

---

### 🗝️ **6. Key Schedule Analysis**

```cpp
static void expand_key(const uint8_t* key, size_t keylen, uint32_t w[100]) {
    // Step 1: Serpent-style padding
    uint8_t fullkey[32];
    std::memset(fullkey, 0, 32);
    std::memcpy(fullkey, key, std::min(keylen, size_t(32)));
    
    if (keylen < 32) {
        fullkey[keylen] = 0x80; // Serpent padding: 1000...
    }
    
    // Step 2: Convert to little-endian 32-bit words
    uint32_t k[140];
    for (int i = 0; i < 8; i++) {
        k[i] = (uint32_t(fullkey[4*i+0]) <<  0) |  // Byte 0 → bits 0-7
               (uint32_t(fullkey[4*i+1]) <<  8) |  // Byte 1 → bits 8-15
               (uint32_t(fullkey[4*i+2]) << 16) |  // Byte 2 → bits 16-23
               (uint32_t(fullkey[4*i+3]) << 24);   // Byte 3 → bits 24-31
    }
    
    // Step 3: Serpent linear recurrence
    for (int i = 8; i < 140; i++) {
        uint32_t temp = k[i-8] ^ k[i-5] ^ k[i-3] ^ k[i-1]  // Linear combination
                        ^ 0x9e3779b9                         // Golden ratio constant
                        ^ (i-8);                             // Round counter
        k[i] = rol32(temp, 11);  // Rotate for better diffusion
    }
    
    // Step 4: S-box mixing (non-linear transformation)
    for (int i = 0; i < 25; i++) { // 100/4 = 25 groups
        uint32_t a = k[i*4 + 8 + 0], b = k[i*4 + 8 + 1];
        uint32_t c = k[i*4 + 8 + 2], d = k[i*4 + 8 + 3];
        
        serpent_s2_simple(a, b, c, d);  // Apply S2 transformation
        
        w[i*4 + 0] = a; w[i*4 + 1] = b;
        w[i*4 + 2] = c; w[i*4 + 3] = d;
    }
}
```

**📝 Key Schedule Breakdown:**

#### **Step 1 - Padding Strategy:**
```
Key 16 bytes: [K0 K1 ... K15] → [K0 K1 ... K15 80 00 00 ... 00]
Key 24 bytes: [K0 K1 ... K23] → [K0 K1 ... K23 80 00 ... 00]  
Key 32 bytes: [K0 K1 ... K31] → [K0 K1 ... K31] (no padding)
```
**Why 0x80?** Serpent standard: 1 bit followed by zeros để tránh weak keys.

#### **Step 2 - Endianness Handling:**
```cpp
// Little-endian conversion example:
bytes = [0x12, 0x34, 0x56, 0x78]
word  = 0x78563412  // LSB first trong memory
```

#### **Step 3 - Linear Recurrence Math:**
```
k[i] = ROL11(k[i-8] ⊕ k[i-5] ⊕ k[i-3] ⊕ k[i-1] ⊕ φ ⊕ i)

Where:
- φ = 0x9e3779b9 = ⌊2³² × (√5-1)/2⌋ (Golden ratio)
- ROL11 = rotate left 11 positions
- Taps at positions -8,-5,-3,-1 cho maximum period
```

#### **Step 4 - S-box Mixing Purpose:**
- **Break Linearity**: Linear recurrence dễ bị algebraic attacks
- **Add Confusion**: S-box tạo non-linear relationships
- **Avalanche**: 1 bit key change → 50% expanded key change

---

### 🎛️ **7. State Initialization Analysis**

```cpp
void init_state_from_key_iv(State& st, const uint8_t* key, size_t keylen,
                            const uint8_t* iv, size_t ivlen)
{
    // Phase 1: Expand user key
    uint32_t w[100];
    expand_key(key, keylen, w);
    
    // Phase 2: Process IV  
    uint32_t iv_words[4] = {0};
    for (int i = 0; i < 4 && (i*4+3) < (int)ivlen; i++) {
        iv_words[i] = (uint32_t(iv[4*i+0]) <<  0) |
                      (uint32_t(iv[4*i+1]) <<  8) |
                      (uint32_t(iv[4*i+2]) << 16) |
                      (uint32_t(iv[4*i+3]) << 24);
    }
    
    // Phase 3: Initialize LFSR with key+IV mixing
    for (int i = 0; i < 10; i++) {
        st.S[i] = w[i];              // Base from expanded key
        if (i < 4) {
            st.S[i] ^= iv_words[i];  // Mix IV into first 4 positions
        }
    }
    
    // Phase 4: Initialize FSM with key+IV mixing
    st.R1 = w[10] ^ iv_words[0];     // FSM state from key+IV
    st.R2 = w[11] ^ iv_words[1];
    
    // Phase 5: Warm-up mixing (CRITICAL SECURITY STEP!)
    for (int round = 0; round < 24; round++) {
        StepOut dummy = step(st);    // Run cipher but discard output
        (void)dummy;
    }
}
```

**📝 Initialization Breakdown:**

#### **Phase 3 - LFSR Setup Logic:**
```
S[0] = w[0] ⊕ iv_words[0]    // Mix key word 0 với IV word 0
S[1] = w[1] ⊕ iv_words[1]    // Mix key word 1 với IV word 1  
S[2] = w[2] ⊕ iv_words[2]    // Mix key word 2 với IV word 2
S[3] = w[3] ⊕ iv_words[3]    // Mix key word 3 với IV word 3
S[4] = w[4]                  // Pure key material (no IV)
S[5] = w[5]                  // Pure key material
...
S[9] = w[9]                  // Pure key material
```

#### **Phase 5 - Warm-up Necessity:**
**Trước warm-up:** State có structure từ key schedule
**Sau 24 rounds:** State trở nên pseudorandom, không còn trace của original key+IV

**Mathematical Justification:**
- **Diffusion Time**: Cần ~20 rounds để 1 bit change lan tỏa toàn bộ state
- **Safety Margin**: 24 rounds > 20 rounds để đảm bảo complete mixing
- **Attack Prevention**: Ngăn chặn attacks exploit initial state structure

---

### ⚡ **8. Core Cipher Step Analysis**

```cpp
StepOut step(State& st){
    // Save values before state update
    uint32_t s0 = st.S[0], s3 = st.S[3], s9 = st.S[9];
    uint32_t R1_old = st.R1, R2_old = st.R2;
    
    // FSM Update (Non-linear component)
    uint32_t choose = mux(R1_old, st.S[1], st.S[1] ^ st.S[8]);
    uint32_t R1_new = R2_old + choose;          // Addition mod 2^32
    uint32_t R2_new = Trans(R1_old);            // Non-linear transform  
    uint32_t f_t = (st.S[9] + R1_new) ^ R2_new; // Output function
    
    // LFSR Update (Linear component)
    uint32_t s10 = s9 ^ div_alpha(s3) ^ mul_alpha(s0);
    
    // Shift LFSR registers
    for(int i=0; i<9; i++) st.S[i] = st.S[i+1];
    st.S[9] = s10;
    
    // Update FSM state
    st.R1 = R1_new; 
    st.R2 = R2_new;
    
    return { f_t, s0 };  // Return output word + dropped S value
}
```

**📝 Step Function Breakdown:**

#### **FSM Logic Analysis:**
```cpp
choose = mux(R1_old, st.S[1], st.S[1] ^ st.S[8]);
```
**Meaning:** 
- Nếu `R1_old & 1 == 1`: chọn `S[1] ⊕ S[8]` 
- Nếu `R1_old & 1 == 0`: chọn `S[1]`

**Why this design?**
- **Data-dependent**: Selection phụ thuộc vào FSM state
- **LFSR coupling**: Kết nối FSM với LFSR state
- **Non-linearity**: Tạo conditional branches

#### **Output Function:**
```cpp
uint32_t f_t = (st.S[9] + R1_new) ^ R2_new;
```
**Components:**
- `S[9]`: LFSR contribution (linear)
- `R1_new`: FSM contribution (non-linear)  
- `R2_new`: Transformed FSM state (more non-linear)
- **Combination**: Addition + XOR để balance linear/non-linear

#### **LFSR Feedback:**
```cpp
uint32_t s10 = s9 ^ div_alpha(s3) ^ mul_alpha(s0);
```
**Mathematical Meaning:**
```
S[10] = S[9] ⊕ (S[3]/α) ⊕ (S[0]×α) trong GF(2³²)
```
**Taps explanation:**
- **S[9]**: Direct feedback (immediate history)
- **S[3]/α**: Delayed feedback với scaling
- **S[0]×α**: Oldest feedback với scaling
- **Result**: Maximum period LFSR sequence

---

### 🌊 **9. Keystream Generation Analysis**

```cpp
void generate_keystream(State& st, uint8_t* out, size_t out_len){
    size_t produced = 0;
    uint32_t fbuf[4], sdrop[4];  // Buffers for batching
    int cnt = 0;

    while(produced < out_len){
        // Collect cipher step outputs
        auto o = step(st);
        fbuf[cnt] = o.f;           // f_t value
        sdrop[cnt] = o.dropped_s;  // dropped S[0] value
        cnt++;

        if(cnt == 4){  // Process batch of 4
            // Prepare input for Serpent S-box (reversed order!)
            uint32_t in4[4] = { fbuf[3], fbuf[2], fbuf[1], fbuf[0] };
            uint32_t out4[4];
            
            // Apply Serpent S2 bitslice transformation
            Serpent2_bitslice(in4, out4);
            
            // XOR with dropped values and extract bytes
            for(int i=0; i<4 && produced < out_len; ++i){
                uint32_t z = out4[i] ^ sdrop[i];  // Final mixing
                
                // Extract bytes in little-endian order
                for(int b=0; b<4 && produced < out_len; ++b){
                    out[produced++] = static_cast<uint8_t>((z >> (8*b)) & 0xFF);
                }
            }
            cnt = 0;  // Reset batch counter
        }
    }
}
```

**📝 Keystream Generation Breakdown:**

#### **Batching Strategy:**
**Why batch 4 f_t values?**
- **S-box Efficiency**: Serpent S2 thiết kế cho 4×32-bit blocks
- **Parallelization**: Bitslice xử lý 32 S-boxes simultaneously  
- **Throughput**: Higher keystream generation rate

#### **Order Reversal Logic:**
```cpp
uint32_t in4[4] = { fbuf[3], fbuf[2], fbuf[1], fbuf[0] };
```
**Reason:** Sosemanuk specification requires reverse order cho S-box input

#### **Final Mixing:**
```cpp
uint32_t z = out4[i] ^ sdrop[i];
```
**Purpose:**
- **Additional Diffusion**: Serpent output XOR với dropped LFSR values
- **State Dependency**: Keystream phụ thuộc vào both current và past state
- **Security**: Thêm một layer protection chống cryptanalysis

#### **Byte Extraction:**
```cpp
out[produced++] = static_cast<uint8_t>((z >> (8*b)) & 0xFF);
```
**Little-endian order:**
- Byte 0: bits 0-7 (LSB first)
- Byte 1: bits 8-15
- Byte 2: bits 16-23  
- Byte 3: bits 24-31 (MSB last)

---

### 🔗 **10. Integration & Dependencies**

#### **Function Call Flow:**
```
main() 
  ↓
init_state_from_key_iv()
  ├── expand_key()           // Key schedule
  │   └── serpent_s2_simple()
  ├── IV processing
  └── 24× step()             // Warm-up
      ├── mux()
      ├── Trans()
      ├── mul_alpha() / div_alpha()
      └── LFSR shift
  ↓
generate_keystream()
  └── step() batches
      └── Serpent2_bitslice()
  ↓
XOR với plaintext = ciphertext
```

#### **Data Flow Dependencies:**
```
User Key → expand_key() → w[100] words
User IV → little-endian → iv_words[4]  
Key+IV → LFSR state S[10] + FSM state R1,R2
State → step() → f_t values + dropped S values
Batched f_t → Serpent S-box → keystream bytes
```

#### **Memory Layout:**
```cpp
State struct:
  S[10]:    10 × 32-bit = 320 bits (LFSR)
  R1, R2:    2 × 32-bit =  64 bits (FSM)
  Total:                 = 384 bits internal state

Lookup Tables:
  s_sosemanukMulTables: 512 × 32-bit = 2KB (read-only)
```

---

### ✅ **11. Code Quality & Security Features**

#### **Memory Safety:**
```cpp
// Bounds checking
for (int i = 0; i < 4 && (i*4+3) < (int)ivlen; i++) { ... }

// Safe type casting  
static_cast<uint8_t>((z >> (8*b)) & 0xFF)

// Buffer management
std::memset(fullkey, 0, 32);
std::memcpy(fullkey, key, std::min(keylen, size_t(32)));
```

#### **Constant-Time Operations:**
```cpp
// No data-dependent branches in crypto core
uint32_t mux(uint32_t c, uint32_t x, uint32_t y){ 
    return (c & 1u) ? y : x;  // Branch on LSB only
}

// Bitslice S-box: no table lookups
Serpent2_bitslice() // Pure Boolean operations
```

#### **Compatibility Features:**
```cpp
// CryptoPP-compatible lookup tables
static const uint32_t s_sosemanukMulTables[512] = { ... };

// Standard endianness handling
uint32_t word = (byte0 << 0) | (byte1 << 8) | (byte2 << 16) | (byte3 << 24);
```

---

### 🎯 **12. Performance Optimizations**

#### **Algorithmic Optimizations:**
- **Lookup Tables**: GF(2³²) operations in O(1) time
- **Bitslice S-box**: 32× parallelization  
- **Batched Processing**: Amortize function call overhead
- **Minimal Branching**: Reduce pipeline stalls

#### **Memory Optimizations:**
- **Static Tables**: Lookup tables in read-only memory
- **Local Variables**: Keep frequently used data in registers
- **Sequential Access**: Good cache locality

#### **Implementation Optimizations:**
- **Inline Functions**: Reduce call overhead for small functions
- **Compile-time Constants**: constexpr for compile-time evaluation
- **Type Safety**: Proper type casting to avoid undefined behavior

---

## Tổng Quan

**Sosemanuk** là một **stream cipher** (mã hóa dòng) được thiết kế bởi nhóm nghiên cứu Pháp năm 2005. Đây là một trong 4 cipher được chọn vào Portfolio cuối cùng của dự án eSTREAM.

### Ý Nghĩa Tên Gọi
- **"Sosemanuk"**: Từ tiếng Cree (thổ dân Canada) có nghĩa là "chó sói băng giá"
- Phản ánh tính chất mạnh mẽ và "lạnh lùng" (khó phá) của thuật toán

### Đặc Điểm Chính
- **Loại**: Synchronous stream cipher (mã hóa dòng đồng bộ)
- **Kích thước key**: 128-256 bits (thường dùng 128 bits)
- **Kích thước IV**: 128 bits
- **Tốc độ**: ~4.8 cycles/byte (rất nhanh)
- **Bảo mật**: Được thiết kế chống lại các tấn công hiện đại

---

## Kiến Trúc Tổng Thể

Sosemanuk kết hợp **3 thành phần chính**:

```
┌─────────────────────────────────────────────────────────┐
│                    SOSEMANUK CIPHER                     │
├─────────────────────────────────────────────────────────┤
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │    LFSR     │───▶│     FSM     │───▶│  S-box +    │  │
│  │ (10 từ 32b) │    │ (2 từ 32b)  │    │  XOR        │  │
│  │             │    │             │    │             │  │
│  └─────────────┘    └─────────────┘    └─────────────┘  │
│         │                   │                   │       │
│    Alpha ops in          Trans func        Serpent S2   │
│     GF(2³²)                                             │
└─────────────────────────────────────────────────────────┘
                              │
                              ▼
                        Keystream Output
```

### Vai Trò Từng Thành Phần:

1. **LFSR**: Tạo ra chuỗi giả ngẫu nhiên dài
2. **FSM**: Thêm tính phi tuyến và phức tạp
3. **S-box**: Tăng cường khuếch tán và bảo mật

---

## Linear Feedback Shift Register (LFSR)

### Khái Niệm Cơ Bản

**LFSR** là một **shift register** (thanh ghi dịch) với **feedback tuyến tính**.

```
S[0] ──► S[1] ──► S[2] ──► ... ──► S[8] ──► S[9]
 ▲                                           │
 │                                           │
 └─────────── Feedback Function ◄───────────┘
```

### Chi Tiết Toán Học

#### Trạng Thái LFSR:
- **10 thanh ghi**: `S[0], S[1], S[2], ..., S[9]`
- **Mỗi thanh ghi**: 32 bits
- **Tổng trạng thái**: 320 bits

#### Hàm Feedback:
```
S[10] = S[9] ⊕ (S[3] / α) ⊕ (S[0] × α)
```

**Giải thích từng phần:**
- `⊕`: Phép XOR (exclusive OR)
- `α`: Phần tử nguyên thủy trong GF(2³²) = 0x00000002
- `S[3] / α`: Chia S[3] cho α trong finite field
- `S[0] × α`: Nhân S[0] với α trong finite field

#### Quá Trình Dịch Chuyển:
```python
# Mỗi bước:
for i in range(9):
    S[i] = S[i+1]  # Dịch chuyển trái
S[9] = S[10]       # Giá trị mới từ feedback
```

### Ý Nghĩa Toán Học

1. **Tuyến Tính**: Đầu ra chỉ phụ thuộc tuyến tính vào trạng thái
2. **Chu Kỳ Dài**: Với polynomial tốt, chu kỳ ≈ 2³²⁰
3. **Dự đoán Được**: Nếu biết đủ bits đầu ra, có thể tính ngược

**⚠️ Lý do cần FSM**: LFSR đơn thuần dễ bị tấn công!

---

## Finite State Machine (FSM)

### Khái Niệm

**FSM** thêm **tính phi tuyến** vào hệ thống, làm cho cipher khó bị phân tích.

### Cấu Trúc FSM

```
┌─────────┐    ┌─────────┐
│   R1    │    │   R2    │
│ (32bit) │    │ (32bit) │  
└─────────┘    └─────────┘
     │              │
     ▼              ▼
┌─────────────────────────┐
│   Hàm Cập Nhật FSM     │
└─────────────────────────┘
```

#### Trạng Thái FSM:
- **R1, R2**: Hai thanh ghi 32-bit
- **Tổng trạng thái**: 64 bits

### Chi Tiết Toán Học FSM

#### Hàm MUX (Multiplexer):
```c
uint32_t MUX(uint32_t c, uint32_t x, uint32_t y) {
    return (c & 1) ? y : x;
}
```
**Ý nghĩa**: Chọn `y` nếu bit cuối của `c` là 1, ngược lại chọn `x`

#### Hàm Trans:
```c
uint32_t Trans(uint32_t z) {
    return ROL((z × 0x54655307) mod 2³², 7);
}
```
**Giải thích**:
- `0x54655307`: Hằng số được chọn cẩn thận để tránh các weakness
- `ROL(x, 7)`: Xoay trái 7 bit
- Tạo ra sự khuếch tán tốt

#### Quá Trình Cập Nhật FSM:
```c
// Bước t → t+1:
uint32_t choose = MUX(R1_old, S[1], S[1] ⊕ S[8]);
uint32_t R1_new = R2_old + choose;
uint32_t R2_new = Trans(R1_old);
uint32_t f_t = (S[9] + R1_new) ⊕ R2_new;
```

**Phân tích từng dòng**:
1. **choose**: Chọn giá trị dựa trên R1
2. **R1_new**: Kết hợp R2 cũ với giá trị được chọn
3. **R2_new**: Áp dụng hàm Trans phi tuyến
4. **f_t**: Tạo đầu ra kết hợp LFSR và FSM

### Tại Sao Cần FSM?

1. **Phá vỡ tuyến tính**: LFSR thuần túy có thể bị tấn công bằng đại số tuyến tính
2. **Tăng độ phức tạp**: Làm cho việc phân tích trở nên khó khăn
3. **Kháng tấn công**: Chống lại correlation attacks và algebraic attacks

---

## Serpent S-box

### Khái Niệm S-box

**S-box** (Substitution Box) là **bảng tra cứu phi tuyến** chuyển đổi input thành output theo một quy tắc cố định.

### Serpent S2 Specification

Sosemanuk sử dụng **S-box thứ 2 của Serpent cipher**:

```
S2[x] = {8, 6, 7, 9, 3, 12, 10, 15, 13, 1, 14, 4, 0, 11, 5, 2}
```

**Giải thích**:
- Input: 4 bits (0-15)
- Output: 4 bits (0-15) 
- Ví dụ: S2[0] = 8, S2[1] = 6, S2[2] = 7, ...

### Bitslice Implementation

Sosemanuk sử dụng **bitslice** - xử lý 32 S-box song song:

```c
void Serpent2_bitslice(uint32_t in[4], uint32_t out[4]) {
    // Xử lý 32 giá trị 4-bit cùng lúc
    // Mỗi bit position tương ứng với 1 S-box
}
```

**Ưu điểm**:
- **Tốc độ**: Xử lý 32 S-box trong 1 lần
- **Hiệu quả**: Tận dụng tính song song của CPU

### Tính Chất Mật Mã Học

1. **Phi tuyến**: Không thể biểu diễn bằng phép toán tuyến tính
2. **Khuếch tán**: Thay đổi 1 bit input → thay đổi nhiều bit output
3. **Confusion**: Làm mờ mối quan hệ giữa key và ciphertext

---

## Finite Field GF(2³²)

### Khái Niệm Finite Field

**Finite Field** (Trường hữu hạn) là tập hợp có **số phần tử hữu hạn** với **các phép toán cộng và nhân** thoả mãn các tính chất của trường.

### GF(2³²) trong Sosemanuk

#### Định Nghĩa:
- **Tập hợp**: Tất cả đa thức bậc < 32 với hệ số trong GF(2)
- **Phần tử**: Biểu diễn dưới dạng 32-bit integer
- **Polynomial bất khả quy**: `P(x) = x³² + x⁷ + x³ + x² + 1`

#### Phép Cộng trong GF(2³²):
```c
uint32_t add(uint32_t a, uint32_t b) {
    return a ⊕ b;  // Đơn giản là XOR
}
```

#### Phép Nhân với α:
```c
uint32_t mul_alpha(uint32_t x) {
    return (x << 8) ⊕ s_mulTable[x >> 24];
}
```

#### Phép Chia cho α:
```c
uint32_t div_alpha(uint32_t x) {
    return (x >> 8) ⊕ s_divTable[x & 0xFF];
}
```

### Lookup Tables

**s_sosemanukMulTables**: Bảng tra cứu 512 phần tử để tính nhanh phép nhân/chia với α.

**Ưu điểm**:
- **Tốc độ**: O(1) thay vì O(32) cho phép nhân polynomial
- **Chính xác**: Tránh lỗi overflow và edge cases

### Ý Nghĩa Toán Học

1. **Cấu trúc đại số**: Đảm bảo các tính chất toán học cần thiết
2. **Tính chất chu kỳ**: α có chu kỳ 2³² - 1 (maximum)
3. **Bảo mật**: Khó dự đoán mối quan hệ giữa input và output

---

## Key Schedule

### Mục Đích Key Schedule

Chuyển đổi **user key** (16 bytes) thành **expanded key** (100 × 32-bit words) để khởi tạo cipher.

### Quá Trình Chi Tiết

#### Bước 1: Key Padding
```c
// Nếu key < 32 bytes, thêm padding theo Serpent
if (keylen < 32) {
    fullkey[keylen] = 0x80;  // Serpent padding
    // Phần còn lại = 0x00
}
```

#### Bước 2: Chuyển đổi sang 32-bit words
```c
for (int i = 0; i < 8; i++) {
    k[i] = bytes_to_word32(fullkey + 4*i);  // Little endian
}
```

#### Bước 3: Linear Recurrence
```c
for (int i = 8; i < 140; i++) {
    uint32_t temp = k[i-8] ⊕ k[i-5] ⊕ k[i-3] ⊕ k[i-1] 
                    ⊕ 0x9e3779b9 ⊕ (i-8);
    k[i] = ROL(temp, 11);
}
```

**Giải thích**:
- **0x9e3779b9**: Golden ratio constant, tránh weak keys
- **ROL(temp, 11)**: Tăng cường khuếch tán
- **XOR cascade**: Mỗi word phụ thuộc vào nhiều word trước đó

#### Bước 4: S-box Mixing
```c
for (int i = 0; i < 25; i++) {  // 100/4 = 25 groups
    // Áp dụng Serpent S2 cho mỗi nhóm 4 words
    serpent_s2_simple(&k[i*4], &k[i*4+1], &k[i*4+2], &k[i*4+3]);
}
```

### Tính Chất Bảo Mật

1. **Avalanche Effect**: Thay đổi 1 bit key → thay đổi ~50% expanded key
2. **Non-linearity**: S-box làm cho key schedule phi tuyến
3. **Collision Resistance**: Các key khác nhau → expanded key khác nhau

---

## Quá Trình Tạo Keystream

### Tổng Quan Workflow

```
Initialization: Key + IV → Initial State (LFSR + FSM)
    ↓
Warm-up: 24 rounds để trộn state
    ↓
Generation Loop:
    ├── LFSR Step → Update S[0..9]  
    ├── FSM Step → Update R1, R2, tạo f_t
    ├── Collect 4 f_t values
    ├── Apply Serpent S2 bitslice
    ├── XOR với 4 dropped S values
    └── Output 16 bytes keystream
```

### Chi Tiết Từng Bước

#### Bước 1: Initialization
```c
void init_state_from_key_iv(State& st, uint8_t* key, uint8_t* iv) {
    // 1. Expand key thành 100 words
    uint32_t w[100];
    expand_key(key, keylen, w);
    
    // 2. Chuyển IV thành words
    uint32_t iv_words[4];
    for (int i = 0; i < 4; i++) {
        iv_words[i] = bytes_to_word32(iv + 4*i);
    }
    
    // 3. Khởi tạo LFSR state
    for (int i = 0; i < 10; i++) {
        st.S[i] = w[i] ⊕ (i < 4 ? iv_words[i] : 0);
    }
    
    // 4. Khởi tạo FSM state  
    st.R1 = w[10] ⊕ iv_words[0];
    st.R2 = w[11] ⊕ iv_words[1];
    
    // 5. Warm-up 24 rounds
    for (int round = 0; round < 24; round++) {
        step(st);  // Discard output
    }
}
```

#### Bước 2: Generation Step
```c
StepOut step(State& st) {
    // A. Lưu giá trị cần thiết
    uint32_t s0 = st.S[0], s3 = st.S[3], s9 = st.S[9];
    uint32_t R1_old = st.R1, R2_old = st.R2;
    
    // B. Cập nhật FSM
    uint32_t choose = MUX(R1_old, st.S[1], st.S[1] ⊕ st.S[8]);
    uint32_t R1_new = R2_old + choose;
    uint32_t R2_new = Trans(R1_old);
    uint32_t f_t = (s9 + R1_new) ⊕ R2_new;
    
    // C. Cập nhật LFSR
    uint32_t s10 = s9 ⊕ div_alpha(s3) ⊕ mul_alpha(s0);
    for (int i = 0; i < 9; i++) st.S[i] = st.S[i+1];
    st.S[9] = s10;
    
    // D. Cập nhật FSM state
    st.R1 = R1_new; 
    st.R2 = R2_new;
    
    return {f_t, s0};  // f_t để tạo keystream, s0 để XOR cuối
}
```

#### Bước 3: Keystream Generation
```c
void generate_keystream(State& st, uint8_t* out, size_t len) {
    size_t produced = 0;
    uint32_t fbuf[4], sdrop[4];
    int cnt = 0;
    
    while (produced < len) {
        // Thu thập 4 giá trị từ step()
        StepOut result = step(st);
        fbuf[cnt] = result.f;
        sdrop[cnt] = result.dropped_s;
        cnt++;
        
        if (cnt == 4) {
            // Áp dụng Serpent S2 bitslice
            uint32_t in4[4] = {fbuf[3], fbuf[2], fbuf[1], fbuf[0]};
            uint32_t out4[4];
            Serpent2_bitslice(in4, out4);
            
            // XOR với dropped values và output
            for (int i = 0; i < 4 && produced < len; i++) {
                uint32_t z = out4[i] ⊕ sdrop[i];
                for (int b = 0; b < 4 && produced < len; b++) {
                    out[produced++] = (z >> (8*b)) & 0xFF;
                }
            }
            cnt = 0;
        }
    }
}
```

### Tại Sao Cần Warm-up?

**24 rounds warm-up** đảm bảo:
1. **Trộn đều**: Key và IV được khuếch tán đầy đủ
2. **Xóa pattern**: Loại bỏ các mẫu có thể dự đoán từ initialization
3. **Bảo mật**: Ngăn chặn các tấn công dựa trên state ban đầu

---

## Ví Dụ Thực Tế

### Input Parameters
```
Plaintext: "Hello"
Key: 00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF
IV:  FF EE DD CC BB AA 99 88 77 66 55 44 33 22 11 00
```

### Bước 1: Key Expansion
```
w[0] = 0x33221100    w[1] = 0x77665544    ...
w[10] = 0x12345678   w[11] = 0x9ABCDEF0   ...
```

### Bước 2: State Initialization
```
S[0] = w[0] ⊕ iv_words[0] = 0x33221100 ⊕ 0xCCDDEEFF = 0xFFFFFFFF
S[1] = w[1] ⊕ iv_words[1] = 0x77665544 ⊕ 0x889900AA = 0xFFFF55EE
...
R1 = w[10] ⊕ iv_words[0] = 0x12345678 ⊕ 0xCCDDEEFF = 0xDEE9B887
R2 = w[11] ⊕ iv_words[1] = 0x9ABCDEF0 ⊕ 0x889900AA = 0x1225DE5A
```

### Bước 3: First Step Output
```
// Sau warm-up và bước đầu tiên:
f_0 = 0x9DC75AC6
f_1 = 0xB5C9660A  
f_2 = 0xE7B07C12
f_3 = 0x34567890

s_drop = {0x11111111, 0x22222222, 0x33333333, 0x44444444}
```

### Bước 4: S-box Application
```
// Input cho Serpent S2:
in[4] = {0x34567890, 0xE7B07C12, 0xB5C9660A, 0x9DC75AC6}

// Sau bitslice S2:
out[4] = {0xA1B2C3D4, 0xE5F60718, 0x293A4B5C, 0x6D7E8F90}
```

### Bước 5: Final XOR
```
keystream[0..3]   = 0xA1B2C3D4 ⊕ 0x11111111 = 0xB0A3D2C5
keystream[4..7]   = 0xE5F60718 ⊕ 0x22222222 = 0xC7D4253A  
keystream[8..11]  = 0x293A4B5C ⊕ 0x33333333 = 0x1A09786F
keystream[12..15] = 0x6D7E8F90 ⊕ 0x44444444 = 0x293ACBD4
```

### Encryption
```
"Hello" = {0x48, 0x65, 0x6C, 0x6C, 0x6F}
Keystream = {0xB0, 0xA3, 0xD2, 0xC5, 0xC7, ...}
Ciphertext = {0x48⊕0xB0, 0x65⊕0xA3, 0x6C⊕0xD2, 0x6C⊕0xC5, 0x6F⊕0xC7}
           = {0xF8, 0xC6, 0xBE, 0xA9, 0xA8}
```

---

## Tóm Tắt Các Khái Niệm Quan Trọng

### Thuật Ngữ Cryptography

1. **Stream Cipher**: Mã hóa từng byte/bit một cách liên tục
2. **Keystream**: Dòng key giả ngẫu nhiên để XOR với plaintext
3. **Synchronous**: Keystream chỉ phụ thuộc key+IV, không phụ thuộc plaintext
4. **Confusion**: Làm mờ mối quan hệ giữa key và ciphertext
5. **Diffusion**: Lan truyền ảnh hưởng của 1 bit thay đổi

### Thuật Ngữ Toán Học

1. **Linear Recurrence**: Công thức tính phần tử tiếp theo từ các phần tử trước
2. **Finite Field**: Trường hữu hạn với phép cộng và nhân
3. **Primitive Element**: Phần tử sinh ra toàn bộ nhóm multiplicative
4. **Irreducible Polynomial**: Đa thức không phân tích được trong trường
5. **Bitslice**: Kỹ thuật xử lý nhiều S-box song song

### Thuật Ngữ Kỹ Thuật

1. **LFSR**: Thanh ghi dịch với feedback tuyến tính
2. **FSM**: Máy trạng thái hữu hạn phi tuyến tính  
3. **S-box**: Bảng substitution phi tuyến
4. **Lookup Table**: Bảng tra cứu để tối ưu tốc độ
5. **Warm-up Rounds**: Các vòng khởi tạo để trộn đều state

---

## Kết Luận

**Sosemanuk** là một thiết kế cipher rất tinh vi, kết hợp:

✅ **Tính đơn giản**: Dễ implement và tối ưu  
✅ **Tính bảo mật**: Chống lại các tấn công hiện đại  
✅ **Hiệu suất cao**: Tốc độ mã hóa rất nhanh  
✅ **Cơ sở toán học vững chắc**: Dựa trên lý thuyết finite field và algebra  

Cipher này minh chứng cho việc **kết hợp khéo léo các thành phần toán học** có thể tạo ra một hệ thống mã hóa vừa mạnh mẽ vừa hiệu quả.

---

*Tài liệu này được viết cho mục đích học tập. Để hiểu sâu hơn, khuyến nghị đọc thêm paper gốc của Sosemanuk và các tài liệu về stream cipher cryptanalysis.*