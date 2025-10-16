# Sosemanuk Stream Cipher - Giải Thích Chi Tiết Thuật Toán

## 📋 Mục Lục
1. [Tổng Quan](#tổng-quan)
2. [Kiến Trúc Tổng Thể](#kiến-trúc-tổng-thể)
3. [Linear Feedback Shift Register (LFSR)](#linear-feedback-shift-register-lfsr)
4. [Finite State Machine (FSM)](#finite-state-machine-fsm)
5. [Serpent S-box](#serpent-s-box)
6. [Finite Field GF(2³²)](#finite-field-gf2³²)
7. [Key Schedule](#key-schedule)
8. [Quá Trình Tạo Keystream](#quá-trình-tạo-keystream)
9. [Ví Dụ Thực Tế](#ví-dụ-thực-tế)

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