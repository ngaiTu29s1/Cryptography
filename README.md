# Triển khai Mã hóa Sosemanuk

Repository này chứa một triển khai C của stream cipher Sosemanuk.

## Biên dịch

Biên dịch tất cả công cụ sử dụng Makefile được cung cấp:

```bash
make all
```

Điều này sẽ biên dịch:
- `main` - Xác thực test vector và đo hiệu năng
- `testvectors` - Tạo test vector
- `simple_sosemanuk` - Công cụ mã hóa/giải mã đơn giản

## Công cụ

### main (Xử lý hàng loạt - Xác thực Test Vector)

Xác thực triển khai Sosemanuk với test vector và đo hiệu năng.

#### Cách sử dụng
```bash
./main
```

#### Công cụ này làm gì:
1. **Đọc test vector** từ `test_vector.txt`
2. **Xác thực mã hóa/giải mã** cho từng test vector
3. **Đo hiệu năng** (throughput tính bằng MB/s)
4. **Báo cáo kết quả pass/fail** cho từng vector

#### Ví dụ đầu ra:
```
=== Test Vector 1 ===
Key: 00112233445566778899AABBCCDDEEFF00000000000000000000000000000000
IV: 8899AABBCCDDEEFF0011223344556677
Plaintext (hex): 48656C6C6F20576F726C642100000000
Ciphertext Expected (hex): A15CD3BE3FF2C33BDD1C2AB190F1D841
Ciphertext Computed (hex): A15CD3BE3FF2C33BDD1C2AB190F1D841
Ciphertext Result: PASS
Recovered Plaintext Result: PASS
Overall Result: PASS
Time for 10000 encryptions: 45 ms
Throughput: 3.55 MB/s

=== Summary ===
Total vectors: 20
Passed: 20
Failed: 0
Overall Throughput: 3.52 MB/s
```

### simple_sosemanuk (Xử lý đơn - I/O dựa trên file)

Công cụ mã hóa/giải mã đơn giản xử lý key, IV và dữ liệu từ file input.

#### Cách sử dụng

```bash
# Mã hóa
./simple_sosemanuk -e input.txt output.bin

# Giải mã từ hex
./simple_sosemanuk -d input.txt

# Giải mã từ hex (cách khác)
./simple_sosemanuk -h input.txt
```

#### Định dạng file input

**Mã hóa:**
```
key=<32_byte_hex_key>
iv=<16_byte_hex_iv>
plaintext=<text_or_hex_data>
```

**Giải mã từ hex:**
```
key=<32_byte_hex_key>
iv=<16_byte_hex_iv>
ciphertext=<hex_data>
```

#### Quy trình ví dụ

1. **Mã hóa** và lấy đầu ra hex:
```bash
./simple_sosemanuk -e encrypt_input.txt message.enc
# Đầu ra: Ciphertext (hex): A66EBE857935C9CBE27C77362A6099B585D64A8C231FC4D800EF733F44F78A1BF5002B6EE80AF7723E413AA7937DAAA59592748FB2BE0463CC3B7944E3
```

2. **Copy hex** vào file decrypt input

3. **Giải mã** từ hex:
```bash
./simple_sosemanuk -d decrypt_input.txt
# Đầu ra: Recovered plaintext: Hello World! This is a test message for Sosemanuk encryption.
```

### testvectors (Tạo Test Vector)

Tạo test vector để xác thực.

#### Cách sử dụng
```bash
./testvectors
```

## Test Vector

File `test_vector.txt` chứa 20 test vector để xác thực triển khai Sosemanuk. Mỗi vector bao gồm:
- Key 32-byte (hex)
- IV 16-byte (hex)
- Cặp plaintext/ciphertext 16-byte
- Keystream mong đợi

## Hiệu năng

Throughput điển hình trên phần cứng hiện đại:
- ~3-5 MB/s cho chế độ xác thực (main.c)
- Có thể đạt throughput cao hơn với build được tối ưu

## Yêu cầu

- Trình biên dịch GCC
- Thư viện C chuẩn
- Môi trường Unix-like (Linux/macOS) hoặc MinGW (Windows)
