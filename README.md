# Sosemanuk Cipher

Triển khai C của stream cipher Sosemanuk.

## Biên dịch

```bash
make all
```

Tạo các file: `main`, `testvectors`, `simple_sosemanuk`.

## Công cụ

### main
Xác thực test vector và đo hiệu năng.

```bash
./main
```

Đọc `test_vector.txt`, kiểm tra mã hóa/giải mã, in kết quả pass/fail và tốc độ.

### simple_sosemanuk
Mã hóa/giải mã đơn giản từ file.

```bash
# Mã hóa
./simple_sosemanuk -e input.txt output.bin

# Giải mã từ hex
./simple_sosemanuk -h input.txt
```

**File input cho mã hóa:**
```
key=<32_byte_hex>
iv=<16_byte_hex>
plaintext=<text>
```

**File input cho giải mã:**
```
key=<32_byte_hex>
iv=<16_byte_hex>
ciphertext=<hex>
```

### testvectors
Tạo test vector.

```bash
./testvectors
```

Tạo `test_vector.txt` với 20 vector.

## Ví dụ

1. Tạo input:
   ```
   key=00112233445566778899AABBCCDDEEFF00000000000000000000000000000000
   iv=8899AABBCCDDEEFF0011223344556677
   plaintext=Hello World!
   ```

2. Mã hóa: `./simple_sosemanuk -e input.txt out.bin`

3. Copy hex từ terminal vào file decrypt.

4. Giải mã: `./simple_sosemanuk -h decrypt.txt`
