# Test Vectors Generator

## 🔧 Quick Usage

### 1. Build the generator:
```bash
# From project root:
cd test_vectors
g++ -std=c++17 generate_test_vectors.cpp ../components/components.cpp ../components/io_handler.cpp -I ../components -o generate_test_vectors.exe
```

### 2. Create input file:
Format: `plaintext|key|iv` (one per line)

Example (`my_input.txt`):
```
Hello World|00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF|FF EE DD CC BB AA 99 88 77 66 55 44 33 22 11 00
Test Message|12 34 56 78 9A BC DE F0 FE DC BA 98 76 54 32 10|01 23 45 67 89 AB CD EF EF CD AB 89 67 45 23 01
```

### 3. Generate test vectors:
```bash
.\generate_test_vectors.exe my_input.txt my_output.txt
```

## 📁 Files

- **`generate_test_vectors.cpp`** - Generator source code
- **`generate_test_vectors.exe`** - Compiled generator tool
- **`input_example.txt`** - Example input file
- **`test_data.txt`** - Original test vectors
- **`generated_vectors.txt`** - Example generated output

## ⚡ One-liner Example

```bash
# Build + run in one go:
g++ -std=c++17 generate_test_vectors.cpp ../components/*.cpp -I ../components -o gen.exe && .\gen.exe input_example.txt new_output.txt
```

## 📝 Output Format

Generated file compatible with main program's test vector format:
```
plaintext=Hello World
key=00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF
iv=FF EE DD CC BB AA 99 88 77 66 55 44 33 22 11 00
keystream=9D C7 5A C6 B5 C9 66 0A E7 B0 7C
expected_ciphertext=D5 A2 36 AA DA E9 31 65 95 DC 18
expected_recovered=Hello World
---
```