# Sosemanuk Stream Cipher Implementation

A complete implementation of the Sosemanuk stream cipher following the official specification. This project includes proper Serpent S2 S-box, GF(2^32) alpha operations, and key schedule for cryptographic research and educational purposes.

## 🚀 Features

- ✅ **Serpent S2 S-box** - Correct implementation according to specification
- ✅ **GF(2^32) Operations** - Proper alpha multiplication/division in finite field
- ✅ **Key Schedule** - Serpent-based key expansion 
- ✅ **Test Vectors** - Batch processing with validation
- ✅ **Cross-platform** - Works on Windows, Linux, macOS

## 📋 Prerequisites

### Windows
- **MSYS2** with UCRT64 environment
- **MinGW-w64 GCC** compiler
- **Crypto++ library** (optional, for reference)

### Linux/macOS
- **GCC** or **Clang** with C++17 support
- **Make** (optional)

## ⚙️ VS Code Ready-to-Use

### Prerequisites
- C++ development environment (GCC/MinGW)  
- VS Code with C/C++ extension

### 🚀 Quick Start
The project includes pre-configured VS Code settings in `.vscode/` folder:
- ✅ **tasks.json** - Build & run tasks
- ✅ **launch.json** - Debug configuration  
- ✅ **c_cpp_properties.json** - IntelliSense settings
- ✅ **settings.json** - Workspace settings

**Just 3 steps:**
1. Clone: `git clone https://github.com/ngaiTu29s1/Cryptography.git`
2. Open folder in VS Code
3. Press `Ctrl+Shift+P` → `Tasks: Run Task` → `build && run`

### 🔧 Available Tasks
- **`build: sose_test (ucrt64)`** - Compile with GCC
- **`run: exe (PowerShell)`** - Execute program  
- **`build && run`** - Build and run in sequence

### ⚠️ Path Configuration
If your GCC is not in `C:/msys64/ucrt64/bin/`, edit `.vscode/tasks.json`:
```json
"command": "g++",  // Use system PATH instead
```

## 📁 Project Structure

```
Cryptography/
├── main.cpp                    # Main test program
├── components/
│   ├── components.h           # Sosemanuk algorithm header
│   ├── components.cpp         # Core implementation
│   └── io_handler.cpp         # Test vector I/O
├── test_vectors/
│   └── test_data.txt         # Test cases
├── .vscode/                  # VS Code configuration
│   ├── tasks.json           # Build tasks
│   └── launch.json          # Debug configuration
└── README.md                # This file
```

## 🧪 Test Vectors

The project includes test vectors in `test_vectors/test_data.txt`:

```
plaintext=Hello Sosemanuk!
key=0123456789ABCDEF0123456789ABCDEF
iv=FEDCBA9876543210FEDCBA9876543210
expected_ciphertext=
expected_recovered=Hello Sosemanuk!
```

## 🔬 Algorithm Details

### Sosemanuk Components
- **LFSR**: 10 32-bit registers with alpha operations in GF(2^32)
- **FSM**: 2 32-bit registers with Trans function
- **S-box**: Serpent S2 for output transformation
- **Key Schedule**: Serpent-based expansion to 100 words

### GF(2^32) Operations
- **Polynomial**: x³² + x⁷ + x³ + x² + 1
- **Alpha**: 0x00000002 (primitive element)
- **Alpha⁻¹**: 0x80000069 (multiplicative inverse)

## 🚨 Security Notice

This implementation is for **educational and research purposes only**. Do not use in production systems without proper security audit and validation.

## 📚 References

- [Sosemanuk Specification](https://cr.yp.to/streamciphers/sosemanuk/desc.pdf)
- [eSTREAM Project](http://www.ecrypt.eu.org/stream/)
- [Crypto++ Library](https://www.cryptopp.com/wiki/Sosemanuk)

## 📄 License

This project is for academic use in Cryptography Subject.
**Let's get A+! 🎯**