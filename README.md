# Sosemanuk Stream Cipher Implementation

An educational implementation of the Sosemanuk stream cipher for Cryptography coursework. This project demonstrates core cryptographic concepts including stream ciphers, S-boxes, finite field operations, and key scheduling.

## 🎓 Educational Features

- ✅ **Stream Cipher Concepts** - LFSR and FSM components
- ✅ **Serpent S2 S-box** - Uses Serpent's 2nd S-box (not S24!)
- ✅ **GF(2^32) Operations** - Finite field arithmetic
- ✅ **Key Schedule** - Serpent-inspired key expansion
- ✅ **Meaningful Tests** - Crypto properties validation
- ✅ **Cross-platform** - Windows development environment

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
├── main.cpp                    # Main demo program (comprehensive testing)
├── components/
│   ├── components.h           # Sosemanuk algorithm header
│   ├── components.cpp         # Core implementation  
│   ├── io_handler.h          # I/O utilities header
│   └── io_handler.cpp         # Test vector I/O
├── test_vectors/
│   ├── generate_test_vectors.cpp # Test vector generator source
│   ├── generate_test_vectors.exe # Compiled generator tool
│   ├── input_example.txt      # Example input format
│   ├── test_data.txt         # Educational test cases
│   └── README.md             # Generator usage guide
├── .vscode/                  # VS Code configuration
│   ├── tasks.json           # Build tasks
│   ├── launch.json          # Debug configuration
│   └── c_cpp_properties.json # IntelliSense settings
└── README.md                # Documentation
```

## 🧪 Educational Tests

### **Main Demo** (`main.cpp`)
- ✅ **Complete test vector processing** - Batch testing with multiple vectors
- ✅ **Encryption/Decryption validation** - Perfect round-trip verification  
- ✅ **Key/IV/Keystream display** - Full cryptographic workflow demonstration
- ✅ **Expected vs Actual comparison** - Automatic validation with [OK]/[FAIL] status
- ✅ **Educational output format** - Clear, readable results for learning

The main program provides comprehensive testing that covers all necessary cryptographic validation.

## 🔬 Algorithm Details

### Sosemanuk Components
- **LFSR**: 10 32-bit registers with alpha operations in GF(2^32)
- **FSM**: 2 32-bit registers with Trans function
- **S-box**: Serpent S2 (2nd S-box of Serpent, not "S24")
- **Key Schedule**: Serpent-based expansion to 100 words

### 📝 S-box Clarification
**Important Note**: Sosemanuk uses **Serpent S2** (the 2nd S-box from Serpent cipher), not "Serpent S24". This is confirmed by the CryptoPP reference implementation. The confusion might arise from:
- Serpent has 8 S-boxes (S0, S1, S2, S3, S4, S5, S6, S7)
- Sosemanuk specifically uses the S2 S-box for output transformation
- "S24" is not a standard Serpent S-box designation

### GF(2^32) Operations
- **Polynomial**: x³² + x⁷ + x³ + x² + 1
- **Alpha**: 0x00000002 (primitive element)
- **Alpha⁻¹**: 0x80000069 (multiplicative inverse)

## 🚨 Security Notice

This implementation is for **educational and research purposes only**. Do not use in production systems without proper security audit and validation.

## 📚 Tài Liệu Chi Tiết

### 🔬 [docs/](./docs/) - Detailed Documentation
- **[SOSEMANUK_DETAILED.md](./docs/SOSEMANUK_DETAILED.md)**: Giải thích chi tiết thuật toán bằng tiếng Việt
- **Toán học**: Linear algebra, Finite fields, LFSR, FSM 
- **Thuật ngữ**: Giải thích mọi khái niệm cryptography
- **Ví dụ**: Workflow step-by-step từ key/IV đến keystream

### 📖 References
- [Sosemanuk Specification](https://cr.yp.to/streamciphers/sosemanuk/desc.pdf)
- [eSTREAM Project](http://www.ecrypt.eu.org/stream/)
- [Crypto++ Library](https://www.cryptopp.com/wiki/Sosemanuk)

## 📄 License

This project is for academic use in Cryptography Subject.