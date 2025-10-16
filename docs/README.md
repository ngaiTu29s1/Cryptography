# 📚 Tài Liệu Kỹ Thuật - Sosemanuk Implementation

## 📋 Danh Mục Tài Liệu

### 🔬 [SOSEMANUK_DETAILED.md](./SOSEMANUK_DETAILED.md)
**Giải thích chi tiết thuật toán Sosemanuk**
- 🧮 **Toán học**: Linear algebra, Finite fields, Polynomial arithmetic
- 🔧 **Thành phần**: LFSR, FSM, S-box, Key schedule  
- 📊 **Ví dụ**: Workflow từ key/IV đến keystream
- 📖 **Thuật ngữ**: Giải thích mọi khái niệm cryptography
- 🎯 **Mục đích**: Để team members hiểu hoàn toàn cách hoạt động

---

## 🎯 Mục Đích Thư Mục

Thư mục `docs/` chứa **tài liệu kỹ thuật chi tiết** để:

✅ **Giáo dục**: Giúp các thành viên nhóm hiểu sâu thuật toán  
✅ **Tham khảo**: Tra cứu các khái niệm và công thức toán học  
✅ **Documentation**: Lưu trữ kiến thức cho dự án  
✅ **Review**: Chuẩn bị cho việc trình bày và báo cáo  

---

## 🔗 Tài Liệu Liên Quan

### 📁 Trong Project
- [README.md](../README.md) - Hướng dẫn sử dụng chung
- [components/](../components/) - Source code implementation
- [test_vectors/](../test_vectors/) - Test data và tools

### 📚 Tài Liệu Gốc
- [Sosemanuk Paper](https://cr.yp.to/streamciphers/sosemanuk.html) - Specification gốc
- [eSTREAM Portfolio](http://www.ecrypt.eu.org/stream/) - Dự án eSTREAM
- [Crypto++ Implementation](https://github.com/weidai11/cryptopp) - Reference code

---

## 💡 Cách Đọc Tài Liệu

### 📖 Cho Người Mới Bắt Đầu:
1. Đọc **Tổng Quan** để nắm ý tưởng chính
2. Hiểu **Kiến Trúc Tổng Thể** trước khi đi vào chi tiết
3. Đọc từng thành phần: **LFSR → FSM → S-box**
4. Xem **Ví Dụ Thực Tế** để cụ thể hóa

### 🔬 Cho Người Có Kinh Nghiệm:
1. Tập trung vào **Chi Tiết Toán Học** của từng section
2. Phân tích **Security Properties** và **Attack Resistance**
3. Đối chiếu với **Implementation** trong source code
4. Review **Performance Considerations**

---

*📝 Note: Tài liệu được viết bằng tiếng Việt để dễ hiểu cho team. Các thuật ngữ kỹ thuật giữ nguyên tiếng Anh để chuẩn quốc tế.*