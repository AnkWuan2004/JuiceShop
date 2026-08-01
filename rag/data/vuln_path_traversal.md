# Ví dụ lỗ hổng — Path Traversal (A01/A05)

**Target:** http://localhost:3000
**Endpoint:** GET `/ftp/../` (và tham số tên file)
**Nhóm:** A01 Broken Access Control · CWE-22 (Path Traversal)

Quan sát: tên file không được chuẩn hoá → dùng `../` hoặc null-byte/Poison-Null để thoát thư mục và đọc file ngoài phạm vi cho phép.

**Evidence (lab):** `/ftp/package.json.bak%2500.md` bypass bộ lọc đuôi file để tải file cấm.
**Recommendation:** canonicalize path và kiểm tra nằm trong base dir; allow-list đuôi file; không tin phần mở rộng do client gửi.

Mapped challenge: *Access Log*, *Poison Null Byte*.
