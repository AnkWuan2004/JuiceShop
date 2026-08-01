# Ví dụ lỗ hổng — Security Misconfiguration (A05)

**Target:** http://localhost:3000
**Endpoint:** GET `/rest/admin/application-version`
**Nhóm:** A05 Security Misconfiguration · CWE-16 / CWE-209

Quan sát: lỗi ứng dụng trả về stack trace chi tiết; một số route admin/nội bộ không được bảo vệ; header bảo mật (CSP, X-Frame-Options) thiếu.

**Evidence (lab):** gửi input sai kiểu → response lộ đường dẫn file và loại DB.
**Recommendation:** tắt debug/verbose error ở production; ẩn thông tin phiên bản; thêm security headers; chặn route quản trị bằng gateway (allowlist).

Mapped challenge: *Error Handling*, *Deprecated Interface*.
