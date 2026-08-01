# Ví dụ lỗ hổng — Sensitive Data Exposure / Crypto Failures (A02)

**Target:** http://localhost:3000
**Endpoint:** GET `/ftp`
**Nhóm:** A02 Cryptographic Failures · CWE-311 / CWE-916

Quan sát: thư mục `/ftp` để lộ file nhạy cảm; password người dùng hash bằng MD5 không salt → dễ crack qua rainbow table.

**Evidence (lab):** dump bảng Users cho hash MD5; tra ngược ra mật khẩu gốc.
**Recommendation:** hash bằng bcrypt/argon2 + salt; không public thư mục file; mã hoá dữ liệu nhạy cảm at-rest & in-transit (TLS).

Mapped challenge: *Confidential Document*, *Password Strength*.
