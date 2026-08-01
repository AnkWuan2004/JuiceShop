# OWASP Top 10 (2021) — Tổng quan 10 nhóm rủi ro

Danh mục chuẩn để phân loại lỗ hổng web. Dùng làm khung tham chiếu cho báo cáo bảo mật.

- **A01 — Broken Access Control:** người dùng làm được việc ngoài quyền (IDOR/BOLA, đổi role, truy cập object của người khác). Juice Shop: xem/sửa basket người khác, vào `/rest/admin`.
- **A02 — Cryptographic Failures:** dữ liệu nhạy cảm lộ do mã hoá yếu/thiếu (MD5 password, không TLS, hash không salt). Juice Shop: password hash MD5.
- **A03 — Injection:** dữ liệu không tin cậy được diễn giải như lệnh (SQL Injection, XSS, Command Injection). Juice Shop: `/rest/products/search` SQLi.
- **A04 — Insecure Design:** thiếu kiểm soát ở tầng thiết kế (không có rate-limit, luồng business bị lạm dụng).
- **A05 — Security Misconfiguration:** cấu hình sai (bật debug/stack trace, default creds, header thiếu, XXE do parser cấu hình sai).
- **A06 — Vulnerable and Outdated Components:** dùng thư viện có CVE (Log4Shell CVE-2021-44228, Struts CVE-2017-5638).
- **A07 — Identification and Authentication Failures:** xác thực yếu (brute force, JWT `alg=none`, session cố định). Juice Shop: `/rest/user/login` bypass.
- **A08 — Software and Data Integrity Failures:** deserialization không an toàn, CI/CD không kiểm tra tính toàn vẹn, cập nhật không ký.
- **A09 — Security Logging and Monitoring Failures:** thiếu log/alert nên không phát hiện tấn công.
- **A10 — Server-Side Request Forgery (SSRF):** server bị ép gọi tới URL do kẻ tấn công kiểm soát (nội bộ, metadata cloud).

**Cách dùng trong Sentinel:** mỗi cảnh báo từ Semgrep/ZAP được gán về 1 nhóm A0x để agent giải thích và ưu tiên xử lý.
