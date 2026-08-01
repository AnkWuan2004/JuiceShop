# Ví dụ lỗ hổng — Server-Side Request Forgery (A10)

**Target:** http://localhost:3000
**Endpoint:** POST `/api/Users` (field ảnh đại diện qua URL) / `/profile/image/url`
**Nhóm:** A10 SSRF · CWE-918

Quan sát: server tải nội dung từ URL do người dùng cung cấp mà không giới hạn đích → có thể ép gọi tới host nội bộ hoặc endpoint metadata cloud.

**Evidence (lab):** đặt URL ảnh trỏ về `http://localhost` nội bộ → server tự gửi request.
**Recommendation:** allow-list domain đích; chặn IP nội bộ/link-local (169.254.169.254); không cho redirect tuỳ ý; tách network egress.

Mapped challenge: *SSRF*.
