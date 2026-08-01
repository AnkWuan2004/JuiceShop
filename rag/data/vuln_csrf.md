# Ví dụ lỗ hổng — Cross-Site Request Forgery (A01)

**Target:** http://localhost:3000
**Endpoint:** POST `/api/Users` / thao tác đổi trạng thái không có anti-CSRF
**Nhóm:** A01 Broken Access Control · CWE-352

Quan sát: request thay đổi trạng thái chỉ dựa vào cookie phiên, không có CSRF token → trang độc bên ngoài có thể tự động submit thay người dùng đã đăng nhập.

**Evidence (lab):** form ẩn trên site khác gửi POST tới app → hành động thực thi với session nạn nhân.
**Recommendation:** dùng CSRF token per-session; `SameSite=Lax/Strict` cho cookie; yêu cầu re-auth cho thao tác nhạy cảm.

Mapped challenge: *CSRF*.
