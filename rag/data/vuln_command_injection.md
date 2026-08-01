# Ví dụ lỗ hổng — Command / Code Injection (A03)

**Target:** http://localhost:3000
**Endpoint:** POST `/api/Feedbacks` (và các field nhận biểu thức)
**Nhóm:** A03 Injection · CWE-78 (OS Command) / CWE-94 (Code Injection)

Quan sát: input truyền vào hàm thực thi hệ thống hoặc eval mà không lọc → chạy được lệnh/biểu thức tuỳ ý (ví dụ payload tính toán làm treo server).

**Evidence (lab):** field chấp nhận biểu thức lồng gây tiêu tốn CPU bất thường / lỗi 500.
**Recommendation:** không dùng `eval`/exec với input người dùng; allow-list tham số; chạy tác vụ trong sandbox; giới hạn tài nguyên.

Mapped challenge: *Local File Read*, *Christmas Special*.
