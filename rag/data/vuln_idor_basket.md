# Ví dụ lỗ hổng — IDOR / Broken Access Control (A01)

**Target:** http://localhost:3000
**Endpoint:** GET `/rest/basket/1`
**Nhóm:** A01 Broken Access Control · CWE-639 (IDOR/BOLA)

Quan sát: đổi id trong `/rest/basket/{id}` sang id người khác vẫn trả về giỏ hàng của họ — server không kiểm tra owner so với JWT.

**Evidence (lab):** đăng nhập user A, gọi `/rest/basket/2` (của user B) → 200 kèm dữ liệu B.
**Recommendation:** kiểm tra quyền sở hữu object theo user trong token; từ chối 403 khi id không thuộc về caller.

Mapped challenge: *View Basket*, *Manipulate Basket*.
