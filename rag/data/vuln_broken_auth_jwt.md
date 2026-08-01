# Ví dụ lỗ hổng — Broken Authentication / JWT (A07)

**Target:** http://localhost:3000
**Endpoint:** POST `/rest/user/login`
**Nhóm:** A07 Identification & Authentication Failures · CWE-287

Quan sát: login cho phép SQLi ở field email (`' OR 1=1--`) để bypass; JWT sau đó có thể bị chấp nhận với `alg=none` nếu server không ép thuật toán.

**Evidence (lab):** payload `admin@juice-sh.op'--` đăng nhập admin không cần mật khẩu.
**Recommendation:** parameterized query cho auth; ép whitelist thuật toán JWT (HS256/RS256), verify chữ ký; khoá brute-force.

Mapped challenge: *Login Admin*, *Login Bender*.
