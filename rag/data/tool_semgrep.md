# Tài liệu công cụ — Semgrep (SAST)

**Loại:** Static Application Security Testing — quét mã nguồn tĩnh, không cần chạy app.

**Cách hoạt động:** so khớp mã nguồn với rule (pattern) theo ngôn ngữ. Rule của Juice Shop chủ yếu cho JavaScript/TypeScript trong `juice-shop/routes/*.ts`.

**Đọc kết quả JSON:**
- `results[]` — mỗi phần tử là 1 finding.
- `check_id` — tên rule (ví dụ `javascript.lang.security.audit.sqli.node-sqli`).
- `path` + `start.line` — vị trí trong source.
- `extra.severity` — `ERROR` / `WARNING` / `INFO`.
- `extra.message` — mô tả lỗi.

**Ánh xạ trong Sentinel:** `scripts/parse_results.py` đọc `results[]` → bảng `vulnerabilities` với schema chung `(tool, severity, name, description, path_or_url)`.

**Giới hạn:** SAST hay có false positive (báo lỗi trên code không thực sự khai thác được); cần agent lọc theo bằng chứng, không tin tuyệt đối.
