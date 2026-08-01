# Tài liệu công cụ — OWASP ZAP (DAST)

**Loại:** Dynamic Application Security Testing — quét ứng dụng đang chạy qua HTTP, không cần source.

**Cách hoạt động:** ZAP Baseline Scan crawl app tại `http://localhost:3000` rồi chạy passive/active checks, báo cáo alert kèm mức rủi ro.

**Đọc kết quả JSON:**
- `site[].alerts[]` — danh sách cảnh báo theo site.
- `name` / `alert` — tên lỗ hổng (ví dụ `SQL Injection`, `Cross Site Scripting (Reflected)`).
- `riskdesc` — mức rủi ro (`High`, `Medium`, `Low`, `Informational`).
- `desc` — mô tả.
- `instances[].uri` — URL cụ thể dính lỗi.

**Ánh xạ trong Sentinel:** `scripts/parse_results.py` duyệt `site[].alerts[]` → cùng schema chung với Semgrep, lấy `instances[0].uri` làm `path_or_url`.

**Giới hạn:** DAST chỉ thấy phần app đã crawl tới; endpoint ẩn/cần auth có thể bị bỏ sót → kết hợp SAST để phủ rộng hơn.
