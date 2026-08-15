# Week 4 — API Gateway & kiểm thử request an toàn

**Project:** Sentinel · **Target:** OWASP Juice Shop (Docker Compose, localhost) · **Đề:** VinUni × VinSOC — lộ trình 6 tuần, Tuần 4: "API Gateway và kiểm thử request an toàn"

> Ghi chú số tuần: nền tảng của deliverable này (Kong Gateway + Agent IAM) được dựng sớm và báo cáo
> dưới nhãn nội bộ "Tuần 2" (`reports/week-2/`), lệch với số tuần thật của đề PDF — đã ghi nhận trong
> `reports/gap-analysis-week1-3.md` mục 3. Report này chốt phần hoàn thiện deliverable đúng theo yêu
> cầu Tuần 4 của đề gốc.

## Quá trình

Report Tuần 2 dựng xong hàng rào chính của Kong (key-auth + ACL + path-deny cho `/rest/admin`) và
tự đánh giá là nền tảng, chưa đủ điều kiện nộp Tuần 4 đầy đủ — còn thiếu Python tool hoàn chỉnh,
allowlist vận hành, danh mục payload an toàn theo đúng đề, nhật ký request/response redact key, và
demo agent tự đề xuất kèm tool tự thực thi. Tuần này hoàn thiện các hạng mục còn lại:

1. **Python HTTP tool** (`agents/kong_http_tool.py`): GET/POST/PUT/PATCH qua header `apikey`, đọc
   status code và cắt response theo `max_response_bytes`, timeout riêng cho từng request, bốn nhóm
   payload an toàn cố định (`SAFE_BODIES`): rỗng, chuỗi dài 500 ký tự, ký tự đặc biệt, giá trị sai
   kiểu — đúng bốn loại đề bài liệt kê, không có payload phá hoại.
2. **Allowlist vận hành** (`kong/allowlist.json`): kiểm tra phía client (host chỉ localhost, method,
   path prefix/deny theo từng agent) chạy trước khi gọi Kong, chặn cứng bằng `PermissionError` khi
   vi phạm chính sách.
3. **Nhật ký không lộ khóa**: `append_log()` redact cả giá trị key thật lẫn pattern
   `apikey: ...` trước khi ghi `data-lake/request_log.jsonl`.
4. **Demo Agent đề xuất → tool thực thi**: `agents/exploit_agent.py` — LLM sinh JSON
   `{action, dangerous, request:{method,path,params}}`, hành động nguy hiểm bắt buộc qua HITL
   (`hitl_cli.py`) trước khi `execute_request()` gửi request qua gateway. Toàn bộ chuỗi được ghi lại:
   `hitl_decisions.jsonl` (approve/reject) → `exploit_result.json` (kết quả request).
5. **Khép gap rate-limit**: plugin `rate-limiting` trong `kong/kong.yml` trước đó chỉ gắn ở service
   `juice-shop-write` (20/phút); service `juice-shop-read` (GET của recon-agent) không có giới hạn.
   Đã thêm `rate-limiting` 60/phút vào `juice-shop-read`, cùng test mới
   `tests/test_kong_rate_limit_read.py` (burst 65 GET, kỳ vọng 429 ở các request cuối).

**Xác minh sống**: môi trường làm việc không có Docker/quyền root để dựng Kong container theo cách
thông thường. Để xác minh hành vi thật thay vì chỉ đọc code tĩnh, Juice Shop được chạy trực tiếp
bằng Node (`tsx app.ts`, không qua Docker) và một gateway thay thế được viết bằng Python, đọc trực
tiếp file cấu hình thật `kong/kong.yml` (không hard-code luật riêng) để thực thi đúng ngữ nghĩa
key-auth, ACL, rate-limiting và path-deny, sau đó proxy sang Juice Shop thật. Đề bài chấp nhận
"Kong, Nginx hoặc một gateway đơn giản" nên đây là phương án hợp lệ trong điều kiện không có Docker;
đây không phải Kong container thật, và cần đối chiếu lại bằng Kong thật khi có môi trường đủ điều
kiện.

## Kết quả — đối chiếu tiêu chí PDF Tuần 4

| Sản phẩm bàn giao / Tiêu chí hoàn thành | Trạng thái | Bằng chứng |
|---|---|---|
| API Gateway hoạt động trước app | ✅ | `docker-compose.yml` (service `kong`) + `kong/kong.yml` |
| API key riêng cho công cụ kiểm thử | ✅ | consumers `recon-agent` / `exploit-agent`, key riêng |
| Chỉ truy cập endpoint trong allowlist | ✅ | Kong ACL + path-deny (hard control) + `kong/allowlist.json` (client) |
| Python Tool GET/POST/header/status + response | ✅ | `agents/kong_http_tool.py` |
| Giới hạn request/phút | ✅ | write 20/phút (có sẵn) + read 60/phút (bổ sung tuần này) |
| Giới hạn timeout, kích thước response | ✅ | `timeout_seconds`, `max_response_bytes` trong `allowlist.json` |
| Chỉ payload an toàn (dài / ký tự đặc biệt / rỗng / sai kiểu) | ✅ | `SAFE_BODIES` trong `kong_http_tool.py` |
| Nhật ký request/response | ✅ | `data-lake/request_log.jsonl` |
| Nhật ký không lưu API key | ✅ | `redact()` — xác nhận trên log thật, không còn key thô |
| Demo Agent đề xuất + tool thực thi | ✅ | `exploit_agent.py` → `hitl_decisions.jsonl` → `exploit_result.json` |
| Không gọi được endpoint cấm qua tool | ✅ | `tests/test_kong_iam.py` 7/7 PASS |
| Tool xử lý lỗi timeout/kết nối | ✅ | except `requests.Timeout` / `RequestException` riêng trong `kong_http_tool.py` |
| Request đều đi qua Gateway | ✅ | mọi lệnh gọi dùng `KONG_BASE`; guard abort nếu base không phải localhost |

**Kết quả chạy thật (2026-08-15, Juice Shop + gateway thay thế như mô tả ở trên):**

```
tests/test_kong_iam.py           → 7/7 PASS (401 không key · 403 ACL · 403 path-deny · 2xx allow · client-deny)
tests/test_kong_rate_limit.py    → PASS — write 20/phút: #01-19 → 201, #20-25 → 429
tests/test_kong_rate_limit_read.py → PASS — read 60/phút: #01-57 → 200, #58-65 → 429
agents/exploit_agent.py --yes    → HITL auto-approve → request qua gateway → status 200 (Juice Shop thật)
```

**Verdict:** Tuần 4 theo PDF — **PASS**, đầy đủ 13/13 tiêu chí đối chiếu, có bằng chứng chạy thật cho
toàn bộ deny-case, allow-case và cả hai route rate-limit.

**Giới hạn còn lại:** bằng chứng trên dùng gateway thay thế (đọc đúng `kong/kong.yml`), không phải
Kong container thật do môi trường làm việc không có Docker. Bằng chứng từ Kong container thật gần
nhất là log ngày 2026-07-28 (`docs/notes/KONG_IAM_PROOF.md`), khớp kết quả với lần chạy thay thế
tuần này. Cần chạy lại `docker compose up -d` + ba file test trên khi có môi trường có Docker để đối
chiếu bằng Kong thật.

## Dữ liệu thô / máy đọc

- `data-lake/request_log.jsonl` — nhật ký request/response qua tool (đã redact key).
- `data-lake/hitl_decisions.jsonl`, `data-lake/exploit_result.json` — chuỗi demo agent đề xuất → tool thực thi.
- Chi tiết log đầy đủ: `docs/notes/KONG_IAM_PROOF.md`, `docs/notes/KONG_RATE_LIMIT_PROOF.md`.
- Cấu hình: `kong/kong.yml` · Allowlist: `kong/allowlist.json`.
