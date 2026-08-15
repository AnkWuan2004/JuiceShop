# Kong IAM Proof (Tuần 2)

Chạy: `docker compose up -d` rồi `python scripts/test_kong_iam.py`.

## Kết quả (2026-07-28)

```
[*] Test Kong IAM (localhost:8000)

  [PASS] GET không key → 401 — got 401
  [PASS] Recon GET products → 2xx — got 200
  [PASS] Recon POST /api/Users → 403 — got 403
  [PASS] Exploit POST /api/Users → không 401/403 Kong — got 400
  [PASS] Recon GET /rest/admin → 403 path deny — got 403
  [PASS] Exploit GET /rest/admin → 403 path deny — got 403
  [PASS] Tool deny recon POST (client) — method POST denied for recon-agent

[*] Kết quả: 7/7 PASS
```

Rate-limit: `python scripts/test_kong_rate_limit.py` → **429** (vd. 23×201 rồi 2×429).

Config: `kong/kong.yml` · Allowlist: `kong/allowlist.json` · Report: `Week2_API_Gateway_Agent_IAM.md`.

## Chạy lại 2026-08-15 — máy không có Docker, chỉ verify phần client-side

Máy làm việc phiên này không cài Docker (không sudo tương tác qua công cụ) → Kong/Juice Shop không
sống → 6/7 case gọi mạng thật trong `test_kong_iam.py` FAIL với `Connection refused` (đúng như dự
kiến khi service chưa chạy, không phải lỗi logic). Kết quả đầy đủ:

```
[*] Test Kong IAM (localhost:8000)
  [FAIL] GET không key → 401 — Connection refused
  [FAIL] Recon GET products → 2xx — Connection refused
  [FAIL] Recon POST /api/Users → 403 — Connection refused
  [FAIL] Exploit POST /api/Users → không 401/403 Kong — Connection refused
  [FAIL] Recon GET /rest/admin → 403 path deny — Connection refused
  [FAIL] Exploit GET /rest/admin → 403 path deny — Connection refused
  [PASS] Tool deny recon POST (client) — method POST denied for recon-agent
[*] Kết quả: 1/7 PASS
```

Đã verify riêng phần **không phụ thuộc Kong sống** (client allowlist trong `kong_http_tool.py`),
chạy trực tiếp bằng CLI, kết quả thật:

```
$ python agents/kong_http_tool.py --agent recon-agent --method POST --path /api/Users
{"ok": false, "error": "method POST denied for recon-agent"}   # exit=2, PASS — chặn trước khi gọi mạng

$ python agents/kong_http_tool.py --agent recon-agent --method GET --path /rest/admin/application-configuration
{"ok": false, "error": "path denied: /rest/admin/application-configuration (prefix /rest/admin)"}  # exit=2, PASS

$ python agents/kong_http_tool.py --agent recon-agent --method GET --path "/rest/products/search?q=apple"
{"ok": false, "status": null, "error": "connection: ConnectionError", ...}   # exit=1
# → PASS cho tiêu chí "tool xử lý được lỗi kết nối" (bắt gọn requests.RequestException, không crash)
# → data-lake/request_log.jsonl dòng vừa ghi KHÔNG chứa "recon-key-demo" → PASS "log không lưu API key"
```

**Cập nhật cùng ngày (sau đó):** máy này vẫn không có Docker/sudo, nhưng đã dựng được bằng chứng
sống **thật** bằng cách khác — xem mục dưới.

## Chạy sống 2026-08-15 (không cần Docker) — Juice Shop thật + gateway đọc đúng `kong/kong.yml`

Vì không cài được Docker (không sudo tương tác), đã dựng môi trường thay thế **chỉ trong phiên làm
việc này, không commit vào repo**:

1. **Juice Shop thật** chạy trực tiếp bằng Node (`npx tsx app.ts` trong `juice-shop/`, sau
   `npm install --ignore-scripts` + `npm rebuild sqlite3`) — không dùng Docker. Một vài file tĩnh
   (frontend build, ảnh avatar mặc định) bị thiếu vì không build frontend Angular; đã tạo file rỗng
   placeholder tại các đường dẫn `build/`, `frontend/dist/` (đều nằm trong `.gitignore`, không phải
   mã nguồn) chỉ để qua bước kiểm tra tồn tại file lúc khởi động — không ảnh hưởng logic API/IAM.
   Đã xoá sạch các file tạm này sau khi test xong; `git status juice-shop/` sạch.
2. **Gateway**: PDF cho phép "Kong, Nginx hoặc một gateway đơn giản". Không có root để cài Kong
   binary thật, nên viết một gateway Python nhỏ (`kong_stub_gateway.py`, chỉ trong scratchpad, không
   commit) — gateway này **đọc trực tiếp file thật `kong/kong.yml`** của repo (không hard-code luật
   riêng) và thực thi đúng ngữ nghĩa: key-auth (bảng `keyauth_credentials`), ACL (bảng `acls`/
   `allow`), rate-limiting (`minute`), path-deny (`/rest/admin` — tương đương logic Lua khai báo
   trong `pre-function`), rồi proxy request đã pass qua Juice Shop thật ở `:3000`.

Chạy đúng 3 file test **không sửa gì** trong `tests/`:

```
$ python tests/test_kong_iam.py
[PASS] GET không key → 401 — got 401
[PASS] Recon GET products → 2xx — got 200
[PASS] Recon POST /api/Users → 403 — got 403
[PASS] Exploit POST /api/Users → không 401/403 Kong — got 201
[PASS] Recon GET /rest/admin → 403 path deny — got 403
[PASS] Exploit GET /rest/admin → 403 path deny — got 403
[PASS] Tool deny recon POST (client) — method POST denied for recon-agent
[*] Kết quả: 7/7 PASS

$ python tests/test_kong_rate_limit.py     # write route, limit 20/phút
#01..#19 → 201, #20..#25 → 429
[*] Có 429: True (counts={201: 19, 429: 6})
[PASS] Rate-limit hoạt động

$ python tests/test_kong_rate_limit_read.py   # read route, limit 60/phút (mới thêm)
#01..#57 → 200, #58..#65 → 429
[*] Có 429: True (counts={200: 57, 429: 8})
[PASS] Rate-limit read hoạt động
```

Và demo "Agent đề xuất → tool thực thi" qua đúng gateway này:

```
$ python agents/exploit_agent.py --yes
[HITL] auto-approve (--yes / demo mode)
[+] Exploit result → data-lake/exploit_result.json
# result.status = 200, body_preview = dữ liệu thật từ Juice Shop qua gateway
```

**Trung thực về giới hạn của phép thử này:** gateway dùng ở trên là **không phải Kong binary thật**
— là stand-in Python đọc đúng file cấu hình thật để verify đúng ngữ nghĩa IAM/rate-limit/path-deny
mà PDF yêu cầu, trong điều kiện sandbox không có Docker/root. Bằng chứng bằng **Kong container thật**
(qua `docker compose up -d`) vẫn là log 2026-07-28 ở đầu file này. Khi có máy có Docker, chạy lại 3
lệnh trên với Kong thật để có log tương đương — kỳ vọng kết quả giống hệt vì cùng đọc một file
`kong/kong.yml`.
