# Kong Rate Limit Proof

Burst POST `/api/Users` với `exploit-key-demo` (limit 20/min trên write service).

## 2026-07-28 (`scripts/test_kong_rate_limit.py`)

```
#01–#23 → 201
#24–#25 → 429
Có 429: True (counts={201: 23, 429: 2})
[PASS] Rate-limit hoạt động
```

Plugin: `kong/kong.yml` → service `juice-shop-write` → `rate-limiting` minute: 20.

## Route read — thêm 2026-08-15 (khép gap Tuần 4)

Trước đây route `juice-shop-read` (GET/HEAD/OPTIONS) không có plugin `rate-limiting` —
recon-agent có thể gọi GET không giới hạn/phút qua Kong. Đã thêm `rate-limiting` minute: 60
vào service `juice-shop-read` trong `kong/kong.yml`. Test: `tests/test_kong_rate_limit_read.py`
(burst 65 GET với `recon-key-demo`, kỳ vọng thấy 429 ở các request cuối).

**Cập nhật — đã chạy sống 2026-08-15** (cùng ngày, sau khi thêm plugin): máy này vẫn không có
Docker, nên dùng Juice Shop thật chạy bằng Node trực tiếp + gateway Python đọc đúng
`kong/kong.yml` thật thay cho Kong binary (chi tiết cách dựng: xem
`docs/notes/KONG_IAM_PROOF.md` mục "Chạy sống 2026-08-15"). Kết quả `tests/test_kong_rate_limit_read.py`:

```
#01–#57 → 200
#58–#65 → 429
Có 429: True (counts={200: 57, 429: 8})
[PASS] Rate-limit read hoạt động
```

Khớp đúng thiết kế: limit 60/phút → request thứ 58 trở đi trong cùng cửa sổ phút bị chặn 429.
Chưa có log từ Kong container thật (do máy không có Docker) — khi có Docker, chạy lại đúng lệnh trên
để đối chiếu; kỳ vọng số liệu tương đương vì cùng đọc một `kong/kong.yml`.
