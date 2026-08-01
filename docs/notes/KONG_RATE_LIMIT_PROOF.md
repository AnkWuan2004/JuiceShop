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
