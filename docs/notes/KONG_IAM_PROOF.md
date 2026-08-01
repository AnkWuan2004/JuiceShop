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
