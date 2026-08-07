# Tuần 2 — API Gateway & Agent IAM

**Project Sentinel** · OWASP Juice Shop staging (Docker Compose) · VI

## 1. Vấn đề

AI agent không phải user: gọi API nhanh, dễ bị thao túng qua prompt/tool. Nếu mọi agent dùng chung quyền admin và gọi thẳng app, một agent lỗi = phá cả staging. Cần **least privilege** nằm ngoài model (gateway), không nằm trong system prompt.

## 2. Kiến trúc

```text
[Recon Agent]  --apikey recon----┐
[Exploit Agent]--apikey exploit--├── Kong :8000 (key-auth + ACL + path-deny + RL)
[MCP tools]    --DB/RAG only-----┘            │
                                              ▼
                                       Juice Shop :3000
        Supervisor ◄── A2A (jsonl) ──► Agents
```

Hard control = Kong. Soft control = prompt (không đủ tin).

## 3. Agent IAM (ma trận)

| Agent | Key | GET `/api`,`/rest` | POST ghi | `/rest/admin` |
|---|---|---|---|---|
| recon-agent | `recon-key-demo` | ✅ | ❌ 403 | ❌ 403 |
| exploit-agent | `exploit-key-demo` | ✅ | ✅ (+ RL 20/phút) | ❌ 403 |
| (không key) | — | ❌ 401 | ❌ 401 | ❌ 401 |

Identity (key) ≠ capability (ACL + route). Path `/rest/admin*` bị chặn bằng `pre-function` (403) trên read/write. Allowlist client: `kong/allowlist.json` + `agents/kong_http_tool.py` (timeout, cắt body, **redact apikey** trong `data-lake/request_log.jsonl`).

## 4. MCP & A2A

- **MCP** (`agents/mcp_server.py`): `tools/list` + `tools/call` — tool có tên = capability (`get_scan_results`, `get_attack_surface`, `hybrid_search`). Tool lạ → deny.
- **A2A** (`agents/a2a.py`): envelope `sentinel-a2a/1.0` + `messageId` → `data-lake/a2a_messages.jsonl`.

## 5. Bằng chứng (chạy)

```bash
docker compose up -d
python scripts/test_kong_iam.py          # 401 / 403 method / 403 path / allow
python scripts/test_kong_rate_limit.py   # 429
python agents/mcp_server.py              # terminal riêng
python scripts/demo_mcp_a2a.py
python agents/kong_http_tool.py --agent recon-agent --path "/rest/products/search?q=apple"
python agents/recon_skeleton.py          # nền tuần 4
```

Kỳ vọng: bảng deny xanh; log không chứa raw key. Chi tiết: `docs/notes/KONG_IAM_PROOF.md`.

## 6. An toàn

Chỉ `localhost` / Compose. Agent không bypass `:3000` trong demo. Không exploit phá hoại — payload tool chỉ empty/long/special/wrong-type.

---
*Không tin agent — tin policy fail-closed.*
