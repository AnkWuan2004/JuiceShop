# Plan Tuần 2 — API Gateway & Agent IAM (+ nền Tuần 4)

**Status: ✅ HOÀN THÀNH (2026-07-28)** — IAM 7/7 PASS · RL 429 · MCP+A2A demo · report MD  
**Nộp:** `docs/notes/Week2_API_Gateway_Agent_IAM.md`  
**Deadline nộp:** ~3 ngày (1 file MD tiếng Việt, ~1 trang A4 + sơ đồ)  
**Nguyên tắc:** viết lại căn bản, giải thích được · fail-closed · chứng minh bằng **deny**  
**Bỏ:** task SAST harness tuần 1 · GraphRAG / multi-agent nặng / vLLM

---

## Mindset (đo thành công)

> Không tin agent. Tin policy: recon chỉ đọc qua Kong; write chỉ exploit + rate-limit; tool chỉ qua MCP; mọi quyết định nguy hiểm fail closed.

| Câu hỏi thiết kế | Trả lời tối thiểu |
|---|---|
| Blast radius khi agent bị hijack? | Chỉ đúng method/path của consumer đó |
| Policy nằm đâu? | Kong ACL + allowlist — không nằm trong prompt |
| Proof gì? | Bảng deny xanh (401/403/429), không chỉ 200 OK |

---

## Scope

### Track A — Nộp tuần 2 (P0)

1. **Gateway:** mọi traffic agent → Kong `:8000` → Juice Shop `:3000`
2. **Agent IAM:** identity (API key) ≠ capability (ACL method + path)
3. **MCP:** `tools/list` + `tools/call` (tool = capability có tên)
4. **A2A:** envelope message có `messageId` / protocol → `jsonl`
5. **Proof:** script + screenshot + 1 MD report

### Track B — Song song tuần 4 (P1, không chặn nộp)

- Python tool: GET/POST an toàn qua Kong (timeout, cắt body, **không log apikey**)
- Skeleton Recon: đọc `vuln_data.db` qua MCP → draft `attack_surface_map.json`
- `request_log.jsonl` sẵn cho demo PDF tuần 4

---

## Kiến trúc mục tiêu

```text
[Recon Agent]  -- apikey: recon   -->┐
[Exploit Agent]-- apikey: exploit -->├── Kong :8000
[MCP Server]   -- tools (DB/RAG)  --┘     │  key-auth + ACL + rate-limit
                                          ▼
                                   Juice Shop :3000

Supervisor ◄── A2A (jsonl) ──► Agents
```

### Ma trận IAM (điểm tối đa = path + method)

| Agent | Key | GET `/api`,`/rest` | POST/PUT/DELETE | Path deny (vd. admin / sensitive) |
|---|---|---|---|---|
| recon-agent | `recon-key-demo` | ✅ | ❌ 403 | ❌ 403 |
| exploit-agent | `exploit-key-demo` | ✅ | ✅ (+ RL) | theo allowlist |
| (không key) | — | ❌ 401 | ❌ 401 | ❌ 401 |

---

## Lịch 3 ngày

### D1 — Control plane (Gateway + IAM)

- [ ] Compose up: Juice Shop + Kong
- [ ] Viết lại `kong/kong.yml` **đủ đơn giản để giải thích**: key-auth, ACL group, route read/write, path deny hoặc allowlist rõ
- [ ] (Tuỳ chọn) tách service/route admin bị cấm khỏi recon
- [ ] Chạy proof cơ bản: 401 / recon GET 200 / recon POST 403 / exploit POST 200

**Verify:** `python scripts/test_kong_iam.py` (mở rộng thêm case path-deny nếu cần)

### D2 — Tool plane (MCP + A2A + HTTP tool)

- [ ] MCP server tối thiểu: 2–3 tools (`get_scan_results`, `get_attack_surface`, …)
- [ ] MCP client gọi được; agent không mở SQLite lung tung khi MCP up
- [ ] A2A wrap + append `data-lake/a2a_messages.jsonl`
- [ ] Python tool qua Kong: timeout, truncate response, redact apikey trong log
- [ ] Rate-limit → chứng minh 429
- [ ] Chụp 1–2 screenshot terminal (deny + allow)

**Verify:** MCP `tools/list` OK · 1 `tools/call` OK · A2A có ≥1 dòng jsonl · log không chứa raw key

### D3 — Evidence + report + nền W4

- [ ] Viết `docs/notes/Week2_API_Gateway_Agent_IAM.md` (~A4, TIẾNG VIỆT)
- [ ] Sơ đồ mermaid/ascii trong MD
- [ ] README ngắn: 5 lệnh demo
- [ ] Track B: skeleton Recon đọc DB qua MCP (không cần LLM đẹp)
- [ ] Dry-run: người lạ chạy theo README vẫn ra bảng PASS/FAIL

**Verify:** MD ≤ ~1 trang khi in · đủ 5 ô: vấn đề / PDF+mentor / tại sao / luồng / bằng chứng

---

## Outline file nộp (1 MD)

1. **Vấn đề** (3–4 câu): agent + full quyền = blast radius lớn  
2. **Sơ đồ** nhỏ  
3. **Agent IAM**: bảng ma trận + least privilege  
4. **MCP / A2A**: mỗi cái 2–3 câu + đường dẫn evidence  
5. **Bằng chứng**: lệnh + PASS/FAIL ngắn (+ link/ảnh)  
6. **An toàn**: chỉ `localhost` / Compose  

Tên file mặc định: `docs/notes/Week2_API_Gateway_Agent_IAM.md`  
(Đổi theo MSSV nếu lớp yêu cầu.)

---

## Definition of Done

- [ ] Agent demo không gọi thẳng `:3000`
- [ ] Deny-table xanh: 401, 403 (method), 403 (path), 429
- [ ] MCP + A2A có output file
- [ ] HTTP tool / log không lộ API key
- [ ] 1 MD VI + sơ đồ, giải thích được không cần đọc cả repo
- [ ] (Bonus W4) draft map JSON từ DB qua MCP

---

## Không làm (tránh over-engineer)

- IdP / OAuth phức tạp, JWT user-style cho “cho đẹp”
- GraphRAG, syndicate đầy đủ, exploit thật, Slack HITL
- Generate IAM 15 file YAML mà không giải thích nổi 1 trang

---

## File chạm chính

| File | Vai trò |
|---|---|
| `docker-compose.yml` | Juice Shop + Kong |
| `kong/kong.yml` | Agent IAM (viết lại căn bản) |
| `scripts/test_kong_iam.py` | Proof deny/allow |
| `agents/mcp_server.py` / `mcp_client.py` | Tool IAM |
| `agents/a2a.py` | Message syndicate |
| `data-lake/a2a_messages.jsonl` | Evidence A2A |
| `docs/notes/Week2_API_Gateway_Agent_IAM.md` | Nộp |
| `docs/notes/KONG_IAM_PROOF.md` | Chi tiết proof (tuỳ chọn kèm) |

---

## Thứ tự ưu tiên khi thiếu thời gian

1. Kong IAM + deny proof (bắt buộc)  
2. MD 1 trang + sơ đồ (bắt buộc)  
3. MCP stub + 1 call (bắt buộc mentor)  
4. A2A jsonl (bắt buộc mentor “điểm tối đa”)  
5. Path-deny + rate-limit 429 + redact log (điểm tối đa)  
6. Skeleton Recon / request log (tuần 4 — cắt được nếu cháy D3)
