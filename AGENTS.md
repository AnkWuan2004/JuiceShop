# AGENTS.md

Hướng dẫn cho AI coding agent (Claude Code, Cursor, Codex, v.v.) khi làm việc trong repo này.

## Repo này là gì

Project Sentinel: hạ tầng DevSecOps + AI security-analysis agent, thực hành trên OWASP Juice Shop
(staging Docker Compose cục bộ). Có 2 phần tách biệt:

- **`juice-shop/`** — target bị quét (vendor code, KHÔNG sửa trừ khi bài yêu cầu, xem `.sentinel-pin`).
- **Phần còn lại** — code của project: agents AI, RAG, API gateway, live demo web.

## Bản đồ thư mục (xem thêm README.md § Cấu trúc)

| Thư mục | Vai trò |
|---|---|
| `agents/` | Các AI agent (recon, fuzz, exploit, analysis, supervisor) + LLM client dùng chung |
| `rag/` | Ingest kho tri thức + hybrid/semantic search |
| `api/` | Live demo web (FastAPI), deploy trên Vercel |
| `kong/`, `guardrails/` | Cấu hình API gateway / IAM cho agent |
| `scripts/` | Script vận hành/demo một lần (không phải test) |
| `tests/` | Test tự động — chạy bằng `python tests/<file>.py`, không cần pytest |
| `data-lake/` | Dữ liệu & output **cho máy đọc** (SQLite, JSONL, trace) — không phải chỗ viết báo cáo |
| `docs/` | Tài liệu sản phẩm sống (PRD, Runbook, FinOps...) — được phép cập nhật theo code |
| `reports/` | Báo cáo tiến độ theo tuần — **đã nộp thì không sửa nội dung nữa**, xem `reports/README.md` |

## Quy tắc quan trọng

1. **Báo cáo trong `reports/week-N/` là hồ sơ đóng băng.** Tên file giữ định dạng
   `<ngày>_<tên>_Week<N>.md` (không đổi sang tên chung chung). Không sửa nội dung report đã tồn tại để
   khớp code mới — kể cả khi đường dẫn/số liệu trong đó không còn đúng 100%. Cập nhật tiến độ mới
   thì viết report tuần mới hoặc thêm vào `reports/PROGRESS.md`.
2. **Không commit secrets.** `.env` đã bị gitignore; chỉ sửa `.env.example`.
3. **LLM provider duy nhất:** DeepSeek (OpenAI-compatible) qua `OPENAI_API_KEY`/`OPENAI_BASE_URL`.
   Không có key → agent tự chạy MOCK offline (xem `agents/common.py::LLMClient`), đây là hành vi
   mong muốn, không phải lỗi.
4. **Vercel deploy KHÔNG cần `rewrites` trong `vercel.json`.** FastAPI được Vercel nhận diện là
   "backend framework" và tự route đúng path gốc. Thêm rewrite `/(.*) → /api/index` sẽ khiến MỌI
   route trả 404 (đã xảy ra thật, xem lịch sử commit) vì Vercel dùng path đích của rewrite làm path
   thực tế app nhận, không giữ path gốc.
5. **`data-lake/` là dữ liệu, không phải báo cáo.** Nếu cần trình bày số liệu cho người đọc, viết
   vào `reports/` hoặc `docs/` và link tới file trong `data-lake/`, đừng copy nguyên khối JSON/CSV.
6. Trước khi coi một thay đổi UI/deploy là xong: chạy thử local (`uvicorn api.index:app --reload`)
   **và** curl thử URL Vercel thật sau khi deploy — trang không load được thì coi như chưa xong việc.

## Chạy nhanh

```bash
pip install -r requirements.txt
python tests/test_analysis_agent.py     # test agent, offline/mock
uvicorn api.index:app --reload          # live demo local: http://127.0.0.1:8000
```

Chi tiết đầy đủ: xem `README.md`.
