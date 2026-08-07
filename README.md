# Project Sentinel

Hạ tầng DevSecOps + AI-assisted pentest thực hành trên **OWASP Juice Shop** (staging giả lập bằng Docker Compose).

## Phiên bản target

| Mục | Giá trị |
|---|---|
| Juice Shop | **v20.1.1** |
| Commit | `f915bddd82790d0f3018902d36ae9b4241a5f51f` |
| Pin file | `juice-shop/.sentinel-pin` |
| App (ZAP/debug) | http://localhost:3000 |
| Kong (agents) | http://localhost:8000 |

## Cấu trúc thư mục

5 phút để nhớ lại repo này tổ chức thế nào — nhóm theo **vai trò**, không theo tuần:

```
Project-Sentinel/
├── AGENTS.md                # Quy tắc cho AI coding agent (đọc trước khi sửa code)
├── CLAUDE.md                # Ghi chú riêng cho Claude Code, trỏ về AGENTS.md
├── README.md                # File này
│
├── agents/                  # SOURCE — AI agent (Recon/Fuzz/Exploit/Analysis/Supervisor) + LLM client
├── rag/                     #   ├─ rag/data/  = corpus tri thức (input, có version)
├── api/                     #   └─ Live demo web (FastAPI) — deploy Vercel
├── kong/, guardrails/       #   API gateway + guardrail config cho agent
├── scripts/                 # Script vận hành/demo một lần (không phải test)
├── tests/                   # TESTS — chạy: python tests/<file>.py
│
├── data-lake/                # DATASET/OUTPUT máy đọc — SQLite, JSONL, trace, artefact CI
├── juice-shop/               # Target bị quét (vendor, pin v20.1.1) — không phải code của mình
│
├── docs/                     # Tài liệu sản phẩm SỐNG (PRD, Runbook, FinOps, Business Case)
│   └── notes/                 #   Ghi chú kỹ thuật theo chủ đề (không phải báo cáo tuần)
└── reports/                  # Báo cáo tiến độ theo TUẦN — đã nộp thì KHÔNG sửa nữa
    ├── week-1/, week-2/, week-3/, ...report.md (≤1 trang, quá trình + kết quả)
    └── PROGRESS.md             # Nhật ký tiến độ toàn dự án (được phép cập nhật liên tục)
```

Quy tắc report vs code: **code** trong `agents/`, `api/`, `rag/`... là của chung project, thay đổi
liên tục theo thời gian. **Báo cáo** trong `reports/week-N/` là hồ sơ lịch sử tại thời điểm nộp —
không chỉnh sửa lại để khớp code mới. Chi tiết: [`reports/README.md`](reports/README.md).

## Chạy staging

```bash
# Khuyến nghị: dùng image pin (không build — tránh npm ECONNRESET)
docker compose up -d
# http://localhost:3000  — Juice Shop
# http://localhost:8000  — Kong gateway
docker compose ps
docker compose down
```

Build từ source (chỉ khi sửa `juice-shop/`, VD Tuần 7):

```bash
docker compose -f docker-compose.yml -f docker-compose.from-source.yml up -d --build
```

## LLM provider — DeepSeek V4 Flash 0731 (qua OpenRouter)

Provider **duy nhất**: DeepSeek V4 Flash qua OpenRouter (OpenAI-compatible). Không dùng OpenAI/Gemini/Anthropic.

```bash
cp .env.example .env          # rồi dán OpenRouter API key (sk-or-v1-...) vào OPENAI_API_KEY
# OPENAI_BASE_URL=https://openrouter.ai/api/v1 · OPENAI_MODEL=deepseek/deepseek-v4-flash-0731
```

Tạo key: https://openrouter.ai/keys · Để trống key → agents chạy **MOCK offline** (không gọi mạng).

## Python setup & demo offline (MOCK LLM)

```bash
pip install -r requirements.txt
python scripts/seed_sample_reports.py
python rag/ingest.py && python rag/evaluate_retrieval.py
python agents/run_syndicate.py          # auto HITL + injection probes
python agents/eval_pipeline.py --both
python tests/test_kong_iam.py         # cần compose up
python scripts/finops_report.py
```

API keys Kong demo: `recon-key-demo` (GET), `exploit-key-demo` (POST).

## Tuần 2 — Gateway + Agent IAM (demo nhanh)

Báo cáo: `reports/week-2/2026-07-31_NguyenThanhAnhQuan_Week2.md` · Gateway/IAM: `reports/week-2/gateway-agent-iam.md` · Plan: `reports/week-2/plan.md`

```bash
docker compose up -d
python tests/test_kong_iam.py              # 401 / 403 method / 403 path
python tests/test_kong_rate_limit.py       # 429 trên write
# terminal riêng:
python agents/mcp_server.py
python scripts/demo_mcp_a2a.py
python agents/kong_http_tool.py --agent recon-agent --path "/rest/products/search?q=apple"
python agents/recon_skeleton.py              # nền Attack Surface Map (tuần 4)
```

Allowlist client: `kong/allowlist.json`. Path `/rest/admin` bị deny mọi agent.

## Tuần 3 — Security Analysis Agent

Đọc findings đã chuẩn hóa → gộp trùng → phân loại severity → giải thích + đề xuất fix → **JSONL**.
Mỗi finding truy vết `evidence.source_ids` về row DB (evidence-based, không bịa).

Báo cáo: `reports/week-3/2026-08-07_NguyenThanhAnhQuan_Week3.md` · Chi tiết kỹ thuật: `reports/week-3/details.md` · Plan: `reports/week-3/plan.md`
System Prompt: `agents/prompts/analysis_system_prompt.txt`

```bash
python scripts/seed_sample_reports.py     # ~140 rows (111 Semgrep + 29 ZAP) → vuln_data.db
python rag/ingest.py                      # kho tri thức tuần 2 (nếu chưa ingest)
python agents/analysis_agent.py --md      # → data-lake/analysis_report.jsonl (+ .md)
python tests/test_analysis_agent.py     # 3 tình huống: happy / empty / injection

# Live demo UI (MOCK, không cần API key)
python scripts/demo_analysis_agent.py     # seed → analyze → http://127.0.0.1:8790
# hoặc: python scripts/demo_analysis_server.py
```

## Live demo — Vercel (FastAPI)

Dashboard demo Tuần 1-3 chạy bằng FastAPI (`api/index.py`), thay cho Streamlit cũ — Streamlit
cần một server sống liên tục nên không deploy được lên Vercel serverless.

```bash
pip install -r requirements.txt
uvicorn api.index:app --reload    # http://127.0.0.1:8000
```

Deploy lên Vercel: import repo GitHub này vào Vercel (Zero Config — Vercel tự nhận diện FastAPI là
"backend framework" và route đúng path gốc; `vercel.json` chỉ khai báo `maxDuration`, **không** khai
`rewrites` — thêm rewrite `/(.*) → /api/index` sẽ làm mọi route trả 404, xem `AGENTS.md`). Đặt biến
môi trường `OPENAI_API_KEY` / `OPENAI_BASE_URL` / `OPENAI_MODEL` trong Project Settings → Environment
Variables nếu muốn chạy LLM thật (bỏ trống → MOCK offline).

Do Vercel serverless không có filesystem ghi bền vững, nút "Chạy Agent ngay" chạy Agent thật trên dữ
liệu hiện có nhưng không ghi đè `analysis_report.jsonl` trong repo — kết quả chỉ hiển thị cho lần bấm
đó. Toàn bộ dữ liệu hiển thị khác (`vuln_data.db`, `rag/store/*`, báo cáo đã commit) đọc thẳng từ
snapshot có sẵn trong repo.

## Tiến độ

**Đề gốc mentor cấp là lộ trình 6 tuần** (`[NCUD-GPAI] VinUni x VinSOC 6-week of Project Sentinnel.pdf`),
không phải 12 tuần. Bảng dưới đây là **số thứ tự sprint nội bộ** của project (để theo dõi tiến độ
code), không phải số tuần trong đề — hai cách đánh số **không khớp 1:1** (vd. sprint "2" bên dưới là
nội dung Kong/IAM, tương ứng Tuần 4 của đề gốc; nội dung Tuần 2 thật của đề — chuẩn hóa + kho tri
thức — nằm trong sprint "3"). Đối chiếu chi tiết Tuần 1-3: [`reports/gap-analysis-week1-3.md`](reports/gap-analysis-week1-3.md).
Từ sprint 4 trở đi là phần **mở rộng tự làm thêm**, không nằm trong yêu cầu bắt buộc của đề 6 tuần.

| Sprint | Nội dung | Trạng thái |
|---|---|---|
| 0 | Clone Juice Shop + Compose | ✅ Done |
| 1 | SAST/DAST CI + parse + Attack Surface + seed reports | ✅ CI verified + demo |
| 2 | Kong IAM + `test_kong_iam.py` + MCP stub | ✅ Verified demo |
| 3 | RAG ingest / hybrid / retrieval eval + **Security Analysis Agent → JSONL** | ✅ 93→74 grounded · live demo Vercel · 13/13 test |
| 4 | Recon Agent → Attack Surface Map | ✅ DB-driven + vs manual |
| 5 | Fuzz Agent qua Kong rate-limit | ✅ Mutate-on-anomaly |
| 6 | Multi-agent Supervisor + traces | ✅ File traces |
| 7 | Indirect prompt injection + guardrails | ✅ Before/after artifacts |
| 8 | HITL CLI approve/reject | ✅ Approve + reject demo |
| 9 | PII redaction | ✅ In traces + GDPR note |
| 10 | Eval pipeline 10 challenges | ✅ Non-circular + improve loop |
| 11 | Full Compose + FinOps + Runbook | ✅ CSV FinOps |
| 12 | PRD + Business Case | ✅ + DEMO_CHECKLIST |

Chi tiết nhật ký: `reports/PROGRESS.md`. Demo: `docs/DEMO_CHECKLIST.md`. Runbook: `docs/RUNBOOK.md`.

## Giới hạn hiện tại

Không tách file `DEBT.md` riêng (nhiều file nhỏ ở gốc repo gây rối hơn là giúp) — theo dõi hạn chế
tại đây, gộp theo tuần phát hiện:

- **Tuần 3 — Semantic search fallback.** Khi không cấu hình Chroma, "semantic search" trong kho tri
  thức dùng TF-IDF cosine similarity thay vì embedding thật — đủ demo nhưng kém chính xác ngữ nghĩa
  hơn embedding model. Xem `reports/week-3/2026-08-07_NguyenThanhAnhQuan_Week3.md`.
- **Live demo Vercel không ghi đè báo cáo.** Serverless không có filesystem ghi bền vững; nút "Chạy
  Agent ngay" chỉ hiển thị kết quả tạm cho lần bấm đó, không cập nhật `analysis_report.jsonl` trong
  repo (xem mục Live demo phía trên).

## An toàn

Mọi fuzz/exploit **chỉ** nhắm `localhost` / dịch vụ Compose. Không tấn công host ngoài.
