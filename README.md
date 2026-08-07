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

```
Project-Sentinel/
├── juice-shop/              # Source OWASP Juice Shop (pin v20.1.1)
├── kong/kong.yml            # Key-auth + ACL (recon GET / exploit POST)
├── docker-compose.yml       # juice-shop + Kong (db-less)
├── .github/workflows/       # CI: Semgrep + ZAP
├── scripts/                 # parse, seed reports, test Kong IAM
├── data-lake/               # reports, SQLite, traces, agent outputs
├── agents/                  # Recon / Fuzz / Exploit / Supervisor / guardrails
├── rag/                     # ingest, hybrid search, eval retrieval
├── docs/                    # PRD, Business Case, Runbook, FinOps, Benchmark
└── README.md
```

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
python scripts/test_kong_iam.py         # cần compose up
python scripts/finops_report.py
```

API keys Kong demo: `recon-key-demo` (GET), `exploit-key-demo` (POST).

## Tuần 2 — Gateway + Agent IAM (demo nhanh)

Báo cáo 1 trang: `docs/notes/Week2_API_Gateway_Agent_IAM.md` · Plan: `docs/notes/WEEK2_PLAN.md`

```bash
docker compose up -d
python scripts/test_kong_iam.py              # 401 / 403 method / 403 path
python scripts/test_kong_rate_limit.py       # 429 trên write
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

Báo cáo: `docs/notes/Week3_Security_Analysis_Agent.md` · Plan: `docs/notes/WEEK3_PLAN.md`
System Prompt: `agents/prompts/analysis_system_prompt.txt`

```bash
python scripts/seed_sample_reports.py     # ~140 rows (111 Semgrep + 29 ZAP) → vuln_data.db
python rag/ingest.py                      # kho tri thức tuần 2 (nếu chưa ingest)
python agents/analysis_agent.py --md      # → data-lake/analysis_report.jsonl (+ .md)
python scripts/test_analysis_agent.py     # 3 tình huống: happy / empty / injection

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

Deploy lên Vercel: import repo GitHub này vào Vercel (Zero Config — `vercel.json` đã có sẵn rewrite
`/* → /api/index`). Đặt biến môi trường `OPENAI_API_KEY` / `OPENAI_BASE_URL` / `OPENAI_MODEL` trong
Project Settings → Environment Variables nếu muốn chạy LLM thật (bỏ trống → MOCK offline).

Do Vercel serverless không có filesystem ghi bền vững, nút "Chạy Agent ngay" chạy Agent thật trên dữ
liệu hiện có nhưng không ghi đè `analysis_report.jsonl` trong repo — kết quả chỉ hiển thị cho lần bấm
đó. Toàn bộ dữ liệu hiển thị khác (`vuln_data.db`, `rag/store/*`, báo cáo đã commit) đọc thẳng từ
snapshot có sẵn trong repo.

## Tiến độ (12 tuần)

| Tuần | Nội dung | Trạng thái |
|---|---|---|
| 0 | Clone Juice Shop + Compose | ✅ Done |
| 1 | SAST/DAST CI + parse + Attack Surface + seed reports | ✅ CI verified + demo |
| 2 | Kong IAM + `test_kong_iam.py` + MCP stub | ✅ Verified demo |
| 3 | RAG ingest / hybrid / retrieval eval + **Security Analysis Agent → JSONL** | ✅ 140→~71 grounded · live demo :8790 · 13/13 test |
| 4 | Recon Agent → Attack Surface Map | ✅ DB-driven + vs manual |
| 5 | Fuzz Agent qua Kong rate-limit | ✅ Mutate-on-anomaly |
| 6 | Multi-agent Supervisor + traces | ✅ File traces |
| 7 | Indirect prompt injection + guardrails | ✅ Before/after artifacts |
| 8 | HITL CLI approve/reject | ✅ Approve + reject demo |
| 9 | PII redaction | ✅ In traces + GDPR note |
| 10 | Eval pipeline 10 challenges | ✅ Non-circular + improve loop |
| 11 | Full Compose + FinOps + Runbook | ✅ CSV FinOps |
| 12 | PRD + Business Case | ✅ + DEMO_CHECKLIST |

Chi tiết nhật ký: `docs/notes/TIEN_DO.md`. Demo: `docs/DEMO_CHECKLIST.md`. Runbook: `docs/RUNBOOK.md`.

## An toàn

Mọi fuzz/exploit **chỉ** nhắm `localhost` / dịch vụ Compose. Không tấn công host ngoài.
