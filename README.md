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

## Python setup & demo offline (MOCK LLM)

Không cần `OPENAI_API_KEY` — agents trả JSON deterministic.

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

## Tiến độ (12 tuần)

| Tuần | Nội dung | Trạng thái |
|---|---|---|
| 0 | Clone Juice Shop + Compose | ✅ Done |
| 1 | SAST/DAST CI + parse + Attack Surface + seed reports | ✅ CI verified + demo |
| 2 | Kong IAM + `test_kong_iam.py` + MCP stub | ✅ Verified demo |
| 3 | RAG ingest / hybrid / retrieval eval | ✅ P@3+MRR (BOW+BM25) |
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

**Tài liệu kiến thức Security (HTML):** mở
`C:\Users\ADMIN\Desktop\VInSOC\Project_Sentinel_Kien_Thuc_Security.html`
(hoặc `docs/Project_Sentinel_Security_Guide.html`) trên trình duyệt — diễn giải đủ 12 tuần theo PDF VinUni × VinSOC.

## An toàn

Mọi fuzz/exploit **chỉ** nhắm `localhost` / dịch vụ Compose. Không tấn công host ngoài.
