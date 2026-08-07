# Runbook — Project Sentinel

## Start / Stop

```bash
cd Project-Sentinel
docker compose up -d          # image pin (khuyến nghị)
docker compose ps
docker compose logs -f kong
docker compose down
```

Build từ source (Tuần 7 FTP file / sửa juice-shop):

```bash
docker compose -f docker-compose.yml -f docker-compose.from-source.yml up -d --build
```

vLLM OpenAI-compatible gateway stub (Tuần 11, không cần GPU):

```bash
docker compose -f docker-compose.yml -f docker-compose.vllm.yml --profile vllm up -d
# hoặc: python scripts/vllm_gateway.py
```

- App debug/ZAP: http://localhost:3000  
- Agent gateway: http://localhost:8000 (header `apikey`)
- vLLM stub: http://localhost:8090/v1
- Slack HITL UI: http://localhost:8787
- Analysis Agent live demo: http://localhost:8790
- MCP: http://127.0.0.1:8765/mcp

## Seed & RAG (+ GraphRAG)

```bash
pip install -r requirements.txt
python scripts/seed_sample_reports.py   # 140 rows → vuln_data.db
python rag/ingest.py
python rag/evaluate_retrieval.py
```

## Security Analysis Agent (Tuần 3)

```bash
python agents/analysis_agent.py --md
python tests/test_analysis_agent.py
python scripts/demo_analysis_agent.py   # UI http://127.0.0.1:8790
```

## Agents (MOCK nếu không có OPENAI_API_KEY / OPENAI_BASE_URL)

```bash
python agents/mcp_server.py             # terminal riêng
python agents/run_syndicate.py          # HITL auto-approve + injection before/after + A2A
python agents/run_syndicate.py --interactive-hitl
python agents/exploit_agent.py --reject-demo
python agents/pii_redaction.py --demo
python agents/eval_pipeline.py --both
```

Slack HITL:

```bash
python scripts/slack_hitl_server.py
set SENTINEL_HITL=slack
python agents/hitl_cli.py --slack-demo
```

vLLM stub client:

```bash
set OPENAI_BASE_URL=http://localhost:8090/v1
set OPENAI_API_KEY=stub-key
set OPENAI_MODEL=sentinel-vllm-stub
```

Demo checklist: `docs/DEMO_CHECKLIST.md`.

## Kong IAM & rate limit

```bash
python tests/test_kong_iam.py
python tests/test_kong_rate_limit.py
```

Keys: `recon-key-demo` (GET), `exploit-key-demo` (POST + rate-limit).

## Observability & FinOps

```bash
python scripts/finops_report.py
python scripts/monitor_agents.py
python scripts/arize_viewer.py
```

## Sự cố thường gặp

| Triệu chứng | Xử lý |
|---|---|
| Kong 502 | Đợi juice-shop healthy; `compose restart kong` |
| 401 mọi request | Thiếu header `apikey` |
| 403 POST với recon key | Đúng thiết kế ACL |
| Fuzz timeout | `compose ps`; chỉ dùng localhost |
| RAG 0 docs | `python rag/ingest.py` |
| MCP client fail | Chạy `python agents/mcp_server.py` (recon fallback local) |
| Slack HITL timeout | Mở http://127.0.0.1:8787 và Approve/Reject |
| UnicodeEncodeError Windows | `$env:PYTHONIOENCODING="utf-8"` |
| Build juice-shop lâu | Dùng image pin; `--build` chỉ khi sửa source |

## An toàn

Chỉ tấn công service trong Compose. Không đổi `SENTINEL_KONG` sang host ngoài.
