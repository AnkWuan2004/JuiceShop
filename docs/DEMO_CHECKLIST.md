# Demo day checklist — Project Sentinel

Chạy trên máy có Docker + Python 3.10+. **Không cần** `OPENAI_API_KEY` (MOCK).

## 1. Staging

```bash
cd Project-Sentinel
docker compose up -d
docker compose ps
# http://localhost:3000  Juice Shop
# http://localhost:8000  Kong
```

Optional vLLM gateway stub (Tuần 11):

```bash
docker compose -f docker-compose.yml -f docker-compose.vllm.yml --profile vllm up -d
# hoặc: python scripts/vllm_gateway.py
# http://localhost:8090/health
```

## 2. Seed + RAG (+ GraphRAG)

```bash
pip install -r requirements.txt
python scripts/seed_sample_reports.py
python rag/ingest.py
python rag/evaluate_retrieval.py
```

Kỳ vọng: hybrid / hybrid_graphrag accuracy cao; P@3 / MRR trong `rag/store/retrieval_eval.json` (có key `hybrid_graphrag`).

## 2b. Security Analysis Agent — live demo (Tuần 3)

```bash
python scripts/demo_analysis_agent.py
# UI: http://127.0.0.1:8790
# Nút “Chạy Agent” → gộp trùng + severity + explanation/remediation → JSONL
python scripts/test_analysis_agent.py   # happy / empty / injection
```

Artifacts: `data-lake/vuln_data.db`, `data-lake/analysis_report.jsonl` (+ `.md`),
System Prompt: `agents/prompts/analysis_system_prompt.txt`.

## 3. MCP + Syndicate E2E

```bash
# terminal A
python agents/mcp_server.py

# terminal B
python agents/mcp_client.py
python agents/run_syndicate.py
```

Artifacts: `attack_surface_map.json`, `fuzz_findings.json`, `exploit_result.json`, `syndicate_summary.json` (A2A), `a2a_messages.jsonl`, `injection_before.json` / `after.json`, `traces/langsmith_spans.jsonl`.

## 4. HITL reject + Slack UI (Tuần 8)

```bash
python agents/exploit_agent.py --reject-demo

# Slack-compatible local:
python scripts/slack_hitl_server.py
# browser http://127.0.0.1:8787
$env:SENTINEL_HITL="slack"
python agents/hitl_cli.py --slack-demo
```

## 5. PII + Eval + FinOps + Kong + Observability

```bash
python agents/pii_redaction.py --demo
python agents/eval_pipeline.py --both
python scripts/finops_report.py
python scripts/monitor_agents.py
python scripts/arize_viewer.py
python scripts/test_kong_iam.py
python scripts/test_kong_rate_limit.py
```

## 6. Nói với người xem (30s)

1. CI Semgrep+ZAP trên GitHub Actions → parse vào `vuln_data.db`.  
2. **Analysis Agent** (UI :8790): gộp trùng, severity, giải thích + fix, mọi finding có `source_ids`.  
3. Kong tách recon (GET) / exploit (POST+RL); MCP tools + A2A.  
4. GraphRAG + hybrid; agents MOCK + NeMo-style guardrail FTP + Slack HITL + PII.  
5. LangSmith spans / Arize dashboard; Eval baseline→improved; FinOps + monitor; vLLM gateway stub.

Keys demo: `recon-key-demo`, `exploit-key-demo`.
