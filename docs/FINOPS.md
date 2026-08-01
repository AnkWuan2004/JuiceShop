# FinOps — Project Sentinel (Tuần 11)

## Nguyên tắc

- Mặc định **MOCK LLM** → $0 token.
- Bật OpenAI hoặc **vLLM gateway** (`OPENAI_BASE_URL`) khi cần.
- Lab không thuê GPU cloud; compose profile `vllm` chạy stub OpenAI-compatible.

## Telemetry

`LLMClient` ghi vào traces:

- `est_tokens_in` / `est_tokens_out` (~4 chars/token)
- `est_cost_usd` (MOCK = 0; real dùng `SENTINEL_COST_IN_PER_1M` / `OUT`)
- `latency_ms`, `model`, `base_url`

```bash
python scripts/finops_report.py
# → data-lake/finops_weekly.csv
python scripts/monitor_agents.py
# → data-lake/monitor_report.json
# ALERT cost / latency / error_rate
```

## Ước lượng (khi dùng API)

| Hoạt động | Token TB | Cost ví dụ |
|---|---|---|
| 1× Recon | ~2k | < $0.01 |
| Full syndicate + eval | ~25k | ~$0.02–0.05 |

## Monitoring

- Trace JSONL: `data-lake/traces/`
- LangSmith spans: `data-lake/traces/langsmith_spans.jsonl`
- Dashboard: `python scripts/arize_viewer.py`
- CSV FinOps: `data-lake/finops_weekly.csv`
- Compose: `docker stats sentinel-juice-shop sentinel-kong`
- Alert: script exit code 2 nếu vượt ngưỡng — tắt API key, về MOCK

## Tối ưu

1. Truncate vuln context trong recon.  
2. `--max` / `--mutate` giới hạn fuzz.  
3. Cache RAG ingest + GraphRAG.  
4. Kong write rate-limit + client sleep GET.
