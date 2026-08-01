# Tracing & Observability (Tuần 6)

Project Sentinel ghi **file traces** + **LangSmith-shaped spans** + **Arize-local dashboard**.

## Vị trí

| Artifact | Path |
|---|---|
| Agent traces | `data-lake/traces/{agent}_{YYYYMMDD}.jsonl` |
| LangSmith spans | `data-lake/traces/langsmith_spans.jsonl` |
| A2A messages | `data-lake/a2a_messages.jsonl` |
| Dashboard | `data-lake/observability_dashboard.html` |

Agents: `recon`, `fuzz`, `exploit`, `supervisor`, `llm`, `eval`.

## Schema (agent JSONL)

```json
{"ts": "ISO-8601", "agent": "fuzz", "event": "probe", "data": {}}
```

Payload đã **PII-redact** trước khi persist (`write_trace` → `observability.emit_langsmith_span`).

## LLM FinOps fields

Trong `event=response` của agent `llm`:

- `est_tokens_in` / `est_tokens_out`
- `est_cost_usd` (MOCK = 0)

```bash
python scripts/finops_report.py
python scripts/monitor_agents.py
python scripts/arize_viewer.py
```

## Message format syndicate (A2A)

Supervisor dùng envelope `sentinel-a2a/1.0`:

`{protocol, messageId, from, to, task, data, createdAt}`

Xem `agents/a2a.py`, `agents/supervisor.py`, `syndicate_summary.json`.
