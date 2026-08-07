# Tiến độ Project Sentinel

Cập nhật: 2026-07-20 (PDF gaps closed)

## Kết luận ngắn

**Tuần 0–12: verified demo local + CI + PDF gap closures.** LLM mặc định **MOCK**. GraphRAG, MCP/A2A, NeMo-style Colang rails, Slack HITL local, LangSmith spans + Arize dashboard, vLLM gateway stub đã có. Traffic agent qua Kong `localhost:8000`.

## Chi tiết theo tuần

### Tuần 0 — Chuẩn bị nền tảng
| Hạng mục | Trạng thái | Ghi chú |
|---|---|---|
| Clone Juice Shop v20.1.1 + Compose | ✅ | localhost:3000 |
| Cấu trúc folder | ✅ | |

### Tuần 1 — SAST/DAST + CI/CD
| Hạng mục | Trạng thái | Ghi chú |
|---|---|---|
| CI Semgrep/ZAP | ✅ verified | [Run 29714467839](https://github.com/quannguyenthanhanh357-coder/JuiceShop/actions/runs/29714467839) |
| `parse_results.py` + seed | ✅ | → `vuln_data.db` |
| `ATTACK_SURFACE.md` | ✅ | |

### Tuần 2 — Kong & IAM + MCP/A2A
| Hạng mục | Trạng thái | Ghi chú |
|---|---|---|
| Kong + keys ACL | ✅ | `kong/kong.yml` |
| `test_kong_iam.py` | ✅ | proof: `docs/notes/KONG_IAM_PROOF.md` |
| MCP JSON-RPC | ✅ | `agents/mcp_server.py` — tools/list + tools/call |
| A2A envelopes | ✅ | `agents/a2a.py` → `data-lake/a2a_messages.jsonl` |

### Tuần 3 — RAG + GraphRAG + Security Analysis Agent
| Hạng mục | Trạng thái | Ghi chú |
|---|---|---|
| ingest / hybrid BOW+BM25 | ✅ | Recon dùng `hybrid_search` |
| GraphRAG | ✅ | `rag/graphrag.py` → `knowledge_graph.json` |
| Eval accuracy + P@3 + MRR | ✅ | modes: bow / hybrid / **hybrid_graphrag** |
| Security Analysis Agent → JSONL | ✅ | `agents/analysis_agent.py` · live demo `:8790` · 13/13 test |

### Tuần 4–6 — Agents + Observability
| Hạng mục | Trạng thái | Ghi chú |
|---|---|---|
| Recon DB-driven + MCP tools | ✅ | fallback local nếu MCP down |
| Fuzz mutate-on-anomaly | ✅ | + Kong rate-limit proof |
| Supervisor A2A | ✅ | |
| LangSmith spans + Arize dashboard | ✅ | `scripts/arize_viewer.py` |

### Tuần 7–9 — Bảo vệ AI
| Hạng mục | Trạng thái | Ghi chú |
|---|---|---|
| NeMo-style Colang rails | ✅ | `guardrails/config.yml` + `rails.co` |
| Injection before/after | ✅ | |
| HITL CLI + Slack local | ✅ | `scripts/slack_hitl_server.py` `:8787` |
| PII + GDPR note | ✅ | |

### Tuần 10–12 — LLMOps & bàn giao
| Hạng mục | Trạng thái | Ghi chú |
|---|---|---|
| Eval non-circular + improvement | ✅ | |
| vLLM OpenAI gateway stub | ✅ | compose profile `vllm` `:8090` |
| FinOps + monitor latency/error | ✅ | `monitor_agents.py` |
| PRD / Business / Demo checklist | ✅ | |

## Mock mode

- Không set `OPENAI_API_KEY` và không set `OPENAI_BASE_URL` → `LLMClient.mock = True`.
- vLLM stub: `OPENAI_BASE_URL=http://localhost:8090/v1` + `OPENAI_API_KEY=stub-key`.
- Demo: `docs/DEMO_CHECKLIST.md` + `docs/RUNBOOK.md`.
