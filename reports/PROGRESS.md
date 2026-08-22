# Tiến độ Project Sentinel

Cập nhật: 2026-08-19 (Tuần 6 — Tích hợp, đánh giá, thuyết trình — PASS, 6/6 tuần đề PDF hoàn thành)

## Kết luận ngắn

**Verified demo local + CI + PDF gap closures.** LLM mặc định **MOCK**. GraphRAG, MCP/A2A, NeMo-style Colang rails, Slack HITL local, LangSmith spans + Arize dashboard, vLLM gateway stub đã có. Traffic agent qua Kong `localhost:8000`.

**2026-08-19 — Tuần 5 "Guardrails, phê duyệt thủ công, che dữ liệu nhạy cảm": PASS.**
Chống prompt injection (`agents/guardrails.py`), phê duyệt thủ công hiển thị rõ Endpoint/Payload/Purpose
trước khi Approve/Reject (`agents/hitl_cli.py`, gate trong `agents/exploit_agent.py`), và che 6 loại dữ
liệu nhạy cảm — email/phone/SSN/token/API key/password — trước khi vào LLM hoặc ghi log
(`agents/pii_redaction.py`, wired vào `agents/kong_http_tool.py::append_log`). Test mới
`tests/test_guardrails_week5.py`: **23/23 PASS** (3 case injection + 3 case sensitive-data + 3 case
approval-required, vượt tối thiểu đề yêu cầu 2+2+2). Chi tiết:
[`reports/week-5/2026-08-19_NguyenThanhAnhQuan_Week5.md`](week-5/2026-08-19_NguyenThanhAnhQuan_Week5.md).

**2026-08-19 — Tuần 6 "Tích hợp, đánh giá và thuyết trình": PASS.** Docker Compose thật lần đầu chạy
được (Juice Shop + Kong container sống) — 3 test Kong (IAM, rate-limit write/read) verify lại trên Kong
thật, đều PASS. Luồng đầu-cuối + metrics mới `scripts/e2e_report.py`. SQL Injection xác nhận khai thác
sống qua gateway thật (`/rest/products/search`). Eval 8 case Security Analysis Agent (đáp án tự chuẩn
bị): 6/8 khớp severity, 2 gap có đề xuất cải tiến cụ thể. Tài liệu mới: `docs/RESULTS_REPORT.md`,
`docs/PRODUCT_BRIEF.md`, `docs/DEMO_CHECKLIST.md` (viết lại), sơ đồ kiến trúc trong `README.md`. Chi
tiết: [`reports/week-6/2026-08-19_NguyenThanhAnhQuan_Week6.md`](week-6/2026-08-19_NguyenThanhAnhQuan_Week6.md).

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

### Bảo vệ AI — Guardrails / HITL / che dữ liệu nhạy cảm (Tuần 5)
| Hạng mục | Trạng thái | Ghi chú |
|---|---|---|
| NeMo-style Colang rails | ✅ | `guardrails/config.yml` + `rails.co` |
| Injection before/after | ✅ | |
| HITL CLI + Slack local | ✅ | `scripts/slack_hitl_server.py` `:8787` |
| PII + GDPR note | ✅ | |

### LLMOps & bàn giao (Tuần 6)
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
