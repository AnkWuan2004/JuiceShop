# PRD — Project Sentinel

## Problem

Đội bảo mật nhỏ không đủ bandwidth pentest liên tục trên mọi release. SAST/DAST tạo nhiều finding nhưng thiếu ngữ cảnh ưu tiên và chứng minh khai thác an toàn trên staging.

## Solution

Project Sentinel = **DevSecOps baseline + AI-assisted pentest syndicate** chạy trên OWASP Juice Shop (Compose local):

1. CI Semgrep + ZAP → data-lake  
2. Kong IAM + MCP tools + A2A messaging  
3. Hybrid RAG + GraphRAG threat intel  
4. Multi-agent Recon → Fuzz → Exploit (HITL Slack/CLI)  
5. NeMo-style guardrails, PII redaction, eval pipeline  
6. Observability (LangSmith spans / Arize-local) + FinOps + vLLM OpenAI gateway  

## Users

- Intern / junior AppSec học thực chiến an toàn  
- Mentor đánh giá deliverable 12 tuần  

## Architecture (Compose)

```
Client/Agent → Kong:8000 (key-auth, ACL, rate-limit) → juice-shop:3000
MCP :8765 | Slack HITL :8787 | vLLM gateway :8090/v1
ZAP/debug có thể gọi thẳng :3000
RAG + agents = process Python trên host (MOCK LLM offline mặc định)
```

## Non-goals

- Không pentest hệ thống production/thật  
- Không bắt buộc GPU / model weights thật (vLLM = OpenAI-compatible gateway stub; có thể trỏ model thật sau)  
- Không thay thế pentest thủ công cấp độ advanced  
- Không bắt buộc Slack cloud / LangSmith cloud (local tương đương đủ lab)

## Risks

| Risk | Mitigation |
|---|---|
| Agent tấn công nhầm host | Hardcode localhost / Kong only |
| Prompt injection | NeMo-style Colang rails Tuần 7 |
| Chi phí API | MOCK mode + FinOps + monitor alerts |
| Juice Shop "đỏ" CI | fail_action false / \|\| true |

## Success metrics

- `docker compose up` chạy Juice Shop + Kong (+ optional vLLM profile)  
- Syndicate E2E với MOCK LLM + A2A + GraphRAG  
- Eval ≥ 70% detect trên 10 challenge ground truth (mock)  
- Tài liệu PRD + Business Case + Runbook + Demo checklist  
