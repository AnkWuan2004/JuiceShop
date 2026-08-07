# Business Case — Project Sentinel

## Bối cảnh

Pentest thủ công 1 ứng dụng web vừa: thường 3–10 ngày người × chi phí consultant.
CI SAST/DAST rẻ hơn nhưng thiếu ưu tiên và proof-of-exploit.

## Đề xuất

Đầu tư **lab nội bộ** (Compose + agents) để:

- Giảm thời gian triage finding  
- Train junior trên Juice Shop an toàn  
- Prototype AI pentest có guardrail/HITL trước khi cân nhắc production  

## ROI đơn giản (minh họa)

| Hạng mục | Thủ công / quý | Sentinel lab / quý |
|---|---|---|
| Pentest 2 app | 10–20 ngày-người | 2–4 ngày-người review HITL + CI |
| Tooling | License scanner | Semgrep OSS + ZAP + OpenAI token |
| Token LLM (mock=0) | — | ~$5–30 nếu bật API thật cho demo |
| Rủi ro tấn công nhầm | Trung bình nếu không quy trình | Thấp (localhost-only + HITL) |

**Kết luận:** ROI chính là **tốc độ học + tái sử dụng pipeline**, không phải thay 100% pentester.
Với intern 6 tuần, giá trị = năng lực vận hành DevSecOps + AI an toàn — đo được bằng demo Compose và eval report.

## Go / No-go

- **Go** nếu mentor chấp nhận scope lab + mock LLM.  
- **No-go** nếu yêu cầu tấn công hệ thống thật hoặc SLA production — ngoài phạm vi.
