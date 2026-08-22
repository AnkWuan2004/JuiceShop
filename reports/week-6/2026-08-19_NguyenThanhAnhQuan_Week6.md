# Week 6 — Tích hợp, đánh giá và thuyết trình

**Project:** Sentinel · **Target:** OWASP Juice Shop v20.1.1, Docker Compose (Juice Shop + Kong **thật**, lần đầu chạy được trong môi trường làm việc này)

## Quá trình

Mục tiêu Tuần 6: hoàn thiện luồng đầu-cuối, đo lường, đánh giá và chuẩn bị trình bày kết quả.

1. **Docker Compose thật**: `docker compose up -d` dựng `sentinel-juice-shop` (:3000) và `sentinel-kong`
   (:8000/:8001), cả hai healthy. Chạy lại 3 bộ test Kong trên container thật (không còn cần gateway
   thay thế): `test_kong_iam.py` 7/7 PASS, `test_kong_rate_limit.py` (write 20/phút, #20-25 → 429),
   `test_kong_rate_limit_read.py` (read 60/phút, #60-65 → 429).
2. **Luồng đầu-cuối + metrics** (`scripts/e2e_report.py`, mới): chạy Security Analysis Agent → Exploit
   Agent đề xuất request → HITL → gửi qua Kong thật, ghi lại thời gian xử lý, số request qua gateway, số
   cảnh báo, số Approve/Reject, số lỗi LLM/app vào `data-lake/e2e_run_report.json`.
3. **Xác nhận khai thác sống**: request SQLi (`' OR '1'='1'`) qua Exploit Agent → Kong thật → Juice Shop
   thật trả về **200 với toàn bộ dữ liệu sản phẩm không lọc** — bằng chứng khai thác thật, không chỉ suy
   luận từ output scanner tĩnh.
4. **Eval Security Analysis Agent — 8 trường hợp** chọn độc lập từ 93 dòng quét thật, tự đánh giá severity
   trước khi đọc explanation của agent, rồi đối chiếu: 6/8 khớp, 2/8 lệch (1 đánh giá thấp — hardcoded
   JWT secret nên là High; 1 đánh giá cao — secret trong file fixture demo nên là Medium). Chi tiết +
   đề xuất cải tiến: `docs/notes/EVAL_SECURITY_AGENT.md`.
5. **Tài liệu bàn giao**: `docs/RESULTS_REPORT.md` (lỗ hổng phát hiện, đúng/sai, FP/FN, cải tiến),
   `docs/PRODUCT_BRIEF.md` (1 trang: vấn đề/người dùng/giá trị/phạm vi/hạn chế/hướng phát triển),
   `docs/DEMO_CHECKLIST.md` viết lại gọn theo đúng 7 bước "Bản trình diễn" của đề PDF (10-15 phút), sơ đồ
   kiến trúc (Mermaid) thêm vào `README.md`.

## Kết quả — đối chiếu tiêu chí PDF Tuần 6

| Tiêu chí hoàn thành | Trạng thái | Bằng chứng |
|---|---|---|
| Hệ thống chạy được bằng một quy trình rõ ràng | ✅ | `docker compose up -d` — 2 container healthy, xác nhận thật |
| Có ít nhất một luồng hoàn chỉnh từ kết quả quét đến báo cáo cuối | ✅ | `scripts/e2e_report.py` → `data-lake/e2e_run_report.json` |
| Không kiểm thử ngoài môi trường được cấp phép | ✅ | Guard `localhost`/`127.0.0.1` only trong `exploit_agent.py`/`kong_http_tool.py` |
| Có cơ chế phê duyệt cho request rủi ro | ✅ | HITL Approve/Reject, xác nhận qua Kong thật |
| Có kiểm thử cho Guardrails và che dữ liệu | ✅ | `tests/test_guardrails_week5.py` 23/23 PASS |
| Thành viên khác chạy lại demo dựa trên README | ✅ | `README.md` § Kiến trúc + `docs/DEMO_CHECKLIST.md` |

**Kết quả chạy thật (2026-08-19, Docker Compose thật):**

```
docker compose up -d                      → 2/2 container healthy
tests/test_kong_iam.py                    → 7/7 PASS (Kong thật)
tests/test_kong_rate_limit.py             → PASS (429 tại #20-25, write 20/phút)
tests/test_kong_rate_limit_read.py        → PASS (429 tại #60-65, read 60/phút)
tests/test_analysis_agent.py              → 13/13 PASS
tests/test_guardrails_week5.py            → 23/23 PASS
scripts/e2e_report.py                     → findings=74, requests=1, approve=1, reject=0, errors=0
Eval Security Analysis Agent (8 case)     → 6/8 khớp severity, 0 false positive/negative
```

**Verdict:** Tuần 6 theo PDF — **PASS**. Đây cũng là lần đầu toàn bộ Kong/Juice Shop chạy thật (Docker)
trong môi trường làm việc, đóng luôn giới hạn "không có Docker" từng ghi nhận ở các report Tuần 2/4/5.

**Giới hạn còn lại:** LLM vẫn chạy MOCK (chưa có API key thật) — ảnh hưởng chất lượng câu giải thích tự
nhiên, không ảnh hưởng độ chính xác grounding/severity đo ở trên (xem `docs/RESULTS_REPORT.md`).

## Dữ liệu thô / máy đọc

- `data-lake/e2e_run_report.json` — metrics luồng đầu-cuối.
- `data-lake/exploit_result.json` — bằng chứng SQLi khai thác sống qua Kong thật.
- `data-lake/eval_security_agent.json` — 8 case eval, đáp án tự chuẩn bị vs agent.
- `data-lake/analysis_report.jsonl` — 74 findings.
- Code mới: `scripts/e2e_report.py`.
