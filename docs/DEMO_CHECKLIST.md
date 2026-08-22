# Demo checklist — Project Sentinel (10-15 phút)

Theo đúng "Bản trình diễn" của đề PDF Tuần 6: chạy công cụ quét → Agent tạo báo cáo → Agent đề xuất
request kiểm tra → Approve/Reject → request qua API Gateway → Prompt Injection bị chặn → dữ liệu nhạy
cảm bị che. Không cần `OPENAI_API_KEY` (LLM chạy MOCK offline mặc định).

**Không có máy/Docker sẵn?** Bước 3-5 (Gateway đề xuất+HITL, Prompt Injection, che PII) đều có bản
live tương đương ngay trên demo Vercel, không cần cài gì: `/gateway` và `/guardrails` — xem
README § Live demo. Checklist dưới đây là bản đầy đủ chạy local với Kong container thật.

## 0. Chuẩn bị (trước buổi demo)

```bash
git clone <repo> && cd Project-Sentinel
pip install -r requirements.txt
docker compose up -d          # hoặc: docker-compose up -d (v1 binary)
docker compose ps             # sentinel-juice-shop :3000, sentinel-kong :8000/:8001
```

## 1. Quét bảo mật (SAST/DAST) → dữ liệu chuẩn hóa

Đã có sẵn kết quả quét CI thật trong `data-lake/vuln_data.db` (93 dòng: 51 Semgrep + 42 ZAP). Nói:
"CI GitHub Actions chạy Semgrep + ZAP mỗi push, `scripts/parse_results.py` chuẩn hóa về một định dạng
chung." (Không cần chạy lại CI trong buổi demo — chỉ cần chỉ vào `.github/workflows/security-scan.yml`.)

## 2. Security Analysis Agent tạo báo cáo

```bash
python agents/analysis_agent.py --md
```

→ `data-lake/analysis_report.jsonl` (+ `.md`): 74 finding, gộp trùng, phân loại severity, giải thích +
đề xuất fix, mọi finding có `evidence.source_ids` trỏ về dòng quét thật (không bịa).

## 3. Agent đề xuất request kiểm tra + Approve/Reject + qua Gateway

```bash
python agents/exploit_agent.py --yes           # nhánh Approve — request thật qua Kong
python agents/exploit_agent.py --reject-demo   # nhánh Reject — KHÔNG có request nào được gửi
```

Chỉ ra trên màn hình: khối `HITL APPROVAL` in rõ **Endpoint / Payload / Purpose** trước khi hỏi. Với
nhánh Approve: `data-lake/exploit_result.json` cho thấy request `GET /rest/products/search?q=' OR '1'='1'`
đi qua `http://localhost:8000` (Kong thật) và trả về **200 với dữ liệu không lọc** — SQLi xác nhận sống.
Với nhánh Reject: `status: "rejected_by_human"`, không có key `result` (không request nào được thực thi).

*Tương đương live trên Vercel:* `/gateway` → "Sinh đề xuất từ Exploit Agent" (gọi AI thật/mock đúng
theo `OPENAI_API_KEY`) → Approve/Reject — không có Kong thật phía sau nên không gửi network, nhưng
logic ACL/HITL là code thật.

## 4. Prompt Injection bị chặn

```bash
python agents/recon_agent.py                          # mặc định chạy cả 2 nhánh so sánh before/after
cat data-lake/injection_before.json    # không guardrail: model bị dụ (hijacked=true)
cat data-lake/injection_after.json     # có guardrail: bị chặn (blocked=true, hijacked=false)
```

Nguồn injection là file thật `juice-shop/ftp/sentinel_indirect_injection.txt` (Juice Shop tự serve).

*Tương đương live trên Vercel:* `/guardrails` → mục "Live: chống Prompt Injection" — dán/sửa nội
dung rồi bấm chạy `check_input()` thật ngay trên input đó.

## 5. Dữ liệu nhạy cảm bị che

```bash
python agents/pii_redaction.py --demo
```

→ in ra before/after: email/phone/SSN/token/API key/password đều bị thay bằng `[REDACTED_*]`.

*Tương đương live trên Vercel:* `/guardrails` → mục "Live: che dữ liệu nhạy cảm (PII)" — chạy
`redact()` thật trên input tự nhập.

## 6. Bộ test tổng hợp (bằng chứng Pass/Fail)

```bash
python tests/test_analysis_agent.py       # 13/13 — happy / empty / injection
python tests/test_guardrails_week5.py     # 23/23 — injection / sensitive-data / approval
python tests/test_kong_iam.py             # 7/7 — 401/403/2xx trên Kong thật
python tests/test_kong_rate_limit.py      # rate-limit write 20/phút
python tests/test_kong_rate_limit_read.py # rate-limit read 60/phút
```

## 7. Luồng đầu-cuối gộp 1 lệnh (metrics)

```bash
python scripts/e2e_report.py
```

In ra: thời gian xử lý, số request qua gateway, số cảnh báo, số lần Approve/Reject, lỗi LLM/app —
`data-lake/e2e_run_report.json`.

## Nói với người xem (30 giây)

1. CI Semgrep+ZAP → `vuln_data.db` → Security Analysis Agent gộp trùng, phân loại, giải thích + fix,
   evidence-based (không bịa).
2. Agent đề xuất request kiểm tra rủi ro → con người Approve/Reject, thấy rõ Endpoint/Payload/Mục đích.
3. Request chỉ đi qua Kong (allowlist, rate-limit) — 2 lỗi SQLi đã xác nhận khai thác sống trên Juice
   Shop thật.
4. Nội dung từ ứng dụng bị coi là không tin cậy (chặn prompt injection); dữ liệu nhạy cảm bị che trước
   khi vào LLM/log.
5. Toàn bộ có test tự động Pass/Fail, không phải chỉ chạy tay một lần.

## Dọn sau demo

```bash
docker compose down
```
