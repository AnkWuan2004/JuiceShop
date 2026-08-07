# Đối chiếu Tuần 1-3 với đề gốc PDF (VinUni × VinSOC — 6 tuần)

> Ghi chú quan trọng: đề gốc mentor cấp là lộ trình **6 tuần**, không phải 12 tuần như một số
> tài liệu nội bộ trong repo mô tả. Đề gốc **không yêu cầu** GraphRAG, Multi-Agent phức tạp,
> MCP/A2A hoàn chỉnh, vLLM/GPU tự triển khai, LLM-as-a-Judge phức tạp, hay khai thác lỗ hổng
> thực tế — các phần đó là **mở rộng tự làm thêm**, không tính vào yêu cầu bắt buộc. Đối chiếu
> dưới đây bám đúng nội dung "Công việc / Sản phẩm bàn giao / Tiêu chí hoàn thành" của PDF.

## Tuần 1 — Chuẩn bị môi trường + quét bảo mật cơ bản

| Tiêu chí PDF | Trạng thái | Bằng chứng |
|---|---|---|
| Chạy web app thử nghiệm bằng Docker | ✅ (cấu hình sẵn) | `docker-compose.yml` — chưa dựng lại trong phiên này vì máy làm việc **chưa có Docker** (không có quyền sudo tương tác) |
| Quy trình CI đơn giản | ✅ | `.github/workflows/security-scan.yml` — chạy Semgrep + ZAP thật trên GitHub Actions mỗi push/PR |
| Tích hợp SAST hoặc DAST (mã nguồn mở) | ✅ **đã chạy THẬT trong phiên này** | Semgrep thật: `semgrep scan --config=p/default` trên toàn bộ source Juice Shop pin v20.1.1 → **51 findings thật**, 307 rule, 996 file quét (`data-lake/reports/semgrep-report.json`) |
| Lưu kết quả quét dạng JSON | ✅ | `data-lake/reports/semgrep-report.json` (thật) + `data-lake/ci-artifacts/zap-scan-report/report_json.json` (thật, từ CI) |
| Xác định endpoint chính | ✅ | `docs/notes/ATTACK_SURFACE.md` |
| Tài liệu ngắn (kiến trúc/endpoint/lỗ hổng) | ✅ | `README.md` + `ATTACK_SURFACE.md` |

**Trước phiên này:** `vuln_data.db` được nạp từ `seed_sample_reports.py` — dữ liệu **tổng hợp giả lập**
(đường dẫn file thật trong repo, nhưng finding là dựng sẵn, script tự ghi rõ "Không cần chạy scan thật").
**Sau phiên này:** đã chạy Semgrep thật + dùng báo cáo ZAP thật từ CI, nạp lại DB — không còn dữ liệu giả lập.

## Tuần 2 — Chuẩn hóa kết quả quét + xây kho tri thức

| Tiêu chí PDF | Trạng thái | Bằng chứng |
|---|---|---|
| Chương trình đọc JSON scan → cấu trúc chung | ✅ | `scripts/parse_results.py` — đã verify chạy đúng trên **Semgrep JSON thật** vừa quét |
| Kho tri thức nhỏ (OWASP Top10 + tài liệu tool + 10-20 ví dụ lỗ hổng) | ✅ vượt yêu cầu | 20 tài liệu trong `rag/data/` (OWASP Top10, cheatsheet SQLi/XSS/Auth, CVE mẫu, ví dụ Juice Shop) |
| Tìm kiếm theo từ khóa/semantic trả kết quả liên quan | ✅ verify live | `rag/query.py::search` — test "SQL Injection" và "XSS" đều trả kết quả liên quan (BOW/TF-IDF) |

## Tuần 3 — Security Analysis Agent

| Tiêu chí PDF | Trạng thái | Bằng chứng |
|---|---|---|
| System Prompt lưu trong repo | ✅ | `agents/prompts/analysis_system_prompt.txt` |
| Kết nối data quét (T1) + kho tri thức (T2) | ✅ | `agents/analysis_agent.py::load_findings` (DB) + `rag_snippets()` (RAG) |
| Gộp cảnh báo trùng | ✅ | `group_findings()` — khóa gộp (severity, title chuẩn hóa, location) |
| Phân loại severity | ✅ | `unify_severity()` → high/medium/low |
| Giải thích ngôn ngữ đơn giản + đề xuất fix | ✅ | `enrich()` — LLM (real/mock) grounded trên RAG, có fallback rule-based nếu LLM lỗi |
| Output JSONL | ✅ | `data-lake/analysis_report.jsonl` |
| Không bịa endpoint/lỗ hổng ngoài data | ✅ verify | Post-check `source_ids` phải khớp DB thật — **0 finding bị drop** trên lần chạy data thật (93 rows → 74 findings) |
| Định dạng ổn định | ✅ | Schema cứng 8 field, sort theo severity |
| Xử lý input rỗng/không hợp lệ | ✅ verify | Test `empty` + `inject` PASS (xem dưới) |
| ≥3 tình huống test | ✅ vượt yêu cầu | `scripts/test_analysis_agent.py` — **13/13 PASS** (happy/empty/injection) |

### Kết quả chạy thật trong phiên này (data thật, không phải seed)
```
Rows quét thật: 93 (51 Semgrep thật + 42 ZAP-CI thật)
→ Gộp: 74 nhóm → 74 findings (high=15, medium=30, low=29)
→ dropped_no_evidence: 0
→ 13/13 test PASS
```
Ví dụ finding thật (không phải demo dựng sẵn): `yaml.github-actions.security.run-shell-injection`
tại `.github/workflows/update-challenges-*.yml`, `generic.secrets.security.detected-jwt-token` tại
`frontend/src/app/last-login-ip/`.

## Giới hạn còn tồn tại (báo trung thực cho mentor)

1. **LLM đang chạy ở chế độ MOCK**, chưa có API key OpenRouter/DeepSeek thật trong `.env`. Khi
   không có key, `explanation`/`remediation` dùng fallback rule-based + trích đoạn RAG (không phải
   văn bản do LLM sinh). Cơ chế tự động phát hiện real/mock hoạt động đúng (`meta.llm_mock`); chỉ
   cần dán key thật vào `.env` (local) hoặc Streamlit Cloud Secrets (deploy) là chuyển sang real
   ngay, không cần sửa code.
2. **Chưa dựng lại Juice Shop + Kong sống** trong phiên làm việc này vì máy chưa có Docker (không
   có quyền sudo tương tác qua công cụ). DAST dùng báo cáo ZAP **thật** đã có từ lần chạy CI gần
   nhất trên GitHub Actions, không phải chạy ZAP baseline mới ngay lúc này.
3. Việc gắn số tuần trong tài liệu nội bộ (README/TIEN_DO.md) lệch với số tuần thật của PDF (ví dụ
   nội dung Kong/IAM trong repo gắn nhãn "Tuần 2" nhưng đó là nội dung **Tuần 4** của đề gốc; nội
   dung Tuần 2 thật của đề — chuẩn hóa + kho tri thức — nằm trong phần code gắn nhãn "Tuần 3" của
   repo). Nội dung đã đủ, chỉ là nhãn tuần nội bộ không khớp số tuần PDF — nên nói rõ với mentor để
   tránh hiểu nhầm khi chấm.

## Việc cần làm để đạt 100% "chạy thật" (cần bạn thực hiện — ngoài khả năng của tool)

- Cài Docker (`sudo apt install -y docker.io`, cần chạy tay vì cần password tương tác) → `docker
  compose up -d` để Juice Shop/Kong sống, có thể chạy ZAP baseline mới nếu muốn.
- Dán OpenRouter API key thật vào `.env` (local) và vào Streamlit Cloud → Settings → Secrets (khi
  deploy) để Agent chạy LLM thật.
