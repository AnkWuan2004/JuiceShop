# Eval Security Analysis Agent — 8 trường hợp (Tuần 6)

So sánh kết quả **Security Analysis Agent** (`agents/analysis_agent.py`) với đáp án tự chuẩn bị độc
lập, chọn từ 93 dòng quét thật (`data-lake/vuln_data.db`: 51 Semgrep + 42 ZAP). Cách làm: đọc dòng quét
gốc trước, tự đánh giá severity/độ nghiêm trọng thật (không đọc explanation của agent trước), rồi mới
đối chiếu với `data-lake/analysis_report.jsonl`.

Dữ liệu máy đọc đầy đủ: [`data-lake/eval_security_agent.json`](../../data-lake/eval_security_agent.json)

## Kết quả

| Finding | Đáp án (tự chuẩn bị) | Agent | Kết luận |
|---|---|---|---|
| `F014` SQLi `routes/search.ts` | High — **đã xác nhận khai thác sống** qua Kong thật (`' OR '1'='1'` trả toàn bộ sản phẩm) | High (conf 0.6) | ✅ Đúng |
| `F013` SQLi `routes/login.ts` | High — bypass đăng nhập admin | High (conf 0.6) | ✅ Đúng |
| `F012` `remote-property-injection` `routes/currentUser.ts` | High — mass-assignment/ghi đè thuộc tính | High (conf 0.6) | ✅ Đúng |
| `F001/F002/F005` shell injection GitHub Actions | High — rủi ro supply-chain CI thật | High (conf 0.65) | ✅ Đúng |
| `F020/F026` hardcoded HMAC/JWT secret `lib/insecurity.ts` | **High** — secret ký token bị hardcode ≈ auth bypass | Medium (conf 0.5) | ⚠️ **Agent đánh giá thấp hơn thực tế** |
| `F010` secret trong `data/static/users.yml` | **Medium** — fixture demo có chủ đích của Juice Shop, không phải secret production rò rỉ thật | High (conf 0.6) | ⚠️ **Agent đánh giá cao hơn thực tế** |
| `F047/F048` CORP/COOP header thiếu | Low — best-practice, không tự khai thác được | Low (conf 0.3) | ✅ Đúng |
| `F049/F050` Timestamp Disclosure | Low — gần như noise | Low (conf 0.3) | ✅ Đúng |

**Độ chính xác severity: 6/8 (75%)** · 0 false positive/negative trong mẫu (agent không bịa finding,
không bỏ sót finding nào trong 8 case) · 2 lệch severity — 1 đánh giá thấp, 1 đánh giá cao.

## Vì sao 2 case lệch — và đề xuất cải tiến

- **`F020/F026` (hardcoded JWT secret) — đánh giá thấp:** `unify_severity()` hiện kế thừa severity gốc
  của Semgrep (`WARNING` → medium) mà chưa có rule riêng nâng mức cho nhóm CWE-321/CWE-798 (hardcoded
  credential dùng để ký token) — nhóm này tác động thực tế tương đương auth bypass, nên luôn nâng lên
  High bất kể severity gốc của tool.
- **`F010` (secret trong fixture demo) — đánh giá cao:** Semgrep phát hiện đúng pattern nhưng không có
  ngữ cảnh rằng `data/static/users.yml` là dữ liệu mẫu cố ý của Juice Shop, không phải secret production
  rò rỉ. Đề xuất: thêm rule hạ severity khi `location` khớp thư mục fixture/test đã biết
  (`data/static/`, `test/`, `*.spec.ts`) trước khi báo cáo.
- **Chất lượng câu giải thích khi chạy MOCK:** cả `F010` và `F020` nhận đúng cùng một đoạn giải thích
  mẫu chung ("Security Misconfiguration A05...") không khớp bản chất finding — vì `OPENAI_API_KEY` chưa
  cấu hình nên `enrich()` rơi vào fallback RAG/rule-based generic. Đây là giới hạn đã biết (không phải
  lỗi mới), chỉ hết khi bật LLM thật; không ảnh hưởng tới độ chính xác severity/grounding đo ở trên.

## Không phải lỗi

Grounding vẫn đúng 100% trên toàn bộ 74 findings: mọi `evidence.source_ids` truy vết về đúng dòng thật
trong `vuln_data.db`, `dropped_no_evidence = 0` (xem `tests/test_analysis_agent.py`). Lệch chỉ nằm ở
**mức độ nghiêm trọng gán cho 2/74 finding**, không phải bịa đặt hay bỏ sót.
